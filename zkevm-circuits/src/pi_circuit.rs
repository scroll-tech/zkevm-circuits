//! Public Input Circuit implementation

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
/// Defines PiTestCircuit
pub mod dev;
mod param;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod test;

use std::{cell::RefCell, collections::BTreeMap, iter, marker::PhantomData, str::FromStr};

use crate::{evm_circuit::util::constraint_builder::ConstrainBuilderCommon, table::KeccakTable};
use bus_mapping::circuit_input_builder::get_dummy_tx_hash;
use eth_types::{Address, Field, Hash, ToBigEndian, ToWord, Word, H256};
use ethers_core::utils::keccak256;
use halo2_proofs::plonk::{Assigned, Expression, Fixed, Instance};

use crate::{
    table::{BlockTable, LookupTable, TxTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
};
#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use crate::{
    evm_circuit::{util::constraint_builder::BaseConstraintBuilder, EvmCircuitExports},
    pi_circuit::param::{
        BASE_FEE_OFFSET, BLOCK_HEADER_BYTES_NUM, BLOCK_LEN, BLOCK_NUM_OFFSET, BYTE_POW_BASE,
        CHAIN_ID_OFFSET, GAS_LIMIT_OFFSET, KECCAK_DIGEST_SIZE, RPI_CELL_IDX,
        RPI_LENGTH_ACC_CELL_IDX, RPI_RLC_ACC_CELL_IDX, TIMESTAMP_OFFSET,
    },
    state_circuit::StateCircuitExports,
    tx_circuit::{CHAIN_ID_OFFSET as CHAIN_ID_OFFSET_IN_TX, TX_HASH_OFFSET, TX_LEN},
    witness::{self, Block, BlockContext, BlockContexts, Transaction},
};
use bus_mapping::util::read_env_var;
use gadgets::util::{and, not, select, Expr};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    pi_circuit::param::{COINBASE_OFFSET, DIFFICULTY_OFFSET, NUM_ALL_TXS_OFFSET},
    table::{
        BlockContextFieldTag,
        BlockContextFieldTag::{
            BaseFee, ChainId, Coinbase, CumNumTxs, Difficulty, GasLimit, NumAllTxs, NumTxs, Number,
            Timestamp,
        },
    },
    util::rlc_be_bytes,
};
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};
use itertools::Itertools;

fn get_coinbase_constant() -> Address {
    let default_coinbase = if cfg!(feature = "scroll") {
        Address::from_str("0x5300000000000000000000000000000000000005").unwrap()
    } else {
        Address::zero()
    };
    read_env_var("COINBASE", default_coinbase)
}

fn get_difficulty_constant() -> Word {
    read_env_var("DIFFICULTY", Word::zero())
}

/// PublicData contains all the values that the PiCircuit receives as input
#[derive(Debug, Clone)]
pub struct PublicData {
    /// chain id
    pub chain_id: u64,
    /// Start L1 QueueIndex
    pub start_l1_queue_index: u64,
    /// Block Transactions
    pub transactions: Vec<Transaction>,
    /// Block contexts
    pub block_ctxs: BlockContexts,
    /// Previous State Root
    pub prev_state_root: Hash,
    /// Next State Root
    pub next_state_root: Hash,
    /// Withdraw Trie Root
    pub withdraw_trie_root: Hash,
    /// Max number of supported transactions
    pub max_txs: usize,
    /// Max number of supported calldata bytes
    pub max_calldata: usize,
    /// Max number of supported inner blocks in a chunk
    pub max_inner_blocks: usize,
}

impl PublicData {
    // Return num of all txs in each block (taking skipped l1 msgs into account)
    fn get_num_all_txs(&self) -> BTreeMap<u64, u64> {
        let mut num_all_txs_in_blocks = BTreeMap::new();
        // short for total number of l1 msgs popped before
        let mut total_l1_popped = self.start_l1_queue_index;
        log::debug!("[public_data] start_l1_queue_index: {}", total_l1_popped);
        for &block_num in self.block_ctxs.ctxs.keys() {
            let num_l2_txs = self
                .transactions
                .iter()
                .filter(|tx| !tx.tx_type.is_l1_msg() && tx.block_number == block_num)
                .count() as u64;
            let num_l1_msgs = self
                .transactions
                .iter()
                .filter(|tx| tx.tx_type.is_l1_msg() && tx.block_number == block_num)
                // tx.nonce alias for queue_index for l1 msg tx
                .map(|tx| tx.nonce)
                .max()
                .map_or(0, |max_queue_index| max_queue_index - total_l1_popped + 1);

            let num_txs = num_l2_txs + num_l1_msgs;
            num_all_txs_in_blocks.insert(block_num, num_txs);

            log::debug!(
                "[public_data][block {}] total_l1_popped_before: {}, num_l1_msgs: {}, num_l2_txs: {}, num_txs: {}",
                block_num,
                total_l1_popped,
                num_l1_msgs,
                num_l2_txs,
                num_txs
            );
            total_l1_popped += num_l1_msgs;
        }

        num_all_txs_in_blocks
    }

    /// Compute the bytes for dataHash from the verifier's perspective.
    fn data_bytes(&self) -> Vec<u8> {
        log::debug!(
            "pi circuit data_bytes, inner block num {}",
            self.block_ctxs.ctxs.len()
        );
        let num_all_txs_in_blocks = self.get_num_all_txs();
        let result = iter::empty()
            .chain(self.block_ctxs.ctxs.iter().flat_map(|(block_num, block)| {
                // sanity check on coinbase & difficulty
                if !self.block_ctxs.relax_mode {
                    let coinbase = get_coinbase_constant();
                    assert_eq!(
                        coinbase, block.coinbase,
                        "[block {}] COINBASE const: {}, block.coinbase: {}",
                        block_num, coinbase, block.coinbase
                    );
                    let difficulty = get_difficulty_constant();
                    assert_eq!(
                        difficulty, block.difficulty,
                        "[block {}] DIFFICULTY const: {}, block.difficulty: {}",
                        block_num, difficulty, block.difficulty
                    );
                }

                let num_all_txs = num_all_txs_in_blocks
                    .get(block_num)
                    .cloned()
                    .unwrap_or_else(|| panic!("get num_all_txs in block {block_num}"))
                    as u16;
                iter::empty()
                    // Block Values
                    .chain(block.number.as_u64().to_be_bytes())
                    .chain(block.timestamp.as_u64().to_be_bytes())
                    .chain(block.base_fee.to_be_bytes())
                    .chain(block.gas_limit.to_be_bytes())
                    .chain(num_all_txs.to_be_bytes())
            }))
            // Tx Hashes
            .chain(
                self.transactions
                    .iter()
                    .flat_map(|tx| tx.hash.to_fixed_bytes()),
            )
            .collect::<Vec<u8>>();

        assert_eq!(
            result.len(),
            BLOCK_HEADER_BYTES_NUM * self.block_ctxs.ctxs.len()
                + KECCAK_DIGEST_SIZE * self.transactions.len()
        );
        result
    }

    fn get_data_hash(&self) -> H256 {
        H256(keccak256(self.data_bytes()))
    }

    fn pi_bytes(&self, data_hash: H256) -> Vec<u8> {
        iter::empty()
            .chain(self.chain_id.to_be_bytes())
            // state roots
            .chain(self.prev_state_root.to_fixed_bytes())
            .chain(self.next_state_root.to_fixed_bytes())
            .chain(self.withdraw_trie_root.to_fixed_bytes())
            // data hash
            .chain(data_hash.to_fixed_bytes())
            .collect::<Vec<u8>>()
    }

    fn get_pi(&self) -> H256 {
        let data_hash = H256(keccak256(self.data_bytes()));
        log::debug!(
            "[pi] chunk data hash: {}",
            hex::encode(data_hash.to_fixed_bytes())
        );

        let pi_bytes = self.pi_bytes(data_hash);
        let pi_hash = keccak256(pi_bytes);

        H256(pi_hash)
    }

    fn difficulty(&self) -> Word {
        self.block_ctxs
            .ctxs
            .first_key_value()
            .map(|(_, blk)| blk.difficulty)
            .unwrap_or_else(get_difficulty_constant)
    }

    fn coinbase(&self) -> Address {
        self.block_ctxs
            .ctxs
            .first_key_value()
            .map(|(_, blk)| blk.coinbase)
            .unwrap_or_else(get_coinbase_constant)
    }

    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn q_block_context_start_offset(&self) -> usize {
        // we start assigning block context values at offset == 1.
        1
    }

    fn q_block_context_end_offset(&self) -> usize {
        self.q_block_context_start_offset() + self.max_inner_blocks * BLOCK_HEADER_BYTES_NUM
    }

    fn q_tx_hashes_start_offset(&self) -> usize {
        self.q_block_context_end_offset()
    }

    fn q_tx_hashes_end_offset(&self) -> usize {
        self.q_tx_hashes_start_offset() + KECCAK_DIGEST_SIZE * self.max_txs
    }

    fn data_bytes_start_offset(&self) -> usize {
        // we start assigning data bytes at offset == 0.
        0
    }

    fn data_bytes_end_offset(&self) -> usize {
        self.data_bytes_start_offset()
            + self.max_inner_blocks * BLOCK_HEADER_BYTES_NUM
            + self.max_txs * KECCAK_DIGEST_SIZE
    }

    fn pi_bytes_start_offset(&self) -> usize {
        self.data_bytes_end_offset()
            + 1 // a row is reserved for the keccak256(rlc(data_bytes)) == data_hash lookup.
            + 1 // new row.
    }

    fn pi_bytes_end_offset(&self) -> usize {
        self.pi_bytes_start_offset() + N_BYTES_U64 + N_BYTES_WORD * 4
    }

    fn pi_hash_start_offset(&self) -> usize {
        self.pi_bytes_end_offset()
            + 1 // a row is reserved for the keccak256(rlc(pi_bytes)) == pi_hash lookup.
            + 1 // new row.
    }

    fn pi_hash_end_offset(&self) -> usize {
        self.pi_hash_start_offset() + KECCAK_DIGEST_SIZE
    }

    fn constants_start_offset(&self) -> usize {
        // there is no keccak lookup after the region where pi_hash is assigned. Hence we start
        // assigning constants (coinbase and difficulty) from where we ended the previous
        // assignment.
        self.pi_hash_end_offset() + 1 // new row.
    }

    fn constants_end_offset(&self) -> usize {
        self.constants_start_offset() + N_BYTES_ACCOUNT_ADDRESS + N_BYTES_WORD
    }
}

impl BlockContext {
    fn padding(chain_id: u64, difficulty: Word, coinbase: Address) -> Self {
        Self {
            chain_id,
            coinbase,
            difficulty,
            gas_limit: 0,
            number: Default::default(),
            timestamp: Default::default(),
            base_fee: Default::default(),
            history_hashes: vec![],
            eth_block: Default::default(),
        }
    }
}

impl Default for BlockContext {
    fn default() -> Self {
        Self::padding(0, get_difficulty_constant(), get_coinbase_constant())
    }
}

enum RpiFieldType {
    /// Default mode where no special behaviour is observed.
    DefaultType,
    /// Whether the assigned field represents a block context field.
    BlockCtx,
    /// Whether the assigned field represents the Keccak hi-lo decomposition.
    KeccakHiLo,
    /// Whether the assigned field represents the block's coinbase/difficulty constants.
    Constant,
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field> {
    /// dedicated column to store the difficulty, coinbase constants
    constant: Column<Fixed>,

    raw_public_inputs: Column<Advice>, // block, history_hashes, states, tx hashes
    rpi_field_bytes: Column<Advice>,   // rpi in bytes
    rpi_field_bytes_acc: Column<Advice>,
    rpi_rlc_acc: Column<Advice>, // RLC(rpi) as the input to Keccak table
    rpi_length_acc: Column<Advice>,

    // columns for padding in block context and tx hashes
    is_rpi_padding: Column<Advice>,
    real_rpi: Column<Advice>,
    q_tx_hashes: Column<Fixed>,
    q_block_context: Column<Fixed>,

    // columns for assertion about cum_num_txs in block table
    cum_num_txs: Column<Advice>,
    is_block_num_txs: Column<Fixed>,
    q_block_tag: Column<Fixed>,

    q_field_step: Selector,
    is_field_rlc: Column<Fixed>,

    q_not_end: Selector,
    // whether we should use keccak_input_rand to get RLC(bytes)
    is_rlc_keccak: Column<Fixed>,
    q_keccak: Selector,

    // 32 big-endian bytes of pi_hash
    pi: Column<Instance>,

    // External tables
    block_table: BlockTable,
    tx_table: TxTable,
    keccak_table: KeccakTable,

    _marker: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct PiCircuitConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// Keccak Table
    pub keccak_table: KeccakTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for PiCircuitConfig<F> {
    type ConfigArgs = PiCircuitConfigArgs<F>;

    /// Return a new PiCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            block_table,
            tx_table,
            keccak_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let constant = meta.fixed_column();

        // the layout of pi circuit on rpi
        // |        rpi         |  rpi_bytes_acc  | rpi_bytes |    rpi_rlc_acc   | rpi_length_acc |
        // |  block[0].number   |      b0         |    b0     |        b0        |       1        |
        // |  block[0].number   |    b0*256+b1    |    b1     |    b0*kec+b1     |       2        |
        // |       ...          |      ...        |   ...     |       ....       |      ...       |
        // |  block[0].number   | b0*256^7+..+b7  |    b7     |  b0*kec^7+..+b7  |       8        |
        // | block[0].gas_limit |      b8         |    b8     |  b0*kec^8+..+b8  |       9        |
        // |       ...          |      ...        |   ...     |      ....        |      ...       |
        // | block[0].gas_limit | b8*256^7+..+b15 |   b15     | b0*kec^15+..+b15 |      16        |
        // |       ...          |      ...        |   ...     |      ....        |      ...       |

        // hold the raw public input's value (e.g. gas_limit in block_context)
        let rpi = meta.advice_column_in(SecondPhase);
        // hold the raw public input's bytes
        let rpi_bytes = meta.advice_column();
        // hold the accumulated value of rpi_bytes (e.g. gas_limit in block_context)
        let rpi_bytes_acc = meta.advice_column_in(SecondPhase);
        // hold the accumulated value of rlc(rpi_bytes, keccak_input)
        let rpi_rlc_acc = meta.advice_column_in(SecondPhase);
        // hold the accumulated length of rpi_bytes for looking into keccak table
        let rpi_length_acc = meta.advice_column();

        // boolean column for indicating if the rpi_bytes is padding
        let is_rpi_padding = meta.advice_column();
        let real_rpi = meta.advice_column_in(SecondPhase);

        let pi = meta.instance_column();

        // Annotate table columns
        tx_table.annotate_columns(meta);
        block_table.annotate_columns(meta);

        let q_field_step = meta.complex_selector();
        let is_field_rlc = meta.fixed_column();

        let q_block_context = meta.fixed_column();
        let q_tx_hashes = meta.fixed_column();

        let q_not_end = meta.complex_selector();
        // We are accumulating bytes for three different purposes
        // 1. input_rlc for hashing data bytes using keccak_input_rand
        // 2. input_rlc for hashing pi bytes using keccak_input_rand
        // 3. get pi_hash using evm_word_rand
        let is_rlc_keccak = meta.fixed_column();
        let q_keccak = meta.complex_selector();

        let q_block_tag = meta.fixed_column();
        let cum_num_txs = meta.advice_column();
        let is_block_num_txs = meta.fixed_column();

        meta.enable_constant(constant);
        meta.enable_equality(rpi_bytes);
        meta.enable_equality(rpi_bytes_acc);
        meta.enable_equality(rpi);
        meta.enable_equality(rpi_length_acc);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(real_rpi);
        meta.enable_equality(block_table.value); // copy block to rpi
        meta.enable_equality(block_table.index);
        meta.enable_equality(tx_table.value); // copy tx hashes to rpi
        meta.enable_equality(cum_num_txs);
        meta.enable_equality(pi);

        // 1. constrain rpi_bytes, rpi_bytes_acc, and rpi for each field
        meta.create_gate(
            "rpi_bytes_acc[i+1] = rpi_bytes_acc[i] * t + rpi_bytes[i+1]",
            |meta| {
                let q_field_step = meta.query_selector(q_field_step);
                let bytes_acc_next = meta.query_advice(rpi_bytes_acc, Rotation::next());
                let bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
                let bytes_next = meta.query_advice(rpi_bytes, Rotation::next());
                let is_field_rlc = meta.query_fixed(is_field_rlc, Rotation::next());
                let evm_rand = challenges.evm_word();
                let t = select::expr(is_field_rlc, evm_rand, BYTE_POW_BASE.expr());

                vec![q_field_step * (bytes_acc_next - (bytes_acc * t + bytes_next))]
            },
        );

        // 2. constrain rpi_rlc and rpi_length_acc
        meta.create_gate(
            "rpi_rlc_acc[i+1] = keccak_rand * rpi_rlc_acc[i] + rpi_bytes[i+1]",
            |meta| {
                // if row_next.is_rpi_padding is not true, then
                //   q_not_end * (row_next.rpi_rlc_acc - row.rpi_rlc_acc * keccak_rand -
                // row_next.rpi_bytes) == 0 else,
                //   q_not_end * (row_next.rpi_rlc_acc - row.rpi_rlc_acc) == 0
                let mut cb = BaseConstraintBuilder::default();
                let is_rpi_padding = meta.query_advice(is_rpi_padding, Rotation::next());
                let rpi_rlc_acc_cur = meta.query_advice(rpi_rlc_acc, Rotation::cur());
                let rpi_bytes_next = meta.query_advice(rpi_bytes, Rotation::next());
                let keccak_rand = challenges.keccak_input();
                let evm_rand = challenges.evm_word();
                let is_rlc_keccak = meta.query_fixed(is_rlc_keccak, Rotation::next());
                let r = select::expr(is_rlc_keccak, keccak_rand, evm_rand);

                cb.require_equal(
                    "rpi_rlc_acc' = is_rpi_padding ? rpi_rlc_acc : rpi_rlc_acc * r + rpi_bytes'",
                    meta.query_advice(rpi_rlc_acc, Rotation::next()),
                    select::expr(
                        is_rpi_padding.expr(),
                        rpi_rlc_acc_cur.expr(),
                        rpi_rlc_acc_cur * r + rpi_bytes_next,
                    ),
                );

                cb.require_equal(
                    "rpi_length_acc' = rpi_length_acc + (is_rpi_padding ? 0 : 1)",
                    meta.query_advice(rpi_length_acc, Rotation::next()),
                    meta.query_advice(rpi_length_acc, Rotation::cur())
                        + select::expr(is_rpi_padding, 0.expr(), 1.expr()),
                );

                cb.gate(meta.query_selector(q_not_end))
            },
        );

        meta.create_gate("padding block context", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_rpi_padding is boolean",
                meta.query_advice(is_rpi_padding, Rotation::cur()),
            );

            // if is_rpi_padding == true, then is_rpi_padding' is true too.
            cb.condition(
                and::expr([
                    meta.query_fixed(q_block_context, Rotation::next()),
                    meta.query_advice(is_rpi_padding, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_equal(
                        "is_rpi_padding' == true if is_rpi_padding is true",
                        meta.query_advice(is_rpi_padding, Rotation::next()),
                        true.expr(),
                    )
                },
            );

            // real_rpi = not(is_rpi_padding) * rpi
            // real_rpi is the column which has valid block context fields that copied to block
            // table
            cb.require_equal(
                "real_rpi == not(is_rpi_padding) * rpi",
                meta.query_advice(real_rpi, Rotation::cur()),
                not::expr(meta.query_advice(is_rpi_padding, Rotation::cur()))
                    * meta.query_advice(rpi, Rotation::cur()),
            );

            // is_rpi_padding cannot go from
            cb.gate(meta.query_fixed(q_block_context, Rotation::cur()))
        });

        meta.create_gate("padding tx hashes", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_rpi_padding is boolean",
                meta.query_advice(is_rpi_padding, Rotation::cur()),
            );

            // if is_rpi_padding == true, then is_rpi_padding' is true too.
            cb.condition(
                and::expr([
                    meta.query_fixed(q_tx_hashes, Rotation::next()),
                    meta.query_advice(is_rpi_padding, Rotation::cur()),
                ]),
                |cb| {
                    cb.require_equal(
                        "is_rpi_padding' == true if is_rpi_padding is true",
                        meta.query_advice(is_rpi_padding, Rotation::next()),
                        true.expr(),
                    )
                },
            );

            // if_rpi_padding == true, then rpi == dummy_tx_hash
            cb.condition(meta.query_advice(is_rpi_padding, Rotation::cur()), |cb| {
                cb.require_equal(
                    "rpi == dummy_tx_hash",
                    meta.query_advice(rpi, Rotation::cur()),
                    iter::once(1.expr())
                        .chain(challenges.evm_word_powers_of_randomness::<31>())
                        .rev()
                        .zip(
                            get_dummy_tx_hash()
                                .to_fixed_bytes()
                                .into_iter()
                                .map(|byte| byte.expr()),
                        )
                        .fold(0.expr(), |acc, (rand_pow, byte)| acc + rand_pow * byte),
                );
            });

            cb.gate(meta.query_fixed(q_tx_hashes, Rotation::cur()))
        });

        // We reuse the layout for rpi to compute the keccak output.
        // The 32 bytes of keccak output are combined into (hi, lo)
        //  where r = challenges.evm_word().
        // And the layout will be like this.
        // | rpi | rpi_bytes | rpi_bytes_acc | rpi_rlc_acc |
        // | hi  |    b31    |      b31      |     b31     |
        // | hi  |    b30    | b31*2^8 + b30 | b31*r + b30 |
        // | hi  |    ...    |      ...      |     ...     |
        // | hi  |    b16    | b31*2^120+... | b31*r^15+...|
        // | lo  |    b15    |      b15      | b31*r^16+...|
        // | lo  |    b14    | b15*2^8 + b14 | b31*r^17+...|
        // | lo  |    ...    |      ...      |     ...     |
        // | lo  |     b0    | b15*2^120+... | b31*r^31+...|

        // We use copy constraints to
        // 1. copy the RLC(data_bytes, keccak_rand) in the `rpi_rlc_acc` column to the `rpi` column
        //    on the row that q_keccak = 1 for data bytes.
        // 2. copy the len(data_bytes) in the `rpi_length_acc` column to the `rpi_length_acc` column
        //    on the row that q_keccak = 1 for data bytes.
        // 3. copy the RLC(data_hash_bytes, word_rand) in the `rpi_rlc_acc` column to the
        //    `rpi_rlc_acc` column on the row that q_keccak = 1 for data hash.

        // The layout for entire pi circuit looks like
        // data bytes:      |   rpi   | rpi_bytes | rpi_bytes_acc | rpi_rlc_acc | rpi_length_acc |
        //                  |   ..    |     ..    |      ...      |   dbs_rlc   |    input_len   |
        // q_keccak = 1     | dbs_rlc |     ..    |      ...      |   dh_rlc    |    input_len   |
        //  chain_id        | chain_id|     ..    |      ...      |     ...     |      ...       |
        // prev_state_root  |   ..    |     ..    |      ...      |     ...     |      ...       |
        // after_state_root |   ..    |     ..    |      ...      |     ...     |      ...       |
        // withdraw_root    |   ..    |     ..    |      ...      |     ...     |      ...       |
        // data hash        |  dh_rlc |     ..    |      ...      |  pi_bs_rlc  |      136       |
        // q_keccak = 1     |pi_bs_rlc|     ..    |      ...      | pi_hash_rlc |      136       |
        //   pi hash        |   hi    |     ..    |      ...      |     ...     |       16       |
        //                  |   lo    |     ..    |      ...      | pi_hash_rlc |       32       |
        meta.lookup_any("keccak(rpi)", |meta| {
            let q_keccak = meta.query_selector(q_keccak);

            let rpi_rlc = meta.query_advice(rpi, Rotation::cur());
            let rpi_length = meta.query_advice(rpi_length_acc, Rotation::cur());
            let output = meta.query_advice(rpi_rlc_acc, Rotation::cur());

            let input_exprs = vec![
                1.expr(), // q_enable = true
                1.expr(), // is_final = true
                rpi_rlc,
                rpi_length,
                output,
            ];
            let keccak_table_exprs = keccak_table.table_exprs(meta);
            assert_eq!(input_exprs.len(), keccak_table_exprs.len());

            input_exprs
                .into_iter()
                .zip(keccak_table_exprs)
                .map(|(input, table)| (q_keccak.expr() * input, table))
                .collect()
        });

        // 3. constrain block_table
        meta.create_gate(
            "cum_num_txs::next == cum_num_txs::cur + (block_table.tag == NumTxs) ? block_table.value : 0",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();
                let num_txs = meta.query_advice(block_table.value, Rotation::cur());

                let num_txs = select::expr(
                    meta.query_fixed(is_block_num_txs, Rotation::cur()),
                    num_txs,
                    0.expr(),
                );
                cb.require_equal(
                    "cum_num_txs",
                    meta.query_advice(cum_num_txs, Rotation::next()),
                    meta.query_advice(cum_num_txs, Rotation::cur()) + num_txs,
                );

                cb.condition(meta.query_fixed(is_block_num_txs, Rotation::cur()), |cb| {
                    cb.require_equal(
                        "block_table.value' == cum_num_txs' if block_table.tag == Nums",
                        meta.query_advice(block_table.value, Rotation::next()),
                        meta.query_advice(cum_num_txs, Rotation::next()),
                    );
                });

                // NOTE: cum_num_txs is already enforced to start with 0 using copy constraint.

                cb.gate(meta.query_fixed(q_block_tag, Rotation::cur()))
            }
        );

        Self {
            block_table,
            tx_table,
            keccak_table,
            constant,
            raw_public_inputs: rpi,
            rpi_field_bytes: rpi_bytes,
            rpi_field_bytes_acc: rpi_bytes_acc,
            rpi_rlc_acc,
            rpi_length_acc,
            is_rpi_padding,
            real_rpi,
            q_tx_hashes,
            q_field_step,
            is_field_rlc,
            q_not_end,
            is_rlc_keccak,
            q_keccak,
            cum_num_txs,
            q_block_tag,
            is_block_num_txs,
            pi,
            _marker: PhantomData,
            q_block_context,
        }
    }
}

// (hi cell, lo cell)
type PiHashExport<F> = Vec<AssignedCell<F, F>>;

#[derive(Debug, Clone)]
struct Connections<F: Field> {
    start_state_root: AssignedCell<F, F>,
    end_state_root: AssignedCell<F, F>,
    withdraw_root: AssignedCell<F, F>,
}

impl<F: Field> PiCircuitConfig<F> {
    /// Assign witness data to the PI circuit's layout.
    ///
    /// The layout of the PI circuit is as follows:
    ///
    /// |----------|------------------------|--------------------------|
    /// |          | rpi initialise         |                          |
    /// |          | block\[0\].number      |                          |
    /// |          | block\[0\].timestamp   |                          |
    /// |          | block\[0\].base_fee    |                          |
    /// |          | block\[0\].gas_limit   |                          |
    /// |          | block\[0\].num_all_txs |                          |
    /// |          | block\[1\].number      | <- q_block_context == 1  |
    /// | *PART 1* | ...                    |                          |
    /// |          | block\[n\].num_all_txs |                          |
    /// | ASSIGN   | PADDING                |                          |
    /// | DATA     | ...                    |                          |
    /// | BYTES    | PADDING                |                          |
    /// |          |------------------------|--------------------------|
    /// |          | tx_hash\[0\]           |                          |
    /// |          | tx_hash\[1\]           |                          |
    /// |          | ...                    |                          |
    /// |          | tx_hash\[n\]           | <- q_tx_hashes == 1      |
    /// |          | DUMMY_TX_HASH          |                          |
    /// |          | ...                    |                          |
    /// |          | DUMMY_TX_HASH          |                          |
    /// |          |------------------------|--------------------------|
    /// |          | rlc(data_bytes)        | <- q_keccak == 1         |
    /// |----------|------------------------|--------------------------|
    /// |          | rpi initialise         |                          |
    /// |          | chain_id               |                          |
    /// | *PART 2* | prev_state_root        |                          |
    /// |          | next_state_root        |                          |
    /// | ASSIGN   | withdraw_trie_root     |                          |
    /// | PI       | data_hash              |                          |
    /// | BYTES    |------------------------|--------------------------|
    /// |          | rlc(pi_bytes)          | <- q_keccak == 1         |
    /// |----------|------------------------|--------------------------|
    /// | *PART 3* | rpi initialise         |                          |
    /// | ASSIGN   | pi_hash_hi             |                          |
    /// | PI HASH  | pi_hash_lo             |                          |
    /// |----------|------------------------|--------------------------|
    /// | *PART 4* | rpi initialise         |                          |
    /// | ASSIGN   | coinbase               |                          |
    /// | CONSTS   | difficulty             |                          |
    /// |----------|------------------------|--------------------------|
    ///
    /// Where each one of the rows above, i.e. block\[0\].number, block\[0\].timestamp, ...,
    /// pi_hash_lo, coinbase, difficulty are assigned using the assign_field method.
    ///
    /// Each `field` takes multiple rows in the actual circuit layout depending on how many bytes
    /// it takes to represent the said field. For instance, pi_hash_lo represent the lower 16 bytes
    /// of the public input hash, hence we need 16 rows to assign the pi_hash_lo field. In
    /// addition, for those rows represent the field, the `q_field_step` fixed column is enabled.
    ///
    /// Since we already know the maximum number of blocks and txs that we will assign in this
    /// layout, all the `q_*` columns are fixed. For blocks and txs, we pad the remaining layout
    /// with a padded field and mark it by the `is_rpi_padding` identifier.
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData,
        block_value_cells: &[AssignedCell<F, F>],
        tx_value_cells: &[AssignedCell<F, F>],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(PiHashExport<F>, Connections<F>), Error> {
        // 1. Assign data bytes.
        let (offset, data_hash_rlc_cell) = self.assign_data_bytes(
            region,
            0, /* offset == 0 */
            public_data,
            block_value_cells,
            tx_value_cells,
            challenges,
        )?;
        debug_assert_eq!(offset, public_data.pi_bytes_start_offset());

        // 2. Assign public input bytes.
        let (offset, pi_hash_rlc_cell, connections) = self.assign_pi_bytes(
            region,
            offset,
            public_data,
            block_value_cells,
            tx_value_cells,
            &data_hash_rlc_cell,
            challenges,
        )?;
        debug_assert_eq!(offset, public_data.pi_hash_start_offset());

        // 3. Assign public input hash (hi, lo) decomposition.
        let (offset, pi_hash_cells) =
            self.assign_pi_hash(region, offset, public_data, &pi_hash_rlc_cell, challenges)?;
        debug_assert_eq!(offset, public_data.constants_start_offset());

        // 4. Assign block coinbase and difficulty.
        let offset =
            self.assign_constants(region, offset, public_data, block_value_cells, challenges)?;
        debug_assert_eq!(offset, public_data.constants_end_offset() + 1);

        Ok((pi_hash_cells, connections))
    }

    /// Assign data bytes, that represent the pre-image to data_hash.
    /// i.e. keccak256(rlc(data_bytes)) == data_hash.
    fn assign_data_bytes(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        public_data: &PublicData,
        block_value_cells: &[AssignedCell<F, F>],
        tx_value_cells: &[AssignedCell<F, F>],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(usize, AssignedCell<F, F>), Error> {
        // Initialise the RLC accumulator and length values.
        let (mut offset, mut rpi_rlc_acc, mut rpi_length) = self.assign_rlc_init(region, offset)?;

        // Enable fixed columns for block context.
        for q_offset in
            public_data.q_block_context_start_offset()..public_data.q_block_context_end_offset()
        {
            region.assign_fixed(
                || "q_block_context",
                self.q_block_context,
                q_offset,
                || Value::known(F::one()),
            )?;
        }
        // Enable fixed columns for tx hashes.
        for q_offset in public_data.q_tx_hashes_start_offset()..public_data.q_tx_hashes_end_offset()
        {
            region.assign_fixed(
                || "q_tx_hashes",
                self.q_tx_hashes,
                q_offset,
                || Value::known(F::one()),
            )?;
        }
        // Enable RLC accumulator consistency check throughout the above rows.
        for q_offset in public_data.data_bytes_start_offset()..public_data.data_bytes_end_offset() {
            self.q_not_end.enable(region, q_offset)?;
        }

        // Assign block context values.
        let n_block_ctxs = public_data.block_ctxs.ctxs.len();
        let num_txs_by_block = public_data.get_num_all_txs();
        let mut block_table_offset = 1;
        let mut block_copy_cells = vec![];
        for (i, block) in public_data
            .block_ctxs
            .ctxs
            .values()
            .cloned()
            .chain(std::iter::repeat(BlockContext::padding(
                public_data.chain_id(),
                public_data.difficulty(),
                public_data.coinbase(),
            )))
            .take(public_data.max_inner_blocks)
            .enumerate()
        {
            let is_rpi_padding = i >= n_block_ctxs;
            let num_all_txs = num_txs_by_block
                .get(&block.number.as_u64())
                .cloned()
                .unwrap_or(0) as u16;

            // Assign fields in pi columns and connect them to block table
            for (field_value_be_bytes, field_offset) in [
                // block number
                (
                    block.number.as_u64().to_be_bytes().to_vec(),
                    BLOCK_NUM_OFFSET,
                ),
                // block timestamp
                (
                    block.timestamp.as_u64().to_be_bytes().to_vec(),
                    TIMESTAMP_OFFSET,
                ),
                // base fee
                (block.base_fee.to_be_bytes().to_vec(), BASE_FEE_OFFSET),
                // gas limit
                (block.gas_limit.to_be_bytes().to_vec(), GAS_LIMIT_OFFSET),
                // num txs in block
                (num_all_txs.to_be_bytes().to_vec(), NUM_ALL_TXS_OFFSET),
            ] {
                let (tmp_offset, tmp_rpi_rlc_acc, tmp_rpi_length, cells) = self.assign_field(
                    region,
                    offset,
                    field_value_be_bytes.as_slice(),
                    RpiFieldType::BlockCtx,
                    is_rpi_padding,
                    rpi_rlc_acc,
                    rpi_length,
                    challenges,
                )?;
                offset = tmp_offset;
                rpi_rlc_acc = tmp_rpi_rlc_acc;
                rpi_length = tmp_rpi_length;
                block_copy_cells.push((
                    cells[RPI_CELL_IDX].clone(),
                    block_table_offset + field_offset,
                ));
            }

            block_table_offset += BLOCK_LEN;
        }
        // Copy block context fields to block table
        for (block_cell, row_offset) in block_copy_cells.into_iter() {
            region.constrain_equal(
                block_cell.cell(),
                block_value_cells[row_offset - 1].cell(), /* -1 for block table's first row of
                                                           * all-zeros */
            )?;
        }

        // Assign tx hash values.
        let n_txs = public_data.transactions.len();
        let mut tx_copy_cells = vec![];
        let mut data_bytes_rlc = None;
        let mut data_bytes_length = None;
        for (i, tx_hash) in public_data
            .transactions
            .iter()
            .map(|tx| tx.hash)
            .chain(std::iter::repeat(get_dummy_tx_hash()))
            .take(public_data.max_txs)
            .enumerate()
        {
            let is_rpi_padding = i >= n_txs;

            let (tmp_offset, tmp_rpi_rlc_acc, tmp_rpi_length, cells) = self.assign_field(
                region,
                offset,
                &tx_hash.to_fixed_bytes(),
                RpiFieldType::DefaultType,
                is_rpi_padding,
                rpi_rlc_acc,
                rpi_length,
                challenges,
            )?;
            offset = tmp_offset;
            rpi_rlc_acc = tmp_rpi_rlc_acc;
            rpi_length = tmp_rpi_length;
            tx_copy_cells.push(cells[RPI_CELL_IDX].clone());
            if i == public_data.max_txs - 1 {
                data_bytes_rlc = Some(cells[RPI_RLC_ACC_CELL_IDX].clone());
                data_bytes_length = Some(cells[RPI_LENGTH_ACC_CELL_IDX].clone());
            }
        }
        // Copy tx_hashes to tx table
        for (i, tx_hash_cell) in tx_copy_cells.into_iter().enumerate() {
            region.constrain_equal(
                tx_hash_cell.cell(),
                tx_value_cells[i * TX_LEN + TX_HASH_OFFSET - 1].cell(),
            )?;
        }

        // Assign row for validating lookup to check:
        // data_hash == keccak256(rlc(data_bytes))
        data_bytes_rlc.unwrap().copy_advice(
            || "data_bytes_rlc in the rpi col",
            region,
            self.raw_public_inputs,
            offset,
        )?;
        data_bytes_length.unwrap().copy_advice(
            || "data_bytes_length in the rpi_length_acc col",
            region,
            self.rpi_length_acc,
            offset,
        )?;
        let data_hash_rlc_cell = {
            let data_hash_rlc = rlc_be_bytes(
                &public_data.get_data_hash().to_fixed_bytes(),
                challenges.evm_word(),
            );
            region.assign_advice(
                || "data_hash_rlc",
                self.rpi_rlc_acc,
                offset,
                || data_hash_rlc,
            )?
        };
        self.q_keccak.enable(region, offset)?;

        Ok((offset + 1, data_hash_rlc_cell))
    }

    /// Assign public input bytes, that represent the pre-image to pi_hash.
    /// i.e. keccak256(rlc(pi_bytes)) == pi_hash.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn assign_pi_bytes(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        public_data: &PublicData,
        block_value_cells: &[AssignedCell<F, F>],
        tx_value_cells: &[AssignedCell<F, F>],
        data_hash_rlc_cell: &AssignedCell<F, F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(usize, AssignedCell<F, F>, Connections<F>), Error> {
        let (mut offset, mut rpi_rlc_acc, mut rpi_length) = self.assign_rlc_init(region, offset)?;

        // Enable RLC accumulator consistency check throughout the above rows.
        for q_offset in public_data.pi_bytes_start_offset()..public_data.pi_bytes_end_offset() {
            self.q_not_end.enable(region, q_offset)?;
        }

        // Assign [chain_id, prev_state_root, state_root, withdraw_trie_root].
        let mut cells = vec![];
        let rpi_cells = [
            public_data.chain_id.to_be_bytes().to_vec(),
            public_data.prev_state_root.to_fixed_bytes().to_vec(),
            public_data.next_state_root.to_fixed_bytes().to_vec(),
            public_data.withdraw_trie_root.to_fixed_bytes().to_vec(),
        ]
        .iter()
        .map(|value_be_bytes| {
            (offset, rpi_rlc_acc, rpi_length, cells) = self.assign_field(
                region,
                offset,
                value_be_bytes,
                RpiFieldType::DefaultType,
                false, // no padding in this case.
                rpi_rlc_acc,
                rpi_length,
                challenges,
            )?;
            Ok(cells[RPI_CELL_IDX].clone())
        })
        .collect::<Result<Vec<_>, Error>>()?;

        // copy chain_id to block table
        for block_idx in 0..public_data.max_inner_blocks {
            region.constrain_equal(
                rpi_cells[0].cell(),
                block_value_cells[block_idx * BLOCK_LEN + CHAIN_ID_OFFSET].cell(),
            )?;
        }
        // copy chain_id to tx table
        for tx_id in 0..public_data.max_txs {
            region.constrain_equal(
                rpi_cells[0].cell(),
                tx_value_cells[tx_id * TX_LEN + CHAIN_ID_OFFSET_IN_TX - 1].cell(),
            )?;
        }
        // connections to be done with other sub-circuits.
        let connections = Connections {
            start_state_root: rpi_cells[1].clone(),
            end_state_root: rpi_cells[2].clone(),
            withdraw_root: rpi_cells[3].clone(),
        };

        // Assign data_hash
        (offset, _, _, cells) = self.assign_field(
            region,
            offset,
            &public_data.get_data_hash().to_fixed_bytes(),
            RpiFieldType::DefaultType,
            false, // no padding in this case
            rpi_rlc_acc,
            rpi_length,
            challenges,
        )?;
        let data_hash_cell = cells[RPI_CELL_IDX].clone();
        let pi_bytes_rlc = cells[RPI_RLC_ACC_CELL_IDX].clone();
        let pi_bytes_length = cells[RPI_LENGTH_ACC_CELL_IDX].clone();

        // Copy data_hash value we collected from assigning data bytes.
        region.constrain_equal(data_hash_rlc_cell.cell(), data_hash_cell.cell())?;

        // Assign row for validating lookup to check:
        // pi_hash == keccak256(rlc(pi_bytes))
        pi_bytes_rlc.copy_advice(
            || "pi_bytes_rlc in the rpi col",
            region,
            self.raw_public_inputs,
            offset,
        )?;
        pi_bytes_length.copy_advice(
            || "pi_bytes_length in the rpi_length_acc col",
            region,
            self.rpi_length_acc,
            offset,
        )?;
        let pi_hash_rlc_cell = {
            let pi_hash_rlc = rlc_be_bytes(
                &public_data.get_pi().to_fixed_bytes(),
                challenges.evm_word(),
            );
            region.assign_advice(|| "pi_hash_rlc", self.rpi_rlc_acc, offset, || pi_hash_rlc)?
        };
        self.q_keccak.enable(region, offset)?;

        Ok((offset + 1, pi_hash_rlc_cell, connections))
    }

    /// Assign the (hi, lo) decomposition of pi_hash.
    fn assign_pi_hash(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        public_data: &PublicData,
        pi_hash_rlc_cell: &AssignedCell<F, F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(usize, PiHashExport<F>), Error> {
        let (mut offset, mut rpi_rlc_acc, mut rpi_length) = self.assign_rlc_init(region, offset)?;

        // Enable RLC accumulator consistency check throughout the above rows.
        for q_offset in public_data.pi_hash_start_offset()..public_data.pi_hash_end_offset() {
            self.q_not_end.enable(region, q_offset)?;
        }

        // the high 16 bytes of keccak output
        let (tmp_offset, tmp_rpi_rlc_acc, tmp_rpi_length, cells) = self.assign_field(
            region,
            offset,
            &public_data.get_pi().to_fixed_bytes()[..16],
            RpiFieldType::KeccakHiLo,
            false, // no padding in this case
            rpi_rlc_acc,
            rpi_length,
            challenges,
        )?;
        (offset, rpi_rlc_acc, rpi_length) = (tmp_offset, tmp_rpi_rlc_acc, tmp_rpi_length);
        let pi_hash_hi_cells = cells[3..].to_vec();

        // the low 16 bytes of keccak output
        let (tmp_offset, _, _, cells) = self.assign_field(
            region,
            offset,
            &public_data.get_pi().to_fixed_bytes()[16..],
            RpiFieldType::KeccakHiLo,
            false, // no padding in this case
            rpi_rlc_acc,
            rpi_length,
            challenges,
        )?;
        offset = tmp_offset;
        let pi_hash_lo_cells = cells[3..].to_vec();

        // Copy pi_hash value we collected from assigning pi bytes.
        region.constrain_equal(pi_hash_rlc_cell.cell(), cells[RPI_RLC_ACC_CELL_IDX].cell())?;

        Ok((offset, [pi_hash_hi_cells, pi_hash_lo_cells].concat()))
    }

    /// Assign constants such as the block's coinbase and difficulty.
    fn assign_constants(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        public_data: &PublicData,
        block_value_cells: &[AssignedCell<F, F>],
        challenges: &Challenges<Value<F>>,
    ) -> Result<usize, Error> {
        let (mut offset, mut rpi_rlc_acc, mut rpi_length) = self.assign_rlc_init(region, offset)?;

        // Enable RLC accumulator consistency check throughout the above rows.
        for q_offset in public_data.constants_start_offset()..public_data.constants_end_offset() {
            self.q_not_end.enable(region, q_offset)?;
        }

        // Assign [coinbase, difficulty] as constants.
        let mut cells = vec![];
        let rpi_cells = [
            public_data.coinbase().to_fixed_bytes().to_vec(),
            public_data.difficulty().to_be_bytes().to_vec(),
        ]
        .iter()
        .map(|value_be_bytes| {
            (offset, rpi_rlc_acc, rpi_length, cells) = self.assign_field(
                region,
                offset,
                value_be_bytes,
                RpiFieldType::Constant,
                false, // no padding in this case
                rpi_rlc_acc,
                rpi_length,
                challenges,
            )?;
            Ok(cells[RPI_CELL_IDX].clone())
        })
        .collect::<Result<Vec<AssignedCell<F, F>>, Error>>()?;

        // Copy coinbase and difficulty cells to block table
        for block_idx in 0..public_data.max_inner_blocks {
            region.constrain_equal(
                rpi_cells[0].cell(),
                block_value_cells[BLOCK_LEN * block_idx + COINBASE_OFFSET].cell(),
            )?;
            region.constrain_equal(
                rpi_cells[1].cell(),
                block_value_cells[BLOCK_LEN * block_idx + DIFFICULTY_OFFSET].cell(),
            )?;
        }

        Ok(offset)
    }

    /// Initialise the RLC computation at the row with the given offset. Returns the offset at the
    /// next row.
    fn assign_rlc_init(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
    ) -> Result<(usize, Value<F>, Value<F>), Error> {
        region.assign_advice_from_constant(
            || "rpi_rlc_acc[0]",
            self.rpi_rlc_acc,
            offset,
            F::zero(),
        )?;
        region.assign_advice_from_constant(
            || "rpi_length_acc[0]",
            self.rpi_length_acc,
            offset,
            F::zero(),
        )?;
        Ok((offset + 1, Value::known(F::zero()), Value::known(F::zero())))
    }

    /// Assign a variable length field (in its big-endian byte representation to the PI circuit.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn assign_field(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value_be_bytes: &[u8],
        field_type: RpiFieldType,
        is_rpi_padding: bool,
        mut rpi_rlc_acc: Value<F>, // rlc accumulator over rpi.
        mut rpi_length: Value<F>,  // no. of bytes accumulated since rlc was last initialised.
        challenges: &Challenges<Value<F>>,
    ) -> Result<(usize, Value<F>, Value<F>, Vec<AssignedCell<F, F>>), Error> {
        // The number of bytes to represent this field's value.
        let n_bytes = value_be_bytes.len();

        // Some fields hold 32-byte values and hence do not fit within the scalar field. In such
        // cases, we mark the field as an RLC field, i.e. `is_field_rlc == true` and use the
        // randomness challenge to compute a random linear combination of its be-bytes. For fields
        // that do fit within the scalar field, we simply compute the linear combination with 2^8.
        let (is_field_rlc, field_rand) = if n_bytes * 8 > F::CAPACITY as usize {
            (F::one(), challenges.evm_word())
        } else {
            (F::zero(), Value::known(F::from(BYTE_POW_BASE)))
        };

        // Some random linear combination of bytes are then hashed to check if:
        // keccak256(rlc(bytes)) == hash.
        //
        // The above lookup to the keccak table requires us to use the EVM randomness from the
        // challenge API.
        //
        // However for other cases, we use the keccak randomness from the challenge API.
        let (is_rlc_keccak, rlc_rand) = match field_type {
            RpiFieldType::KeccakHiLo | RpiFieldType::Constant => (F::zero(), challenges.evm_word()),
            _ => (F::one(), challenges.keccak_input()),
        };

        // The RLC of the big-endian bytes representing this field's value.
        let rpi_value = rlc_be_bytes(value_be_bytes, field_rand);

        // The linear combination accumulator for this specific field.
        let rpi_bytes_acc = value_be_bytes
            .iter()
            .scan(Value::known(F::zero()), |acc, &byte| {
                *acc = *acc * field_rand + Value::known(F::from(byte as u64));
                Some(*acc)
            })
            .collect::<Vec<Value<F>>>();

        // Enable the field step until the penultimate offset.
        for q_offset in offset..offset + n_bytes - 1 {
            self.q_field_step.enable(region, q_offset)?;
        }

        let (mut final_rpi_cell, mut final_rpi_rlc_cell, mut final_rpi_length_cell) =
            (None, None, None);
        let cells =
            value_be_bytes
                .iter()
                .zip(rpi_bytes_acc.iter())
                .enumerate()
                .map(|(idx, (&byte, &bytes_acc))| {
                    let row_offset = offset + idx;

                    // Update rpi_rlc and rpi_length if this field is not meant for padding.
                    if !is_rpi_padding {
                        rpi_rlc_acc = rpi_rlc_acc * rlc_rand + Value::known(F::from(byte as u64));
                        rpi_length = rpi_length.map(|v| v + F::one());
                    }

                    region.assign_fixed(
                        || "is_field_rlc",
                        self.is_field_rlc,
                        row_offset,
                        || Value::known(is_field_rlc),
                    )?;
                    region.assign_fixed(
                        || "is_rlc_keccak",
                        self.is_rlc_keccak,
                        row_offset,
                        || Value::known(is_rlc_keccak),
                    )?;
                    region.assign_advice(
                        || "is_rpi_padding",
                        self.is_rpi_padding,
                        row_offset,
                        || Value::known(F::from(is_rpi_padding as u64)),
                    )?;
                    let byte_cell = match field_type {
                        RpiFieldType::Constant => region.assign_advice_from_constant(
                            || "field byte",
                            self.rpi_field_bytes,
                            row_offset,
                            F::from(byte as u64),
                        )?,
                        _ => region.assign_advice(
                            || "field byte",
                            self.rpi_field_bytes,
                            row_offset,
                            || Value::known(F::from(byte as u64)),
                        )?,
                    };
                    let rpi_bytes_acc_cell = region.assign_advice(
                        || "field byte acc",
                        self.rpi_field_bytes_acc,
                        row_offset,
                        || bytes_acc,
                    )?;
                    let rpi_cell = region.assign_advice(
                        || "field value",
                        self.raw_public_inputs,
                        row_offset,
                        || rpi_value,
                    )?;
                    let rpi_rlc_cell = region.assign_advice(
                        || "rpi_rlc_acc",
                        self.rpi_rlc_acc,
                        row_offset,
                        || rpi_rlc_acc,
                    )?;
                    let rpi_length_cell = region.assign_advice(
                        || "rpi_length_acc",
                        self.rpi_length_acc,
                        row_offset,
                        || rpi_length,
                    )?;
                    let real_rpi_cell = region.assign_advice(
                        || "real_rpi",
                        self.real_rpi,
                        row_offset,
                        || {
                            if is_rpi_padding {
                                Value::known(F::zero())
                            } else {
                                rpi_value
                            }
                        },
                    )?;

                    // Update the RPI related cells for the final row.
                    if idx == n_bytes - 1 {
                        final_rpi_cell = match field_type {
                            RpiFieldType::BlockCtx => Some(real_rpi_cell),
                            _ => Some(rpi_cell.clone()),
                        };
                        final_rpi_rlc_cell = Some(rpi_rlc_cell);
                        final_rpi_length_cell = Some(rpi_length_cell);
                    }

                    Ok((byte_cell, (rpi_cell, rpi_bytes_acc_cell)))
                })
                .collect::<Result<
                    Vec<(AssignedCell<F, F>, (AssignedCell<F, F>, AssignedCell<F, F>))>,
                    Error,
                >>()?;

        let (byte_cells, cells): (
            Vec<AssignedCell<F, F>>,
            Vec<(AssignedCell<F, F>, AssignedCell<F, F>)>,
        ) = cells.into_iter().unzip();
        let (rpi_cells, rpi_bytes_acc_cells): (Vec<AssignedCell<F, F>>, Vec<AssignedCell<F, F>>) =
            cells.into_iter().unzip();

        // Copy constraints:
        // byte[0] == rpi_bytes_acc[0]
        region.constrain_equal(byte_cells[0].cell(), rpi_bytes_acc_cells[0].cell())?;

        // Copy constraints:
        // rpi[0] == rpi_cells[1] == ... == rpi_cells[n_bytes - 1]
        for i in 1..n_bytes {
            region.constrain_equal(rpi_cells[0].cell(), rpi_cells[i].cell())?;
        }

        // Copy constraints:
        // rpi[0] == rpi_bytes_acc[n - 1]
        region.constrain_equal(rpi_cells[0].cell(), rpi_bytes_acc_cells[n_bytes - 1].cell())?;

        // We return cells in the following order:
        // [
        //      rpi_cell
        //      rpi_rlc_cell
        //      rpi_length_cell
        //      byte_cell[0]
        //      ...
        //      byte_cell[n_bytes - 1]
        // ]
        Ok((
            offset + n_bytes,
            rpi_rlc_acc,
            rpi_length,
            [
                vec![
                    final_rpi_cell.unwrap(),
                    final_rpi_rlc_cell.unwrap(),
                    final_rpi_length_cell.unwrap(),
                ],
                byte_cells,
            ]
            .concat(),
        ))
    }

    fn assign_block_table(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData,
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let mut offset = 0;

        let block_table_columns = <BlockTable as LookupTable<F>>::advice_columns(&self.block_table);

        for fixed in [self.q_block_tag, self.is_block_num_txs] {
            region.assign_fixed(
                || "block table all-zero row for fixed",
                fixed,
                offset,
                || Value::known(F::zero()),
            )?;
        }
        region.assign_fixed(
            || "tag of first row of block table",
            self.block_table.tag,
            offset,
            || Value::known(F::from(BlockContextFieldTag::Null as u64)),
        )?;
        for column in block_table_columns
            .iter()
            .chain(iter::once(&self.cum_num_txs))
        {
            region.assign_advice(
                || "block table all-zero row",
                *column,
                offset,
                || Value::known(F::zero()),
            )?;
        }
        offset += 1;

        let mut cum_num_txs = 0usize;
        let mut block_value_cells = vec![];
        let block_ctxs = &public_data.block_ctxs;
        let num_all_txs_in_blocks = public_data.get_num_all_txs();
        for block_ctx in block_ctxs.ctxs.values().cloned().chain(
            (block_ctxs.ctxs.len()..public_data.max_inner_blocks).map(|_| {
                BlockContext::padding(
                    public_data.chain_id,
                    public_data.difficulty(),
                    public_data.coinbase(),
                )
            }),
        ) {
            let num_txs = public_data
                .transactions
                .iter()
                .filter(|tx| tx.block_number == block_ctx.number.as_u64())
                .count();
            // unwrap_or(0) for padding block
            let num_all_txs = num_all_txs_in_blocks
                .get(&block_ctx.number.as_u64())
                .cloned()
                .unwrap_or(0);
            let tag = [
                Coinbase, Timestamp, Number, Difficulty, GasLimit, BaseFee, ChainId, NumTxs,
                CumNumTxs, NumAllTxs,
            ];

            // index_cells of same block are equal to block_number.
            let mut index_cells = vec![];
            let mut block_number_cell = None;

            let mut cum_num_txs_field = F::from(cum_num_txs as u64);
            cum_num_txs += num_txs;
            for (row, tag) in block_ctx
                .table_assignments(num_txs, cum_num_txs, num_all_txs, challenges)
                .into_iter()
                .zip(tag.iter())
            {
                region.assign_fixed(
                    || format!("block table row {offset}"),
                    self.block_table.tag,
                    offset,
                    || row[0],
                )?;
                for (column, value) in block_table_columns.iter().zip_eq(&row[1..]) {
                    let cell = region.assign_advice(
                        || format!("block table row {offset}"),
                        *column,
                        offset,
                        || *value,
                    )?;
                    if *tag == Number && *column == self.block_table.value {
                        block_number_cell = Some(cell.clone());
                    }
                    if *column == self.block_table.index {
                        index_cells.push(cell.clone());
                    }
                    if *column == self.block_table.value {
                        block_value_cells.push(cell);
                    }
                }

                region.assign_fixed(
                    || "is_block_num_txs",
                    self.is_block_num_txs,
                    offset,
                    || Value::known(F::from((*tag == NumTxs) as u64)),
                )?;
                if offset != public_data.max_inner_blocks * BLOCK_LEN {
                    // it's not the last row of block table
                    region.assign_fixed(
                        || "q_block_tag",
                        self.q_block_tag,
                        offset,
                        || Value::known(F::one()),
                    )?;
                }
                if *tag == CumNumTxs {
                    // only increase cum_num_txs when the block_table.tag = CumNumTxs
                    cum_num_txs_field = F::from(cum_num_txs as u64);
                }
                if offset == 1 {
                    assert_eq!(cum_num_txs_field, F::zero());
                    // use copy constraint to make sure that cum_num_txs starts with 0
                    region.assign_advice_from_constant(
                        || "cum_num_txs",
                        self.cum_num_txs,
                        offset,
                        cum_num_txs_field,
                    )?;
                } else {
                    region.assign_advice(
                        || "cum_num_txs",
                        self.cum_num_txs,
                        offset,
                        || Value::known(cum_num_txs_field),
                    )?;
                }
                offset += 1;
            }
            // block_num == index[0]
            region.constrain_equal(block_number_cell.unwrap().cell(), index_cells[0].cell())?;
            // index[i] == index[i+1]
            for i in 0..(index_cells.len() - 1) {
                region.constrain_equal(index_cells[i].cell(), index_cells[i + 1].cell())?;
            }
        }

        Ok(block_value_cells)
    }
}

/// Public Inputs Circuit
#[derive(Clone, Debug)]
pub struct PiCircuit<F: Field> {
    /// PublicInputs data known by the verifier
    pub public_data: PublicData,

    _marker: PhantomData<F>,

    connections: RefCell<Option<Connections<F>>>,
    tx_value_cells: RefCell<Option<Vec<AssignedCell<F, F>>>>,
}

impl<F: Field> PiCircuit<F> {
    /// Creates a new PiCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        max_inner_blocks: usize,
        block: &Block<F>,
    ) -> Self {
        let chain_id = block.chain_id;
        let next_state_root = block
            .context
            .ctxs
            .last_key_value()
            .map(|(_, blk)| blk.eth_block.state_root)
            .unwrap_or(H256(block.prev_state_root.to_be_bytes()));
        if block.mpt_updates.new_root().to_be_bytes() != next_state_root.to_fixed_bytes() {
            log::error!(
                "replayed root {:?} != block head root {:?}",
                block.mpt_updates.new_root().to_word(),
                next_state_root
            );
        }
        let public_data = PublicData {
            max_txs,
            max_calldata,
            max_inner_blocks,
            chain_id,
            start_l1_queue_index: block.start_l1_queue_index,
            transactions: block.txs.clone(),
            block_ctxs: block.context.clone(),
            prev_state_root: H256(block.mpt_updates.old_root().to_be_bytes()),
            next_state_root,
            withdraw_trie_root: H256(block.withdraw_root.to_be_bytes()),
        };

        Self {
            public_data,
            _marker: PhantomData,
            connections: Default::default(),
            tx_value_cells: RefCell::new(None),
        }
    }

    /// Return txs
    pub fn txs(&self) -> &[Transaction] {
        &self.public_data.transactions
    }

    /// Import tx value cells from Tx circuit
    pub fn import_tx_values(&self, values: Vec<AssignedCell<F, F>>) {
        *self.tx_value_cells.borrow_mut() = Some(values);
    }

    /// Connect the exportings from other circuit when we are in super circuit
    pub fn connect_export(
        &self,
        layouter: &mut impl Layouter<F>,
        state_roots: Option<&StateCircuitExports<Assigned<F>>>,
        withdraw_roots: Option<&EvmCircuitExports<Assigned<F>>>,
    ) -> Result<(), Error> {
        let local_conn = self
            .connections
            .borrow()
            .clone()
            .expect("expected to be called after syncthesis");

        layouter.assign_region(
            || "pi connecting region",
            |mut region| {
                if let Some(state_roots) = state_roots {
                    log::debug!(
                        "constrain_equal of state root: {:?} <-> {:?}",
                        (&local_conn.start_state_root, &local_conn.end_state_root),
                        (&state_roots.start_state_root, &state_roots.end_state_root)
                    );

                    region.constrain_equal(
                        local_conn.start_state_root.cell(),
                        state_roots.start_state_root.0,
                    )?;
                    region.constrain_equal(
                        local_conn.end_state_root.cell(),
                        state_roots.end_state_root.0,
                    )?;
                } else {
                    log::warn!("state roots are not set, skip connection with state circuit");
                }

                if let Some(withdraw_roots) = withdraw_roots {
                    log::debug!(
                        "constrain_equal of withdraw root: {:?} <-> {:?}",
                        &local_conn.withdraw_root,
                        &withdraw_roots.withdraw_root
                    );
                    region.constrain_equal(
                        local_conn.withdraw_root.cell(),
                        withdraw_roots.withdraw_root.0,
                    )?;
                } else {
                    log::warn!("withdraw roots are not set, skip connection with evm circuit");
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> SubCircuit<F> for PiCircuit<F> {
    type Config = PiCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        PiCircuit::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.circuits_params.max_inner_blocks,
            block,
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let tx_usage = block.txs.len() as f32 / block.circuits_params.max_txs as f32;
        let max_inner_blocks = block.circuits_params.max_inner_blocks;
        let max_txs = block.circuits_params.max_txs;

        let num_rows = 1 + max_inner_blocks * BLOCK_HEADER_BYTES_NUM
            + max_txs * KECCAK_DIGEST_SIZE
            + 1 // for data hash row
            + 1 // for pi bytes start row
            + N_BYTES_U64 // chain_id
            + 4 * KECCAK_DIGEST_SIZE // state_roots & data hash
            + 1 // for pi hash row
            + 1 // for pi hash bytes start row
            + KECCAK_DIGEST_SIZE // pi hash bytes
            + 1 // for coinbase & difficulty start row
            + N_BYTES_ACCOUNT_ADDRESS
            + N_BYTES_WORD;

        (
            (tx_usage * block.circuits_params.max_vertical_circuit_rows as f32).ceil() as usize,
            num_rows,
        )
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let pi_hash = self.public_data.get_pi();

        let public_inputs = iter::empty()
            .chain(
                pi_hash
                    .to_fixed_bytes()
                    .into_iter()
                    .map(|byte| F::from(byte as u64)),
            )
            .collect::<Vec<F>>();

        vec![public_inputs]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let pi_cells = layouter.assign_region(
            || "pi region",
            |mut region| {
                // Annotate columns
                config.tx_table.annotate_columns_in_region(&mut region);
                config.block_table.annotate_columns_in_region(&mut region);

                // assign block table
                let tx_value_cells = self
                    .tx_value_cells
                    .borrow()
                    .clone()
                    .expect("tx_value_cells must have been set");
                let block_value_cells =
                    config.assign_block_table(&mut region, &self.public_data, challenges)?;
                // assign pi cols
                let (inst_byte_cells, conn) = config.assign(
                    &mut region,
                    &self.public_data,
                    &block_value_cells,
                    &tx_value_cells,
                    challenges,
                )?;

                self.connections.borrow_mut().replace(conn);

                Ok(inst_byte_cells)
            },
        )?;

        // Constrain raw_public_input cells to public inputs
        for (i, pi_cell) in pi_cells.iter().enumerate() {
            layouter.constrain_instance(pi_cell.cell(), config.pi, i)?;
        }

        Ok(())
    }
}
