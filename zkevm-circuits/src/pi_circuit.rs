//! Public Input Circuit implementation

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
/// Defines PiTestCircuit
pub mod dev;
mod param;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod test;

use std::{iter, marker::PhantomData, str::FromStr};

use crate::{evm_circuit::util::constraint_builder::ConstrainBuilderCommon, table::KeccakTable};
use bus_mapping::circuit_input_builder::get_dummy_tx_hash;
use eth_types::{Address, Field, Hash, ToBigEndian, Word, H256};
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
        CHAIN_ID_OFFSET, GAS_LIMIT_OFFSET, KECCAK_DIGEST_SIZE, NUM_TXS_OFFSET, RPI_CELL_IDX,
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
use once_cell::sync::Lazy;

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    pi_circuit::param::{COINBASE_OFFSET, DIFFICULTY_OFFSET},
    table::BlockContextFieldTag::{
        BaseFee, ChainId, Coinbase, CumNumTxs, Difficulty, GasLimit, NumTxs, Number, Timestamp,
    },
    util::rlc_be_bytes,
};
use halo2_proofs::circuit::{Cell, RegionIndex};
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};
use itertools::Itertools;

pub(crate) static COINBASE: Lazy<Address> = Lazy::new(|| {
    read_env_var(
        "COINBASE",
        Address::from_str("0x5300000000000000000000000000000000000005").unwrap(),
    )
});
pub(crate) static DIFFICULTY: Lazy<Word> = Lazy::new(|| read_env_var("DIFFICULTY", Word::zero()));

/// PublicData contains all the values that the PiCircuit receives as input
#[derive(Debug, Clone)]
pub struct PublicData {
    /// chain id
    pub chain_id: u64,
    /// Block Transactions
    pub transactions: Vec<Transaction>,
    /// Block contexts
    pub block_ctxs: BlockContexts,
    /// Previous State Root
    pub prev_state_root: Hash,
    /// Withdraw Trie Root
    pub withdraw_trie_root: Hash,
}

impl Default for PublicData {
    fn default() -> Self {
        PublicData {
            chain_id: 0,
            transactions: vec![],
            prev_state_root: H256::zero(),
            withdraw_trie_root: H256::zero(),
            block_ctxs: Default::default(),
        }
    }
}

impl PublicData {
    /// Compute the bytes for dataHash from the verifier's perspective.
    fn data_bytes(&self) -> Vec<u8> {
        let result = iter::empty()
            .chain(self.block_ctxs.ctxs.iter().flat_map(|(block_num, block)| {
                let num_txs = self
                    .transactions
                    .iter()
                    .filter(|tx| tx.block_number == *block_num)
                    .count() as u16;

                iter::empty()
                    // Block Values
                    .chain(block.number.as_u64().to_be_bytes())
                    .chain(block.timestamp.as_u64().to_be_bytes())
                    .chain(block.base_fee.to_be_bytes())
                    .chain(block.gas_limit.to_be_bytes())
                    .chain(num_txs.to_be_bytes())
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
        let withdraw_trie_root = self.withdraw_trie_root;
        let after_state_root = self
            .block_ctxs
            .ctxs
            .last_key_value()
            .map(|(_, blk)| blk.eth_block.state_root)
            .unwrap_or(self.prev_state_root);

        iter::empty()
            .chain(self.chain_id.to_be_bytes())
            // state roots
            .chain(self.prev_state_root.to_fixed_bytes())
            .chain(after_state_root.to_fixed_bytes())
            .chain(withdraw_trie_root.to_fixed_bytes())
            // data hash
            .chain(data_hash.to_fixed_bytes())
            .collect::<Vec<u8>>()
    }

    fn get_pi(&self) -> H256 {
        let data_hash = H256(keccak256(self.data_bytes()));
        let pi_bytes = self.pi_bytes(data_hash);
        let pi_hash = keccak256(pi_bytes);

        H256(pi_hash)
    }
}

impl BlockContext {
    fn padding(chain_id: u64) -> Self {
        Self {
            chain_id,
            coinbase: *COINBASE,
            difficulty: *DIFFICULTY,
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
        Self::padding(0)
    }
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field> {
    /// Max number of supported transactions
    max_txs: usize,
    /// Max number of supported calldata bytes
    max_calldata: usize,
    /// Max number of supported inner blocks in a batch
    max_inner_blocks: usize,

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
    /// Max number of supported transactions
    pub max_txs: usize,
    /// Max number of supported calldata bytes
    pub max_calldata: usize,
    /// Max number of supported blocks in a batch
    pub max_inner_blocks: usize,
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
            max_txs,
            max_calldata,
            max_inner_blocks,
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
                        .chain(challenges.evm_word_powers_of_randomness::<31>().into_iter())
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
        // 1. copy the RLC(data_bytes, keccak_rand) in the `rpi_rlc_acc` column
        //     to the `rpi` column on the row that q_keccak = 1 for data bytes.
        // 2. copy the len(data_bytes) in the `rpi_length_acc` column to the
        //     `rpi_length_acc` column on the row that q_keccak = 1 for data bytes.
        // 3. copy the RLC(data_hash_bytes, word_rand) in the `rpi_rlc_acc` column
        //     to the `rpi_rlc_acc` column on the row that q_keccak = 1 for data hash.

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
                .zip(keccak_table_exprs.into_iter())
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

                cb.gate(meta.query_fixed(q_block_tag, Rotation::cur()))
            }
        );

        Self {
            max_txs,
            max_calldata,
            max_inner_blocks,
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
    #[allow(clippy::type_complexity)]
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData,
        block_value_cells: &[AssignedCell<F, F>],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(PiHashExport<F>, Connections<F>), Error> {
        let block_values = &public_data.block_ctxs;
        let chain_id = block_values
            .ctxs
            .first_key_value()
            .map_or(0, |(_, context)| context.chain_id);
        let tx_hashes = public_data
            .transactions
            .iter()
            .map(|tx| tx.hash)
            .collect::<Vec<H256>>();

        let mut offset = 0;
        let mut block_copy_cells = vec![];
        let mut tx_copy_cells = vec![];
        let mut block_table_offset = 1; // first row of block is all-zeros.

        let mut rpi_length_acc = 0u64;
        let mut rpi_rlc_acc = Value::known(F::zero());

        let dummy_tx_hash = get_dummy_tx_hash();

        ///////////////////////////////////
        ///////  assign data bytes ////////
        ///////////////////////////////////
        let data_bytes_start_row = 0;
        let data_bytes_end_row =
            self.max_inner_blocks * BLOCK_HEADER_BYTES_NUM + self.max_txs * KECCAK_DIGEST_SIZE;
        self.assign_rlc_start(region, &mut offset, &mut rpi_rlc_acc, &mut rpi_length_acc)?;
        // assign block contexts
        for (i, block) in block_values
            .ctxs
            .values()
            .cloned()
            .chain(
                (block_values.ctxs.len()..self.max_inner_blocks)
                    .into_iter()
                    .map(|_| BlockContext::padding(chain_id)),
            )
            .enumerate()
        {
            let is_rpi_padding = i >= block_values.ctxs.len();
            let num_txs = public_data
                .transactions
                .iter()
                .filter(|tx| tx.block_number == block.number.as_u64())
                .count() as u16;

            // Assign fields in pi columns and connect them to block table
            let fields = vec![
                (
                    block.number.as_u64().to_be_bytes().to_vec(),
                    BLOCK_NUM_OFFSET,
                ), // number
                (
                    block.timestamp.as_u64().to_be_bytes().to_vec(),
                    TIMESTAMP_OFFSET,
                ), // timestamp
                (block.base_fee.to_be_bytes().to_vec(), BASE_FEE_OFFSET), // base_fee
                (block.gas_limit.to_be_bytes().to_vec(), GAS_LIMIT_OFFSET), // gas_limit
                (num_txs.to_be_bytes().to_vec(), NUM_TXS_OFFSET),         // num_txs
            ];
            for (bytes, block_offset) in fields {
                let cells = self.assign_field_in_pi(
                    region,
                    &mut offset,
                    bytes.as_slice(),
                    &mut rpi_rlc_acc,
                    &mut rpi_length_acc,
                    true,
                    is_rpi_padding,
                    false,
                    challenges,
                )?;
                block_copy_cells.push((
                    cells[RPI_CELL_IDX].clone(),
                    block_table_offset + block_offset,
                ));
            }

            block_table_offset += BLOCK_LEN;
        }

        let q_block_context_start_row = 1;
        let q_block_context_end_row = 1 + BLOCK_HEADER_BYTES_NUM * self.max_inner_blocks;
        for i in q_block_context_start_row..q_block_context_end_row {
            // assign q_block_context
            region.assign_fixed(
                || "q_block_context",
                self.q_block_context,
                i,
                || Value::known(F::one()),
            )?;
        }

        debug_assert_eq!(offset, 1 + BLOCK_HEADER_BYTES_NUM * self.max_inner_blocks);

        // assign tx hashes
        let q_tx_hashes_start_row = offset;
        let q_tx_hashes_end_row = q_tx_hashes_start_row + KECCAK_DIGEST_SIZE * self.max_txs;
        let num_txs = tx_hashes.len();
        let mut data_bytes_rlc = None;
        let mut data_bytes_length = None;
        for (i, tx_hash) in tx_hashes
            .into_iter()
            .chain(
                (0..self.max_txs - num_txs)
                    .into_iter()
                    .map(|_| dummy_tx_hash),
            )
            .enumerate()
        {
            let is_rpi_padding = i >= num_txs;

            let cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &tx_hash.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                false,
                is_rpi_padding,
                false,
                challenges,
            )?;
            tx_copy_cells.push(cells[RPI_CELL_IDX].clone());

            if i == self.max_txs - 1 {
                data_bytes_rlc = Some(cells[RPI_RLC_ACC_CELL_IDX].clone());
                data_bytes_length = Some(cells[RPI_LENGTH_ACC_CELL_IDX].clone());
            }
        }
        for i in q_tx_hashes_start_row..q_tx_hashes_end_row {
            region.assign_fixed(
                || "q_tx_hashes",
                self.q_tx_hashes,
                i,
                || Value::known(F::one()),
            )?;
        }

        assert_eq!(offset, data_bytes_end_row + 1);

        // the last row of data bytes part is disabled
        for i in data_bytes_start_row..data_bytes_end_row {
            self.q_not_end.enable(region, i)?;
        }

        // copy block context fields to block table
        for (block_cell, row_offset) in block_copy_cells.into_iter() {
            region.constrain_equal(
                block_cell.cell(),
                block_value_cells[row_offset - 1].cell(), /* -1 for block table's first row of
                                                           * all-zeros */
            )?;
        }
        // copy tx_hashes to tx table
        for (i, tx_hash_cell) in tx_copy_cells.into_iter().enumerate() {
            region.constrain_equal(
                tx_hash_cell.cell(),
                Cell {
                    region_index: RegionIndex(1), // FIXME: this is not safe
                    row_offset: i * TX_LEN + TX_HASH_OFFSET,
                    column: self.tx_table.value.into(),
                },
            )?;
        }

        // assign keccak row for computing data_hash = keccak256(data bytes)
        let data_hash_row = offset;
        data_bytes_rlc.unwrap().copy_advice(
            || "data_bytes_rlc in the rpi col",
            region,
            self.raw_public_inputs,
            data_hash_row,
        )?;
        let data_hash = public_data.get_data_hash();
        let data_hash_rlc = rlc_be_bytes(&data_hash.to_fixed_bytes(), challenges.evm_word());
        data_bytes_length.unwrap().copy_advice(
            || "data_bytes_length in the rpi_length_acc col",
            region,
            self.rpi_length_acc,
            data_hash_row,
        )?;
        let data_hash_rlc_cell = region.assign_advice(
            || "data_hash_rlc",
            self.rpi_rlc_acc,
            data_hash_row,
            || data_hash_rlc,
        )?;
        self.q_keccak.enable(region, data_hash_row)?;
        offset += 1;

        /////////////////////////////////
        ///////// assign pi bytes ///////
        /////////////////////////////////
        let pi_bytes_start_row = offset;
        let pi_bytes_end_row = pi_bytes_start_row + N_BYTES_U64 + N_BYTES_WORD * 4;
        self.assign_rlc_start(region, &mut offset, &mut rpi_rlc_acc, &mut rpi_length_acc)?;
        // assign chain_id
        let cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &public_data.chain_id.to_be_bytes(),
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            false,
            challenges,
        )?;
        let chain_id_cell = cells[RPI_CELL_IDX].clone();
        // copy chain_id to block table
        for block_idx in 0..self.max_inner_blocks {
            region.constrain_equal(
                chain_id_cell.cell(),
                block_value_cells[block_idx * BLOCK_LEN + CHAIN_ID_OFFSET].cell(),
            )?;
        }
        // copy chain_id to tx table
        for tx_id in 0..self.max_txs {
            region.constrain_equal(
                chain_id_cell.cell(),
                Cell {
                    region_index: RegionIndex(1), // FIXME: this is not safe
                    row_offset: tx_id * TX_LEN + CHAIN_ID_OFFSET_IN_TX,
                    column: self.tx_table.value.into(),
                },
            )?;
        }

        // assign roots
        //  1. prev_state_root
        //  2. after_state_root
        //  3. withdraw_trie_root

        // state_root after applying this batch
        let after_state_root = block_values
            .ctxs
            .last_key_value()
            .map(|(_, blk)| blk.eth_block.state_root)
            .unwrap_or(public_data.prev_state_root);
        let roots = vec![
            public_data.prev_state_root.to_fixed_bytes(),
            after_state_root.to_fixed_bytes(),
            public_data.withdraw_trie_root.to_fixed_bytes(),
        ];
        let root_cells = roots
            .into_iter()
            .map(|root_be_bytes| -> Result<AssignedCell<F, F>, Error> {
                let cells = self.assign_field_in_pi(
                    region,
                    &mut offset,
                    root_be_bytes.as_slice(),
                    &mut rpi_rlc_acc,
                    &mut rpi_length_acc,
                    false,
                    false,
                    false,
                    challenges,
                )?;
                Ok(cells[RPI_CELL_IDX].clone())
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let connections = Connections {
            start_state_root: root_cells[0].clone(),
            end_state_root: root_cells[1].clone(),
            withdraw_root: root_cells[2].clone(),
        };

        // assign data_hash
        let cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &data_hash.to_fixed_bytes(),
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            false,
            challenges,
        )?;
        let data_hash_cell = cells[RPI_CELL_IDX].clone();
        let pi_bytes_rlc = cells[RPI_RLC_ACC_CELL_IDX].clone();
        let pi_bytes_length = cells[RPI_LENGTH_ACC_CELL_IDX].clone();

        // copy data_hash down here
        region.constrain_equal(data_hash_rlc_cell.cell(), data_hash_cell.cell())?;

        for i in pi_bytes_start_row..pi_bytes_end_row {
            self.q_not_end.enable(region, i)?;
        }

        // +1 for the rlc_start row
        assert_eq!(offset, pi_bytes_end_row + 1);

        // assign keccak row for computing pi_hash = keccak256(pi_bytes)
        let pi_hash_row = offset;
        pi_bytes_rlc.copy_advice(
            || "pi_bytes_rlc in the rpi col",
            region,
            self.raw_public_inputs,
            pi_hash_row,
        )?;
        let pi_hash = public_data.get_pi();
        let pi_hash_rlc = rlc_be_bytes(&pi_hash.to_fixed_bytes(), challenges.evm_word());
        pi_bytes_length.copy_advice(
            || "pi_bytes_length in the rpi_length_acc col",
            region,
            self.rpi_length_acc,
            pi_hash_row,
        )?;
        let pi_hash_rlc_cell = region.assign_advice(
            || "pi_hash_rlc",
            self.rpi_rlc_acc,
            pi_hash_row,
            || pi_hash_rlc,
        )?;
        self.q_keccak.enable(region, pi_hash_row)?;
        offset += 1;

        //////////////////////////////////////////////////
        //// assign pi_hash (high, low)-decomposition ////
        //////////////////////////////////////////////////
        let pi_hash_bytes_start_row = offset;
        let pi_hash_bytes_end_row = pi_hash_bytes_start_row + KECCAK_DIGEST_SIZE;
        self.assign_rlc_start(region, &mut offset, &mut rpi_rlc_acc, &mut rpi_length_acc)?;

        for i in pi_hash_bytes_start_row..pi_hash_bytes_end_row {
            self.q_not_end.enable(region, i)?;
        }

        // the high 16 bytes of keccak output
        let cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &pi_hash.to_fixed_bytes()[..16],
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            true,
            challenges,
        )?;
        let pi_hash_hi_byte_cells = cells[3..].to_vec();
        // let pi_hash_hi_cell = cells[RPI_CELL_IDX].clone();

        // the low 16 bytes of keccak output
        let cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &pi_hash.to_fixed_bytes()[16..],
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            true,
            challenges,
        )?;
        let pi_hash_lo_byte_cells = cells[3..].to_vec();
        // let pi_hash_lo_cell = cells[RPI_CELL_IDX].clone();

        // +1 for the rlc_start row
        assert_eq!(offset, pi_hash_bytes_end_row + 1);

        // copy pi hash down here
        region.constrain_equal(pi_hash_rlc_cell.cell(), cells[RPI_RLC_ACC_CELL_IDX].cell())?;

        //////////////////////////////////////////////////
        ////////// assign COINBASE, DIFFICULTY  //////////
        //////////////////////////////////////////////////
        let coinbase_diff_start_row = offset;
        let coinbase_diff_end_row =
            coinbase_diff_start_row + N_BYTES_ACCOUNT_ADDRESS + N_BYTES_WORD;

        self.assign_rlc_start(region, &mut offset, &mut rpi_rlc_acc, &mut rpi_length_acc)?;

        let cells = self.assign_field_in_pi_ext(
            region,
            &mut offset,
            &(*COINBASE).to_fixed_bytes(),
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            true,
            true,
            challenges,
        )?;
        let coinbase_cell = cells[RPI_CELL_IDX].clone();

        let cells = self.assign_field_in_pi_ext(
            region,
            &mut offset,
            &(*DIFFICULTY).to_be_bytes(),
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            true,
            true,
            challenges,
        )?;
        let difficulty_cell = cells[RPI_CELL_IDX].clone();

        for i in coinbase_diff_start_row..coinbase_diff_end_row {
            self.q_not_end.enable(region, i)?;
        }

        // copy to block table
        for block_idx in 0..self.max_inner_blocks {
            region.constrain_equal(
                coinbase_cell.cell(),
                block_value_cells[BLOCK_LEN * block_idx + COINBASE_OFFSET].cell(),
            )?;
            region.constrain_equal(
                difficulty_cell.cell(),
                block_value_cells[BLOCK_LEN * block_idx + DIFFICULTY_OFFSET].cell(),
            )?;
        }

        assert_eq!(
            offset,
            // for data bytes start row
            1 + self.max_inner_blocks * BLOCK_HEADER_BYTES_NUM
                + self.max_txs * KECCAK_DIGEST_SIZE
                + 1 // for data hash row
                + 1 // for pi bytes start row
                + N_BYTES_U64
                + 4 * KECCAK_DIGEST_SIZE
                + 1 // for pi hash row
                + 1 // for pi hash bytes start row
                + KECCAK_DIGEST_SIZE
                + 1 // for coinbase & difficulty start row
                + N_BYTES_ACCOUNT_ADDRESS
                + N_BYTES_WORD,
        );

        let instance_byte_cells = [pi_hash_hi_byte_cells, pi_hash_lo_byte_cells].concat();

        Ok((instance_byte_cells, connections))
    }

    fn assign_rlc_start(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        rpi_rlc_acc: &mut Value<F>,
        rpi_length_acc: &mut u64,
    ) -> Result<(), Error> {
        *rpi_rlc_acc = Value::known(F::zero());
        *rpi_length_acc = 0;

        region.assign_advice_from_constant(
            || "rpi_rlc_acc[0]",
            self.rpi_rlc_acc,
            *offset,
            F::zero(),
        )?;
        region.assign_advice_from_constant(
            || "rpi_length_acc[0]",
            self.rpi_length_acc,
            *offset,
            F::zero(),
        )?;
        *offset += 1;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_field_in_pi(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        value_be_bytes: &[u8],
        rpi_rlc_acc: &mut Value<F>,
        rpi_length_acc: &mut u64,
        is_block_context: bool, // if this field related to block context
        is_rpi_padding: bool,   // if this field is not included in the data bytes
        keccak_hi_lo: bool,     // if this field is related to keccak decomposition
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        self.assign_field_in_pi_ext(
            region,
            offset,
            value_be_bytes,
            rpi_rlc_acc,
            rpi_length_acc,
            is_block_context,
            is_rpi_padding,
            keccak_hi_lo,
            false,
            challenges,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_field_in_pi_ext(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        value_be_bytes: &[u8],
        rpi_rlc_acc: &mut Value<F>,
        rpi_length_acc: &mut u64,
        is_block_context: bool, // if this field related to block context
        is_rpi_padding: bool,   // if this field is not included in the data bytes
        keccak_hi_lo: bool,     // if this field is related to keccak decomposition
        is_constant: bool,
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let len = value_be_bytes.len();

        let (is_field_rlc, t) = if len * 8 > F::CAPACITY as usize {
            (F::one(), challenges.evm_word())
        } else {
            (F::zero(), Value::known(F::from(BYTE_POW_BASE)))
        };
        // keccak_hi_lo = true if we are re-using rpi layout for keccak bytes
        let r = if keccak_hi_lo {
            challenges.evm_word()
        } else {
            challenges.keccak_input()
        };
        let value = rlc_be_bytes(value_be_bytes, t);
        let mut value_bytes_acc = Value::known(F::zero());

        // +3 for rpi, rpi_rlc_acc, rpi_length_acc
        let mut cells = vec![None; 3 + value_be_bytes.len()];

        // use copy constraints to make sure that
        // 1. rpi_cells are equal.
        // 2. rpi_cell equals to the last rpi_bytes_acc
        // 3. the first rpi_bytes_acc equals to the first byte_cell
        let mut rpi_cells = vec![];
        let mut rpi_bytes_acc_cells = vec![];
        let mut byte_cells = vec![];
        for (i, byte) in value_be_bytes.iter().enumerate() {
            let row_offset = *offset + i;

            let real_value = if is_rpi_padding {
                Value::known(F::zero())
            } else {
                value
            };

            value_bytes_acc = value_bytes_acc
                .zip(t)
                .and_then(|(acc, t)| Value::known(acc * t + F::from(*byte as u64)));

            // this field is not padding then we absorb the byte into rpi_rlc_acc
            if !is_rpi_padding {
                *rpi_rlc_acc = rpi_rlc_acc
                    .zip(r)
                    .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)));
                *rpi_length_acc += 1;
            }

            // set field-related selectors
            if i < len - 1 {
                self.q_field_step.enable(region, row_offset)?;
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
                || Value::known(F::from(!keccak_hi_lo as u64)),
            )?;

            let byte_cell = if is_constant {
                region.assign_advice_from_constant(
                    || "field byte",
                    self.rpi_field_bytes,
                    row_offset,
                    F::from(*byte as u64),
                )?
            } else {
                region.assign_advice(
                    || "field byte",
                    self.rpi_field_bytes,
                    row_offset,
                    || Value::known(F::from(*byte as u64)),
                )?
            };

            let rpi_bytes_acc_cell = region.assign_advice(
                || "field byte acc",
                self.rpi_field_bytes_acc,
                row_offset,
                || value_bytes_acc,
            )?;
            let rpi_cell = region.assign_advice(
                || "field value",
                self.raw_public_inputs,
                row_offset,
                || value,
            )?;
            let rpi_rlc_cell = region.assign_advice(
                || "rpi_rlc_acc",
                self.rpi_rlc_acc,
                row_offset,
                || *rpi_rlc_acc,
            )?;
            let rpi_length_cell = {
                region.assign_advice(
                    || "rpi_length_acc",
                    self.rpi_length_acc,
                    row_offset,
                    || Value::known(F::from(*rpi_length_acc)),
                )?
            };

            region.assign_advice(
                || "is_rpi_padding",
                self.is_rpi_padding,
                row_offset,
                || Value::known(F::from(is_rpi_padding as u64)),
            )?;
            // For block context fields,
            //  If it's padding, then the rpi cell does not matter any more
            //  as it's not included in the data bytes. This means the rpi cell is not
            //  constrained. Then we cannot use that to connect to block table.
            //  Therefore we use the `real_rpi_cell` instead.
            let real_rpi_cell =
                region.assign_advice(|| "real_rpi", self.real_rpi, row_offset, || real_value)?;

            rpi_cells.push(rpi_cell.clone());
            rpi_bytes_acc_cells.push(rpi_bytes_acc_cell);
            byte_cells.push(byte_cell.clone());

            if i == len - 1 {
                cells[RPI_CELL_IDX] = if is_block_context {
                    Some(real_rpi_cell)
                } else {
                    Some(rpi_cell)
                };
                cells[RPI_RLC_ACC_CELL_IDX] = Some(rpi_rlc_cell);
                cells[RPI_LENGTH_ACC_CELL_IDX] = Some(rpi_length_cell);
            }
            cells[i + 3] = Some(byte_cell);
        }

        // copy constraints
        region.constrain_equal(byte_cells[0].cell(), rpi_bytes_acc_cells[0].cell())?;
        region.constrain_equal(rpi_cells[0].cell(), rpi_bytes_acc_cells[len - 1].cell())?;
        for i in 1..len {
            region.constrain_equal(rpi_cells[0].cell(), rpi_cells[i].cell())?;
        }

        *offset += len;

        Ok(cells.into_iter().map(|cell| cell.unwrap()).collect())
    }

    fn assign_block_table(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData,
        max_inner_blocks: usize,
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
        for block_ctx in block_ctxs.ctxs.values().cloned().chain(
            (block_ctxs.ctxs.len()..max_inner_blocks)
                .into_iter()
                .map(|_| BlockContext::padding(public_data.chain_id)),
        ) {
            let num_txs = public_data
                .transactions
                .iter()
                .filter(|tx| tx.block_number == block_ctx.number.as_u64())
                .count();
            let tag = [
                Coinbase, Timestamp, Number, Difficulty, GasLimit, BaseFee, ChainId, NumTxs,
                CumNumTxs,
            ];
            let mut cum_num_txs_field = F::from(cum_num_txs as u64);
            cum_num_txs += num_txs;
            for (row, tag) in block_ctx
                .table_assignments(num_txs, cum_num_txs, challenges)
                .into_iter()
                .zip(tag.iter())
            {
                region.assign_fixed(
                    || format!("block table row {offset}"),
                    self.block_table.tag,
                    offset,
                    || row[0],
                )?;
                // index_cells of same block are equal to block_number.
                let mut index_cells = vec![];
                let mut block_number_cell = None;
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
                for i in 0..(index_cells.len() - 1) {
                    region.constrain_equal(index_cells[i].cell(), index_cells[i + 1].cell())?;
                }
                if *tag == Number {
                    region.constrain_equal(
                        block_number_cell.unwrap().cell(),
                        index_cells[0].cell(),
                    )?;
                }

                region.assign_fixed(
                    || "is_block_num_txs",
                    self.is_block_num_txs,
                    offset,
                    || Value::known(F::from((*tag == NumTxs) as u64)),
                )?;
                if offset != max_inner_blocks * BLOCK_LEN {
                    // it's not the last row of block table
                    region.assign_fixed(
                        || "q_block_tag",
                        self.q_block_tag,
                        offset,
                        || Value::known(F::one()),
                    )?;
                }
                if *tag == CumNumTxs {
                    cum_num_txs_field = F::from(cum_num_txs as u64);
                }
                if offset == 1 {
                    assert_eq!(cum_num_txs_field, F::zero());
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
        }

        Ok(block_value_cells)
    }
}

/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct PiCircuit<F: Field> {
    max_txs: usize,
    max_calldata: usize,
    max_inner_blocks: usize,
    /// PublicInputs data known by the verifier
    pub public_data: PublicData,

    _marker: PhantomData<F>,

    connections: std::cell::RefCell<Option<Connections<F>>>,
}

impl<F: Field> PiCircuit<F> {
    /// Creates a new PiCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        max_inner_blocks: usize,
        block: &Block<F>,
    ) -> Self {
        let chain_id = block
            .context
            .ctxs
            .iter()
            .next()
            .map_or(0, |(_k, v)| v.chain_id);
        let public_data = PublicData {
            chain_id,
            transactions: block.txs.clone(),
            block_ctxs: block.context.clone(),
            prev_state_root: H256(block.mpt_updates.old_root().to_be_bytes()),
            withdraw_trie_root: H256(block.withdraw_root.to_be_bytes()),
        };
        Self {
            public_data,
            max_txs,
            max_calldata,
            max_inner_blocks,
            _marker: PhantomData,
            connections: Default::default(),
        }
    }

    /// Return txs
    pub fn txs(&self) -> &[Transaction] {
        &self.public_data.transactions
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

                    #[cfg(feature = "scroll-trace")]
                    {
                        region.constrain_equal(
                            local_conn.start_state_root.cell(),
                            state_roots.start_state_root.0,
                        )?;
                        region.constrain_equal(
                            local_conn.end_state_root.cell(),
                            state_roots.end_state_root.0,
                        )?;
                    }
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
        let row_num = |inner_block_num, tx_num| -> usize {
            BLOCK_HEADER_BYTES_NUM * inner_block_num + KECCAK_DIGEST_SIZE * tx_num + 33
        };
        (
            row_num(block.context.ctxs.len(), block.txs.len()),
            row_num(
                block.circuits_params.max_inner_blocks,
                block.circuits_params.max_txs,
            ),
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
                let block_value_cells = config.assign_block_table(
                    &mut region,
                    &self.public_data,
                    self.max_inner_blocks,
                    challenges,
                )?;
                // assign pi cols
                let (inst_byte_cells, conn) = config.assign(
                    &mut region,
                    &self.public_data,
                    &block_value_cells,
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
