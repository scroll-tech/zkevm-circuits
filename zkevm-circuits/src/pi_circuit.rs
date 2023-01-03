//! Public Input Circuit implementation

use std::iter;
use std::marker::PhantomData;

use crate::table::TxTable;
use crate::table::{BlockTable, KeccakTable};
use bus_mapping::circuit_input_builder::get_dummy_tx_hash;
use eth_types::H256;
use eth_types::{Field, ToBigEndian, Word};
use ethers_core::utils::keccak256;
use halo2_proofs::plonk::{Expression, Fixed, Instance, SecondPhase};

use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::util::{Challenges, SubCircuit, SubCircuitConfig};
use crate::witness::{Block, BlockContext, BlockContexts, Transaction};
use gadgets::util::{not, select, Expr};
use halo2_proofs::circuit::{Cell, RegionIndex};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

/// Fixed by the spec
const BLOCK_LEN: usize = 7 + 256;
const EXTRA_LEN: usize = 2;
const BYTE_POW_BASE: u64 = 1 << 8;
const BLOCK_HEADER_BYTES_NUM: usize = 148;
const KECCAK_DIGEST_SIZE: usize = 32;
const RPI_CELL_IDX: usize = 0;
const RPI_RLC_ACC_CELL_IDX: usize = 1;
const ZERO_BYTE_GAS_COST: u64 = 4;
const NONZERO_BYTE_GAS_COST: u64 = 16;

/// PublicData contains all the values that the PiCircuit recieves as input
#[derive(Debug, Clone, Default)]
pub struct PublicData {
    /// chain id
    pub chain_id: Word,
    /// Block Transactions
    pub transactions: Vec<Transaction>,
    /// Block contexts
    pub block_ctxs: BlockContexts,
}

impl PublicData {
    /// Compute the raw_public_inputs bytes from the verifier's perspective.
    fn raw_public_input_bytes(&self, max_txs: usize) -> Vec<u8> {
        // TODO: add history hashes and state roots
        let dummy_tx_hash = get_dummy_tx_hash(self.chain_id.as_u64());

        let result = self
            .block_ctxs
            .ctxs
            .iter()
            .flat_map(|(block_num, block)| {
                let num_txs = self
                    .transactions
                    .iter()
                    .filter(|tx| tx.block_number == *block_num)
                    .count() as u64;

                iter::empty()
                    // Block Values
                    .chain(block.coinbase.to_fixed_bytes())
                    .chain(block.timestamp.as_u64().to_be_bytes())
                    .chain(block.number.as_u64().to_be_bytes())
                    .chain(block.difficulty.to_be_bytes())
                    .chain(block.gas_limit.to_be_bytes())
                    .chain(block.base_fee.to_be_bytes())
                    .chain(block.chain_id.to_be_bytes())
                    .chain(num_txs.to_be_bytes())
            })
            // history_hashes
            // .chain(
            //     block
            //         .history_hashes
            //         .iter()
            //         .flat_map(|tx_hash| tx_hash.to_fixed_bytes()),
            // )
            // state roots
            // .chain(
            //     extra.state_root.to_fixed_bytes()
            // )
            // .chain(
            //     extra.prev_state_root.to_fixed_bytes()
            // )
            // Tx Hashes
            .chain(
                self.transactions
                    .iter()
                    .flat_map(|tx| tx.hash.to_fixed_bytes()),
            )
            .chain(
                (0..(max_txs - self.transactions.len()))
                    .into_iter()
                    .flat_map(|_| dummy_tx_hash.to_fixed_bytes()),
            )
            .collect::<Vec<u8>>();

        assert_eq!(
            result.len(),
            BLOCK_HEADER_BYTES_NUM * self.block_ctxs.ctxs.len() + KECCAK_DIGEST_SIZE * max_txs
        );
        result
    }

    fn get_pi(&self, max_txs: usize) -> H256 {
        let rpi_bytes = self.raw_public_input_bytes(max_txs);
        let rpi_keccak = keccak256(&rpi_bytes);
        H256(rpi_keccak)
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

    raw_public_inputs: Column<Advice>, // block, history_hashes, states, tx hashes
    rpi_field_bytes: Column<Advice>,   // rpi in bytes
    rpi_field_bytes_acc: Column<Advice>,
    rpi_rlc_acc: Column<Advice>, // RLC(rpi) as the input to Keccak table
    rpi_length_acc: Column<Advice>,

    is_rpi_padding: Column<Advice>,
    real_rpi: Column<Advice>,

    q_field_start: Selector,
    q_field_step: Selector,
    is_field_rlc: Column<Fixed>,
    q_field_end: Selector,

    q_start: Selector,
    q_not_end: Selector,
    q_keccak: Selector,

    pi: Column<Instance>, // hi(keccak(rpi)), lo(keccak(rpi))

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
        let rpi = meta.advice_column_in(SecondPhase);
        let rpi_bytes = meta.advice_column();
        let rpi_bytes_acc = meta.advice_column_in(SecondPhase);
        let rpi_rlc_acc = meta.advice_column_in(SecondPhase);
        let rpi_length_acc = meta.advice_column();
        let is_rpi_padding = meta.advice_column();
        let real_rpi = meta.advice_column_in(SecondPhase);

        let pi = meta.instance_column();

        let q_field_start = meta.complex_selector();
        let q_field_step = meta.complex_selector();
        let q_field_end = meta.complex_selector();
        let is_field_rlc = meta.fixed_column();

        let q_start = meta.complex_selector();
        let q_not_end = meta.complex_selector();
        let q_keccak = meta.complex_selector();

        meta.enable_equality(rpi);
        meta.enable_equality(real_rpi);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(block_table.value); // copy block to rpi
        meta.enable_equality(tx_table.value); // copy tx hashes to rpi
        meta.enable_equality(pi);

        // field bytes
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
        meta.create_gate("rpi_bytes_acc = rpi_bytes for field start", |meta| {
            let q_field_start = meta.query_selector(q_field_start);
            let rpi_field_bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
            let rpi_field_bytes = meta.query_advice(rpi_bytes, Rotation::cur());

            vec![q_field_start * (rpi_field_bytes_acc - rpi_field_bytes)]
        });
        meta.create_gate("rpi_bytes_acc = rpi for field end", |meta| {
            let q_field_end = meta.query_selector(q_field_end);
            let rpi_bytes_acc = meta.query_advice(rpi_bytes_acc, Rotation::cur());
            let rpi = meta.query_advice(rpi, Rotation::cur());

            vec![q_field_end * (rpi - rpi_bytes_acc)]
        });
        meta.create_gate("rpi_next = rpi", |meta| {
            let q_field_step = meta.query_selector(q_field_step);
            let rpi_next = meta.query_advice(rpi, Rotation::next());
            let rpi = meta.query_advice(rpi, Rotation::cur());

            vec![q_field_step * (rpi_next - rpi)]
        });

        // rpi_rlc
        meta.create_gate(
            "rpi_rlc_acc[i+1] = keccak_rand * rpi_rlc_acc[i] + rpi_bytes[i+1]",
            |meta| {
                // if is_rpi_padding is true, then
                //   q_not_end * row_next.rpi_rlc_acc ==
                //   (q_not_end * row.rpi_rlc_acc * keccak_rand + row_next.rpi_bytes)
                // else,
                //   q_not_end * row_next.rpi_rlc_acc == q_not_end * row.rpi_rlc_acc
                let mut cb = BaseConstraintBuilder::default();
                let is_rpi_padding = meta.query_advice(is_rpi_padding, Rotation::next());
                let rpi_rlc_acc_cur = meta.query_advice(rpi_rlc_acc, Rotation::cur());
                let rpi_bytes_next = meta.query_advice(rpi_bytes, Rotation::next());
                let keccak_rand = challenges.keccak_input();

                cb.require_equal(
                    "rpi_rlc_acc' = is_rpi_padding ? rpi_rlc_acc : rpi_rlc_acc * r + rpi_bytes'",
                    meta.query_advice(rpi_rlc_acc, Rotation::next()),
                    select::expr(
                        is_rpi_padding.expr(),
                        rpi_rlc_acc_cur.expr(),
                        rpi_rlc_acc_cur * keccak_rand + rpi_bytes_next,
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
        meta.create_gate("rpi_rlc_acc[0] = rpi_bytes[0]", |meta| {
            let q_start = meta.query_selector(q_start);
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            let rpi_bytes = meta.query_advice(rpi_bytes, Rotation::cur());

            vec![q_start * (rpi_rlc_acc - rpi_bytes)]
        });
        meta.create_gate("real rpi", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_rpi_padding is boolean",
                meta.query_advice(is_rpi_padding, Rotation::cur()),
            );

            cb.require_equal(
                "real_rpi == not(is_rpi_padding) * rpi",
                meta.query_advice(real_rpi, Rotation::cur()),
                not::expr(meta.query_advice(is_rpi_padding, Rotation::cur()))
                    * meta.query_advice(rpi, Rotation::cur()),
            );

            cb.gate(meta.query_selector(q_not_end))
        });

        meta.lookup_any("keccak(rpi)", |meta| {
            let is_enabled = meta.query_advice(keccak_table.is_enabled, Rotation::cur());
            let input_rlc = meta.query_advice(keccak_table.input_rlc, Rotation::cur());
            let input_len = meta.query_advice(keccak_table.input_len, Rotation::cur());
            let output_rlc = meta.query_advice(keccak_table.output_rlc, Rotation::cur());
            let q_keccak = meta.query_selector(q_keccak);

            let rpi_rlc = meta.query_advice(rpi, Rotation::cur());
            let rpi_length = meta.query_advice(rpi_length_acc, Rotation::cur());
            let output = meta.query_advice(rpi_rlc_acc, Rotation::cur());

            vec![
                (q_keccak.expr() * 1.expr(), is_enabled),
                (q_keccak.expr() * rpi_rlc, input_rlc),
                (
                    q_keccak.expr()
                        // * (BLOCK_HEADER_BYTES_NUM + max_txs * KECCAK_DIGEST_SIZE).expr(),
                        * rpi_length,
                    input_len,
                ),
                (q_keccak * output, output_rlc),
            ]
        });

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

        // TODO: add constraints on block_table.value for tag = 'CumNumTxs'.
        //       cur_block.cum_num_txs = prev_block.cum_num_txs + cur_block.num_txs

        Self {
            max_txs,
            max_calldata,
            max_inner_blocks,
            block_table,
            tx_table,
            keccak_table,
            raw_public_inputs: rpi,
            rpi_field_bytes: rpi_bytes,
            rpi_field_bytes_acc: rpi_bytes_acc,
            rpi_rlc_acc,
            rpi_length_acc,
            is_rpi_padding,
            real_rpi,
            q_field_start,
            q_field_step,
            is_field_rlc,
            q_field_end,
            q_start,
            q_not_end,
            q_keccak,
            pi,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> PiCircuitConfig<F> {
    #[allow(clippy::type_complexity)]
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        public_data: &PublicData,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let block_values = &public_data.block_ctxs;
        let tx_hashes = public_data
            .transactions
            .iter()
            .map(|tx| tx.hash)
            .collect::<Vec<H256>>();

        let mut offset = 0;
        let mut rpi_length_acc = 0u64;
        let mut block_copy_cells = vec![];
        let mut block_copy_offsets = vec![];
        let mut tx_copy_cells = vec![];
        let mut block_table_offset = 1; // first row of block is all-zeros.
        let mut rpi_rlc_acc = Value::known(F::zero());
        let dummy_tx_hash = get_dummy_tx_hash(public_data.chain_id.as_u64());

        self.q_start.enable(region, offset)?;

        for (i, block) in block_values
            .ctxs
            .iter()
            .map(|(_, block)| block.clone())
            .chain(
                (block_values.ctxs.len()..self.max_inner_blocks)
                    .into_iter()
                    .map(|_| BlockContext::default()),
            )
            .enumerate()
        {
            let is_rpi_padding = i >= block_values.ctxs.len();
            block_copy_offsets.push(block_table_offset);
            let num_txs = public_data
                .transactions
                .iter()
                .filter(|tx| tx.block_number == block.number.as_u64())
                .count() as u64;
            // Assign fields in block table
            // coinbase
            let mut cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.coinbase.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            debug_assert_eq!(cells.len(), 2);
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());

            // timestamp
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.timestamp.as_u64().to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());

            // number
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.number.as_u64().to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());

            // difficulty
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.difficulty.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());

            // gas_limit
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.gas_limit.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());

            // base_fee
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.base_fee.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());

            // chain_id
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &block.chain_id.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());

            // num_txs
            cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &num_txs.to_be_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                true,
                is_rpi_padding,
                challenges,
                false,
            )?;
            block_copy_cells.push(cells[RPI_CELL_IDX].clone());

            block_table_offset += 9 + block.history_hashes.len();
        }
        debug_assert_eq!(offset, BLOCK_HEADER_BYTES_NUM * self.max_inner_blocks);

        // assign tx hashes
        let num_txs = tx_hashes.len();
        let mut rpi_rlc_cell = None;
        for tx_hash in tx_hashes.into_iter().chain(
            (0..self.max_txs - num_txs)
                .into_iter()
                .map(|_| dummy_tx_hash),
        ) {
            let cells = self.assign_field_in_pi(
                region,
                &mut offset,
                &tx_hash.to_fixed_bytes(),
                &mut rpi_rlc_acc,
                &mut rpi_length_acc,
                false,
                false,
                challenges,
                false,
            )?;
            tx_copy_cells.push(cells[RPI_CELL_IDX].clone());
            rpi_rlc_cell = Some(cells[RPI_RLC_ACC_CELL_IDX].clone());
        }

        debug_assert_eq!(
            offset,
            BLOCK_HEADER_BYTES_NUM * self.max_inner_blocks + KECCAK_DIGEST_SIZE * self.max_txs
        );

        for i in 0..(offset - 1) {
            self.q_not_end.enable(region, i)?;
        }

        for (block_cells, offset) in block_copy_cells
            .chunks(8)
            .into_iter()
            .zip(block_copy_offsets.into_iter())
        {
            for (i, block_cell) in block_cells.iter().enumerate() {
                let row_offset = offset + i;
                region.constrain_equal(
                    block_cell.cell(),
                    Cell {
                        region_index: RegionIndex(0), // FIXME: this is not safe
                        row_offset,
                        column: self.block_table.value.into(),
                    },
                )?;
            }
        }
        for (i, tx_hash_cell) in tx_copy_cells.into_iter().enumerate() {
            region.constrain_equal(
                tx_hash_cell.cell(),
                Cell {
                    region_index: RegionIndex(1), // FIXME: this is not safe
                    row_offset: i * 11 + 10,
                    column: self.tx_table.value.into(),
                },
            )?;
        }
        // assign rpi_acc, keccak_rpi
        let keccak_row = offset;
        let rpi_rlc_cell = rpi_rlc_cell.unwrap();
        rpi_rlc_cell.copy_advice(
            || "keccak(rpi)_input",
            region,
            self.raw_public_inputs,
            keccak_row,
        )?;
        let keccak = public_data.get_pi(self.max_txs);
        let keccak_rlc =
            keccak
                .to_fixed_bytes()
                .iter()
                .fold(Value::known(F::zero()), |acc, byte| {
                    acc.zip(challenges.evm_word())
                        .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)))
                });
        region.assign_advice(
            || "rpi_length_acc",
            self.rpi_length_acc,
            keccak_row,
            || Value::known(F::from(rpi_length_acc)),
        )?;
        let keccak_output_cell = region.assign_advice(
            || "keccak(rpi)_output",
            self.rpi_rlc_acc,
            keccak_row,
            || keccak_rlc,
        )?;
        self.q_keccak.enable(region, keccak_row)?;

        // start over to accumulate big-endian bytes of keccak output
        rpi_rlc_acc = Value::known(F::zero());
        offset += 1;
        // the high 16 bytes of keccak output
        let mut cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &keccak.to_fixed_bytes()[..16],
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            challenges,
            true,
        )?;
        let keccak_hi_cell = cells[RPI_CELL_IDX].clone();

        // the low 16 bytes of keccak output
        cells = self.assign_field_in_pi(
            region,
            &mut offset,
            &keccak.to_fixed_bytes()[16..],
            &mut rpi_rlc_acc,
            &mut rpi_length_acc,
            false,
            false,
            challenges,
            true,
        )?;
        let keccak_lo_cell = cells[RPI_CELL_IDX].clone();

        region.constrain_equal(
            keccak_output_cell.cell(),
            cells[RPI_RLC_ACC_CELL_IDX].cell(),
        )?;

        Ok((keccak_hi_cell, keccak_lo_cell))
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_field_in_pi(
        &self,
        region: &mut Region<'_, F>,
        offset: &mut usize,
        value_bytes: &[u8],
        rpi_rlc_acc: &mut Value<F>,
        rpi_length_acc: &mut u64,
        is_block: bool,
        is_padding: bool,
        challenges: &Challenges<Value<F>>,
        keccak_hi_lo: bool,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        let len = value_bytes.len();

        let mut value_bytes_acc = Value::known(F::zero());
        let (use_rlc, t) = if len * 8 > F::CAPACITY as usize {
            (F::one(), challenges.evm_word())
        } else {
            (F::zero(), Value::known(F::from(BYTE_POW_BASE)))
        };
        let r = if keccak_hi_lo {
            challenges.evm_word()
        } else {
            challenges.keccak_input()
        };
        let value = value_bytes
            .iter()
            .fold(Value::known(F::zero()), |acc, byte| {
                acc.zip(t)
                    .and_then(|(acc, t)| Value::known(acc * t + F::from(*byte as u64)))
            });

        let mut cells = vec![None, None];
        for (i, byte) in value_bytes.iter().enumerate() {
            let row_offset = *offset + i;

            let real_value = if is_padding {
                Value::known(F::zero())
            } else {
                value
            };
            *rpi_length_acc += if is_padding { 0 } else { 1 };
            // calculate acc
            value_bytes_acc = value_bytes_acc
                .zip(t)
                .and_then(|(acc, t)| Value::known(acc * t + F::from(*byte as u64)));

            if !is_padding {
                *rpi_rlc_acc = rpi_rlc_acc
                    .zip(r)
                    .and_then(|(acc, rand)| Value::known(acc * rand + F::from(*byte as u64)));
            }

            // set field-related selectors
            if i == 0 {
                self.q_field_start.enable(region, row_offset)?;
            }
            if i == len - 1 {
                self.q_field_end.enable(region, row_offset)?;
            } else {
                self.q_field_step.enable(region, row_offset)?;
            }

            region.assign_fixed(
                || "is_field_rlc",
                self.is_field_rlc,
                row_offset,
                || Value::known(use_rlc),
            )?;
            region.assign_advice(
                || "field byte",
                self.rpi_field_bytes,
                row_offset,
                || Value::known(F::from(*byte as u64)),
            )?;
            region.assign_advice(
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
            region.assign_advice(
                || "is_rpi_padding",
                self.is_rpi_padding,
                row_offset,
                || Value::known(F::from(is_padding as u64)),
            )?;
            let real_rpi_cell =
                region.assign_advice(|| "real_rpi", self.real_rpi, row_offset, || real_value)?;
            region.assign_advice(
                || "rpi_length_acc",
                self.rpi_length_acc,
                row_offset,
                || Value::known(F::from(*rpi_length_acc)),
            )?;

            if i == len - 1 {
                cells[RPI_CELL_IDX] = if is_block {
                    Some(real_rpi_cell)
                } else {
                    Some(rpi_cell)
                };
                cells[RPI_RLC_ACC_CELL_IDX] = Some(rpi_rlc_cell);
            }
        }
        *offset += len;

        Ok(cells.into_iter().map(|cell| cell.unwrap()).collect())
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
}

impl<F: Field> PiCircuit<F> {
    /// Creates a new PiCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        max_inner_blocks: usize,
        block: &Block<F>,
    ) -> Self {
        let context = block
            .context
            .ctxs
            .iter()
            .next()
            .map(|(_k, v)| v.clone())
            .unwrap_or_default();
        let public_data = PublicData {
            chain_id: context.chain_id,
            // history_hashes: context.history_hashes.clone(),
            transactions: block.txs.clone(),
            block_ctxs: block.context.clone(),
        };
        Self {
            public_data,
            max_txs,
            max_calldata,
            max_inner_blocks,
            _marker: PhantomData,
        }
    }

    /// Return txs
    pub fn txs(&self) -> &[Transaction] {
        &self.public_data.transactions
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

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let keccak_rpi = self.public_data.get_pi(self.max_txs);
        let keccak_hi = keccak_rpi
            .to_fixed_bytes()
            .iter()
            .take(16)
            .fold(F::zero(), |acc, byte| {
                acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
            });

        let keccak_lo = keccak_rpi
            .to_fixed_bytes()
            .iter()
            .skip(16)
            .fold(F::zero(), |acc, byte| {
                acc * F::from(BYTE_POW_BASE) + F::from(*byte as u64)
            });

        let public_inputs = vec![keccak_hi, keccak_lo];
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
                // assign
                let (keccak_hi_cell, keccak_lo_cell) =
                    config.assign(&mut region, &self.public_data, challenges)?;

                Ok(vec![keccak_hi_cell, keccak_lo_cell])
            },
        )?;
        // TODO: add copy constraints between block_table.index and
        //       block_table.value (tag = 'Number') for tags except
        //       history_hashes

        // Constrain raw_public_input cells to public inputs
        for (i, pi_cell) in pi_cells.iter().enumerate() {
            layouter.constrain_instance(pi_cell.cell(), config.pi, i)?;
        }

        Ok(())
    }
}

// We define the PiTestCircuit as a wrapper over PiCircuit extended to take the
// generic const parameters MAX_TXS and MAX_CALLDATA.  This is necessary because
// the trait Circuit requires an implementation of `configure` that doesn't take
// any circuit parameters, and the PiCircuit defines gates that use rotations
// that depend on MAX_TXS and MAX_CALLDATA, so these two values are required
// during the configuration.
/// Test Circuit for PiCircuit
#[cfg(any(feature = "test", test))]
#[derive(Default)]
pub struct PiTestCircuit<
    F: Field,
    const MAX_TXS: usize,
    const MAX_CALLDATA: usize,
    const MAX_INNER_BLOCKS: usize,
>(pub PiCircuit<F>);

#[cfg(any(feature = "test", test))]
impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize, const MAX_INNER_BLOCKS: usize>
    Circuit<F> for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>
{
    type Config = (PiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            PiCircuitConfig::new(
                meta,
                PiCircuitConfigArgs {
                    max_txs: MAX_TXS,
                    max_calldata: MAX_CALLDATA,
                    max_inner_blocks: MAX_INNER_BLOCKS,
                    block_table,
                    keccak_table,
                    tx_table,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);

        // assign block table
        config.block_table.load(
            &mut layouter,
            &self.0.public_data.block_ctxs,
            &self.0.public_data.transactions,
            self.0.max_inner_blocks,
            &challenges,
        )?;
        // assign tx table
        config.tx_table.load(
            &mut layouter,
            &self.0.public_data.transactions,
            self.0.max_txs,
            &challenges,
        )?;
        // assign keccak table
        let rpi_bytes = self.0.public_data.raw_public_input_bytes(self.0.max_txs);
        config
            .keccak_table
            .dev_load(&mut layouter, vec![&rpi_bytes], &challenges)?;

        self.0.synthesize_sub(&config, &challenges, &mut layouter)?;

        Ok(())
    }
}

#[cfg(test)]
mod pi_circuit_test {
    use super::*;

    use crate::witness::block_convert;
    use bus_mapping::mock::BlockData;
    use eth_types::bytecode;
    use eth_types::geth_types::GethData;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use mock::TestContext;
    use pretty_assertions::assert_eq;

    fn run<
        F: Field,
        const MAX_TXS: usize,
        const MAX_CALLDATA: usize,
        const MAX_INNER_BLOCKS: usize,
    >(
        k: u32,
        block: Block<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(PiCircuit::new(
            MAX_TXS,
            MAX_CALLDATA,
            MAX_INNER_BLOCKS,
            &block,
        ));
        let public_inputs = circuit.0.instance();

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    // #[test]
    // fn test_default_pi() {
    //     const MAX_TXS: usize = 2;
    //     const MAX_CALLDATA: usize = 8;
    //     let public_data = PublicData::default();
    //
    //     let k = 16;
    //     assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    // }

    #[test]
    fn test_simple_pi() {
        const MAX_TXS: usize = 4;
        const MAX_CALLDATA: usize = 20;
        const MAX_INNER_BLOCKS: usize = 64;

        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode! {
            STOP
        })
        .unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db).unwrap();

        let k = 16;
        assert_eq!(
            run::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(k, block),
            Ok(())
        );
    }
}
