//! Public Input Circuit implementation

use std::marker::PhantomData;

use eth_types::geth_types::BlockConstants;
use eth_types::sign_types::SignData;
use eth_types::H256;
use eth_types::{
    geth_types::Transaction, Address, Field, ToBigEndian, ToLittleEndian, ToScalar, Word,
};
use ethers_core::abi::ethereum_types::BigEndianHash;
use halo2_proofs::plonk::Instance;

use crate::table::BlockTable;
use crate::table::TxFieldTag;
use crate::table::TxTable;
use crate::util::{random_linear_combine_word as rlc, Challenges, SubCircuit, SubCircuitConfig};
use crate::witness;
use gadgets::is_zero::IsZeroChip;
use gadgets::util::{not, or, Expr};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};

/// Fixed by the spec
const TX_LEN: usize = 10;
const BLOCK_LEN: usize = 7 + 256;
const EXTRA_LEN: usize = 2;
const ZERO_BYTE_GAS_COST: u64 = 4;
const NONZERO_BYTE_GAS_COST: u64 = 16;

/// Values of the block table (as in the spec)
#[derive(Clone, Default, Debug)]
pub struct BlockValues {
    coinbase: Address,
    gas_limit: u64,
    number: u64,
    timestamp: u64,
    difficulty: Word,
    base_fee: Word, // NOTE: BaseFee was added by EIP-1559 and is ignored in legacy headers.
    chain_id: u64,
    history_hashes: Vec<H256>,
}

/// Values of the tx table (as in the spec)
#[derive(Default, Debug, Clone)]
pub struct TxValues {
    nonce: Word,
    gas: Word, //gas limit
    gas_price: Word,
    from_addr: Address,
    to_addr: Address,
    is_create: u64,
    value: Word,
    call_data_len: u64,
    call_data_gas_cost: u64,
    tx_sign_hash: [u8; 32],
}

/// Extra values (not contained in block or tx tables)
#[derive(Default, Debug, Clone)]
pub struct ExtraValues {
    // block_hash: H256,
    state_root: H256,
    prev_state_root: H256,
}

/// PublicData contains all the values that the PiCircuit recieves as input
#[derive(Debug, Clone, Default)]
pub struct PublicData {
    /// chain id
    pub chain_id: Word,
    /// History hashes contains the most recent 256 block hashes in history,
    /// where the latest one is at history_hashes[history_hashes.len() - 1].
    pub history_hashes: Vec<Word>,
    /// Block Transactions
    pub transactions: Vec<eth_types::Transaction>,
    /// Block State Root
    pub state_root: H256,
    /// Previous block root
    pub prev_state_root: H256,
    /// Constants related to Ethereum block
    pub block_constants: BlockConstants,
}

impl PublicData {
    /// Returns struct with values for the block table
    pub fn get_block_table_values(&self) -> BlockValues {
        let history_hashes = [
            vec![H256::zero(); 256 - self.history_hashes.len()],
            self.history_hashes
                .iter()
                .map(|&hash| H256::from(hash.to_be_bytes()))
                .collect(),
        ]
        .concat();
        BlockValues {
            coinbase: self.block_constants.coinbase,
            gas_limit: self.block_constants.gas_limit.as_u64(),
            number: self.block_constants.number.as_u64(),
            timestamp: self.block_constants.timestamp.as_u64(),
            difficulty: self.block_constants.difficulty,
            base_fee: self.block_constants.base_fee,
            chain_id: self.chain_id.as_u64(),
            history_hashes,
        }
    }

    /// Returns struct with values for the tx table
    pub fn get_tx_table_values(&self) -> Vec<TxValues> {
        let chain_id: u64 = self
            .chain_id
            .try_into()
            .expect("Error converting chain_id to u64");
        let mut tx_vals = vec![];
        for tx in &self.txs() {
            let sign_data: SignData = tx
                .sign_data(chain_id)
                .expect("Error computing tx_sign_hash");
            let mut msg_hash_le = [0u8; 32];
            msg_hash_le.copy_from_slice(sign_data.msg_hash.to_bytes().as_slice());
            tx_vals.push(TxValues {
                nonce: tx.nonce,
                gas_price: tx.gas_price,
                gas: tx.gas_limit,
                from_addr: tx.from,
                to_addr: tx.to.unwrap_or_else(Address::zero),
                is_create: (tx.to.is_none() as u64),
                value: tx.value,
                call_data_len: tx.call_data.0.len() as u64,
                call_data_gas_cost: tx.call_data.0.iter().fold(0, |acc, byte| {
                    acc + if *byte == 0 {
                        ZERO_BYTE_GAS_COST
                    } else {
                        NONZERO_BYTE_GAS_COST
                    }
                }),
                tx_sign_hash: msg_hash_le,
            });
        }
        tx_vals
    }

    /// Returns struct with the extra values
    pub fn get_extra_values(&self) -> ExtraValues {
        ExtraValues {
            // block_hash: self.hash.unwrap_or_else(H256::zero),
            state_root: self.state_root,
            prev_state_root: self.prev_state_root,
        }
    }

    fn txs(&self) -> Vec<Transaction> {
        self.transactions.iter().map(Transaction::from).collect()
    }
}

/// Config for PiCircuit
#[derive(Clone, Debug)]
pub struct PiCircuitConfig<F: Field> {
    /// Max number of supported transactions
    max_txs: usize,
    /// Max number of supported calldata bytes
    max_calldata: usize,

    q_block_table: Selector,
    q_tx_table: Selector,
    q_tx_calldata: Selector,
    q_calldata_start: Selector,

    tx_id_inv: Column<Advice>,
    tx_value_inv: Column<Advice>,
    tx_id_diff_inv: Column<Advice>,
    fixed_u16: Column<Fixed>,
    calldata_gas_cost: Column<Advice>,
    is_final: Column<Advice>,

    raw_public_inputs: Column<Advice>,
    rpi_rlc_acc: Column<Advice>,
    rand_rpi: Column<Advice>,
    q_not_end: Selector,
    q_end: Selector,

    pi: Column<Instance>, // rpi_rand, rpi_rlc, chain_ID, state_root, prev_state_root

    _marker: PhantomData<F>,
    // External tables
    block_table: BlockTable,
    tx_table: TxTable,
}

/// Circuit configuration arguments
pub struct PiCircuitConfigArgs {
    /// Max number of supported transactions
    pub max_txs: usize,
    /// Max number of supported calldata bytes
    pub max_calldata: usize,
    /// TxTable
    pub tx_table: TxTable,
    /// BlockTable
    pub block_table: BlockTable,
}

impl<F: Field> SubCircuitConfig<F> for PiCircuitConfig<F> {
    type ConfigArgs = PiCircuitConfigArgs;

    /// Return a new PiCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            max_txs,
            max_calldata,
            block_table,
            tx_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_block_table = meta.selector();

        let q_tx_table = meta.complex_selector();
        let q_tx_calldata = meta.complex_selector();
        let q_calldata_start = meta.complex_selector();
        // Tx Table
        let tx_id = tx_table.tx_id;
        let tx_value = tx_table.value;
        let tag = tx_table.tag;
        let index = tx_table.index;
        let tx_id_inv = meta.advice_column();
        let tx_value_inv = meta.advice_column();
        let tx_id_diff_inv = meta.advice_column();
        // The difference of tx_id of adjacent rows in calldata part of tx table
        // lies in the interval [0, 2^16] if their tx_id both do not equal to zero.
        // We do not use 2^8 for the reason that a large block may have more than
        // 2^8 transfer transactions which have 21000*2^8 (~ 5.376M) gas.
        let fixed_u16 = meta.fixed_column();
        let calldata_gas_cost = meta.advice_column();
        let is_final = meta.advice_column();

        let raw_public_inputs = meta.advice_column();
        let rpi_rlc_acc = meta.advice_column();
        let rand_rpi = meta.advice_column();
        let q_not_end = meta.selector();
        let q_end = meta.selector();

        let pi = meta.instance_column();

        meta.enable_equality(raw_public_inputs);
        meta.enable_equality(rpi_rlc_acc);
        meta.enable_equality(rand_rpi);
        meta.enable_equality(pi);

        // 0.0 rpi_rlc_acc[0] == RLC(raw_public_inputs, rand_rpi)
        meta.create_gate(
            "rpi_rlc_acc[i] = rand_rpi * rpi_rlc_acc[i+1] + raw_public_inputs[i]",
            |meta| {
                // q_not_end * row.rpi_rlc_acc ==
                // (q_not_end * row_next.rpi_rlc_acc * row.rand_rpi + row.raw_public_inputs )
                let q_not_end = meta.query_selector(q_not_end);
                let cur_rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
                let next_rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::next());
                let rand_rpi = meta.query_advice(rand_rpi, Rotation::cur());
                let raw_public_inputs = meta.query_advice(raw_public_inputs, Rotation::cur());

                vec![
                    q_not_end * (next_rpi_rlc_acc * rand_rpi + raw_public_inputs - cur_rpi_rlc_acc),
                ]
            },
        );
        meta.create_gate("rpi_rlc_acc[last] = raw_public_inputs[last]", |meta| {
            let q_end = meta.query_selector(q_end);
            let raw_public_inputs = meta.query_advice(raw_public_inputs, Rotation::cur());
            let rpi_rlc_acc = meta.query_advice(rpi_rlc_acc, Rotation::cur());
            vec![q_end * (raw_public_inputs - rpi_rlc_acc)]
        });

        // 0.1 rand_rpi[i] == rand_rpi[j]
        meta.create_gate("rand_pi = rand_rpi.next", |meta| {
            // q_not_end * row.rand_rpi == q_not_end * row_next.rand_rpi
            let q_not_end = meta.query_selector(q_not_end);
            let cur_rand_rpi = meta.query_advice(rand_rpi, Rotation::cur());
            let next_rand_rpi = meta.query_advice(rand_rpi, Rotation::next());

            vec![q_not_end * (cur_rand_rpi - next_rand_rpi)]
        });

        // 0.2 Block table -> value column match with raw_public_inputs at expected
        // offset
        meta.create_gate("block_table[i] = raw_public_inputs[offset + i]", |meta| {
            let q_block_table = meta.query_selector(q_block_table);
            let block_value = meta.query_advice(block_table.value, Rotation::cur());
            let rpi_block_value = meta.query_advice(raw_public_inputs, Rotation::cur());
            vec![q_block_table * (block_value - rpi_block_value)]
        });

        let offset = BLOCK_LEN + 1 + EXTRA_LEN;
        let tx_table_len = max_txs * TX_LEN + 1;

        //  0.3 Tx table -> {tx_id, index, value} column match with raw_public_inputs
        // at expected offset
        meta.create_gate(
            "tx_table.tx_id[i] == raw_public_inputs[offset + i]",
            |meta| {
                // row.q_tx_table * row.tx_table.tx_id
                // == row.q_tx_table * row_offset_tx_table_tx_id.raw_public_inputs
                let q_tx_table = meta.query_selector(q_tx_table);
                let tx_id = meta.query_advice(tx_table.tx_id, Rotation::cur());
                let rpi_tx_id = meta.query_advice(raw_public_inputs, Rotation(offset as i32));

                vec![q_tx_table * (tx_id - rpi_tx_id)]
            },
        );

        meta.create_gate(
            "tx_table.index[i] == raw_public_inputs[offset + tx_table_len + i]",
            |meta| {
                // row.q_tx_table * row.tx_table.tx_index
                // == row.q_tx_table * row_offset_tx_table_tx_index.raw_public_inputs
                let q_tx_table = meta.query_selector(q_tx_table);
                let tx_index = meta.query_advice(tx_table.index, Rotation::cur());
                let rpi_tx_index =
                    meta.query_advice(raw_public_inputs, Rotation((offset + tx_table_len) as i32));

                vec![q_tx_table * (tx_index - rpi_tx_index)]
            },
        );

        meta.create_gate(
            "tx_table.tx_value[i] == raw_public_inputs[offset + 2* tx_table_len + i]",
            |meta| {
                // (row.q_tx_calldata | row.q_tx_table) * row.tx_table.tx_value
                // == (row.q_tx_calldata | row.q_tx_table) *
                // row_offset_tx_table_tx_value.raw_public_inputs
                let q_tx_table = meta.query_selector(q_tx_table);
                let tx_value = meta.query_advice(tx_value, Rotation::cur());
                let q_tx_calldata = meta.query_selector(q_tx_calldata);
                let rpi_tx_value = meta.query_advice(
                    raw_public_inputs,
                    Rotation((offset + 2 * tx_table_len) as i32),
                );

                vec![or::expr([q_tx_table, q_tx_calldata]) * (tx_value - rpi_tx_value)]
            },
        );

        let tx_id_is_zero_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_tx_calldata),
            |meta| meta.query_advice(tx_table.tx_id, Rotation::cur()),
            tx_id_inv,
        );
        let tx_value_is_zero_config = IsZeroChip::configure(
            meta,
            |meta| {
                or::expr([
                    meta.query_selector(q_tx_table),
                    meta.query_selector(q_tx_calldata),
                ])
            },
            |meta| meta.query_advice(tx_value, Rotation::cur()),
            tx_value_inv,
        );
        let _tx_id_diff_is_zero_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_tx_calldata),
            |meta| {
                meta.query_advice(tx_table.tx_id, Rotation::next())
                    - meta.query_advice(tx_table.tx_id, Rotation::cur())
            },
            tx_id_diff_inv,
        );

        meta.lookup_any("tx_id_diff", |meta| {
            let tx_id_next = meta.query_advice(tx_id, Rotation::next());
            let tx_id = meta.query_advice(tx_id, Rotation::cur());
            let tx_id_inv_next = meta.query_advice(tx_id_inv, Rotation::next());
            let tx_id_diff_inv = meta.query_advice(tx_id_diff_inv, Rotation::cur());
            let fixed_u16_table = meta.query_fixed(fixed_u16, Rotation::cur());

            let tx_id_next_nonzero = tx_id_next.expr() * tx_id_inv_next;
            let tx_id_not_equal_to_next = (tx_id_next.expr() - tx_id.expr()) * tx_id_diff_inv;
            let tx_id_diff_minus_one = tx_id_next - tx_id - 1.expr();

            vec![(
                tx_id_diff_minus_one * tx_id_next_nonzero * tx_id_not_equal_to_next,
                fixed_u16_table,
            )]
        });

        meta.create_gate("calldata constraints", |meta| {
            let q_is_calldata = meta.query_selector(q_tx_calldata);
            let q_calldata_start = meta.query_selector(q_calldata_start);
            let tx_idx = meta.query_advice(tx_id, Rotation::cur());
            let tx_idx_next = meta.query_advice(tx_id, Rotation::next());
            let tx_idx_inv_next = meta.query_advice(tx_id_inv, Rotation::next());
            let tx_idx_diff_inv = meta.query_advice(tx_id_diff_inv, Rotation::cur());
            let idx = meta.query_advice(index, Rotation::cur());
            let idx_next = meta.query_advice(index, Rotation::next());
            let value_next = meta.query_advice(tx_value, Rotation::next());
            let value_next_inv = meta.query_advice(tx_value_inv, Rotation::next());

            let gas_cost = meta.query_advice(calldata_gas_cost, Rotation::cur());
            let gas_cost_next = meta.query_advice(calldata_gas_cost, Rotation::next());
            let is_final = meta.query_advice(is_final, Rotation::cur());

            let is_tx_id_nonzero = not::expr(tx_id_is_zero_config.expr());
            let is_tx_id_next_nonzero = tx_idx_next.expr() * tx_idx_inv_next.expr();

            let is_value_zero = tx_value_is_zero_config.expr();
            let is_value_nonzero = not::expr(tx_value_is_zero_config.expr());

            let is_value_next_nonzero = value_next.expr() * value_next_inv.expr();
            let is_value_next_zero = not::expr(is_value_next_nonzero.expr());

            // gas = value == 0 ? 4 : 16
            let gas = ZERO_BYTE_GAS_COST.expr() * is_value_zero.expr()
                + NONZERO_BYTE_GAS_COST.expr() * is_value_nonzero.expr();
            let gas_next = ZERO_BYTE_GAS_COST.expr() * is_value_next_zero
                + NONZERO_BYTE_GAS_COST.expr() * is_value_next_nonzero;

            // if tx_id == 0 then idx == 0, tx_id_next == 0
            let default_calldata_row_constraint1 = tx_id_is_zero_config.expr() * idx.expr();
            let default_calldata_row_constraint2 = tx_id_is_zero_config.expr() * tx_idx_next.expr();
            let default_calldata_row_constraint3 = tx_id_is_zero_config.expr() * is_final.expr();
            let default_calldata_row_constraint4 = tx_id_is_zero_config.expr() * gas_cost.expr();

            // if tx_id != 0 then
            //    1. tx_id_next == tx_id: idx_next == idx + 1, gas_cost_next == gas_cost +
            //       gas_next, is_final == false;
            //    2. tx_id_next == tx_id + 1 + x (where x is in [0, 2^16)): idx_next == 0,
            //       gas_cost_next == gas_next, is_final == true;
            //    3. tx_id_next == 0: is_final == true, idx_next == 0, gas_cost_next == 0;
            // either case 1, case 2 or case 3 holds.

            let tx_id_equal_to_next =
                1.expr() - (tx_idx_next.expr() - tx_idx.expr()) * tx_idx_diff_inv.expr();
            let idx_of_same_tx_constraint =
                tx_id_equal_to_next.clone() * (idx_next.expr() - idx.expr() - 1.expr());
            let idx_of_next_tx_constraint = (tx_idx_next.expr() - tx_idx.expr()) * idx_next.expr();

            let gas_cost_of_same_tx_constraint = tx_id_equal_to_next.clone()
                * (gas_cost_next.expr() - gas_cost.expr() - gas_next.expr());
            let gas_cost_of_next_tx_constraint = is_tx_id_next_nonzero.expr()
                * (tx_idx_next.expr() - tx_idx.expr())
                * (gas_cost_next.expr() - gas_next.expr());

            let is_final_of_same_tx_constraint = tx_id_equal_to_next * is_final.expr();
            let is_final_of_next_tx_constraint =
                (tx_idx_next.expr() - tx_idx.expr()) * (is_final.expr() - 1.expr());

            // if tx_id != 0 then
            //    1. q_calldata_start * (index - 0) == 0 and
            //    2. q_calldata_start * (gas_cost - gas) == 0.

            vec![
                q_is_calldata.expr() * default_calldata_row_constraint1,
                q_is_calldata.expr() * default_calldata_row_constraint2,
                q_is_calldata.expr() * default_calldata_row_constraint3,
                q_is_calldata.expr() * default_calldata_row_constraint4,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * idx_of_same_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * idx_of_next_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * gas_cost_of_same_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * gas_cost_of_next_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * is_final_of_same_tx_constraint,
                q_is_calldata.expr() * is_tx_id_nonzero.expr() * is_final_of_next_tx_constraint,
                q_calldata_start.expr() * is_tx_id_nonzero.expr() * (idx - 0.expr()),
                q_calldata_start.expr() * is_tx_id_nonzero.expr() * (gas_cost - gas),
            ]
        });

        // Test if tx tag equals to CallDataLength
        let tx_tag_is_cdl_config = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_tx_table),
            |meta| meta.query_advice(tag, Rotation::cur()) - TxFieldTag::CallDataLength.expr(),
            tx_id_inv,
        );

        meta.create_gate(
            "call_data_gas_cost should be zero if call_data_length is zero",
            |meta| {
                let q_tx_table = meta.query_selector(q_tx_table);

                let is_calldata_length_zero = tx_value_is_zero_config.expr();
                let is_calldata_length_row = tx_tag_is_cdl_config.expr();
                let calldata_cost = meta.query_advice(tx_value, Rotation::next());

                vec![q_tx_table * is_calldata_length_row * is_calldata_length_zero * calldata_cost]
            },
        );

        meta.lookup_any("gas_cost in tx table", |meta| {
            let q_tx_table = meta.query_selector(q_tx_table);
            let is_final = meta.query_advice(is_final, Rotation::cur());

            let tx_id = meta.query_advice(tx_id, Rotation::cur());

            // calldata gas cost assigned in the tx table
            // CallDataGasCost is on the next row of CallDataLength
            let calldata_cost_assigned = meta.query_advice(tx_value, Rotation::next());
            // calldata gas cost calculated in call data
            let calldata_cost_calc = meta.query_advice(calldata_gas_cost, Rotation::cur());

            let is_calldata_length_row = tx_tag_is_cdl_config.expr();
            let is_calldata_length_nonzero = not::expr(tx_value_is_zero_config.expr());

            // lookup (tx_id, true, is_calldata_length_nonzero * is_calldata_cost *
            // gas_cost) in the table (tx_id, is_final, gas_cost)
            // if q_tx_table is true
            let condition = q_tx_table * is_calldata_length_nonzero * is_calldata_length_row;

            vec![
                (condition.expr() * tx_id.expr(), tx_id),
                (condition.expr() * 1.expr(), is_final),
                (
                    condition.expr() * calldata_cost_assigned,
                    calldata_cost_calc,
                ),
            ]
        });

        Self {
            max_txs,
            max_calldata,
            q_block_table,
            block_table,
            q_tx_table,
            q_tx_calldata,
            q_calldata_start,
            tx_table,
            tx_id_inv,
            tx_value_inv,
            tx_id_diff_inv,
            fixed_u16,
            calldata_gas_cost,
            is_final,
            raw_public_inputs,
            rpi_rlc_acc,
            rand_rpi,
            q_not_end,
            q_end,
            pi,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> PiCircuitConfig<F> {
    /// Return the number of rows in the circuit
    #[inline]
    fn circuit_len(&self) -> usize {
        // +1 empty row in block table, +1 empty row in tx_table
        BLOCK_LEN + 1 + EXTRA_LEN + 3 * (TX_LEN * self.max_txs + 1) + self.max_calldata
    }

    fn assign_tx_empty_row(&self, region: &mut Region<'_, F>, offset: usize) -> Result<(), Error> {
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "tx_id_inv",
            self.tx_id_inv,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "tag",
            self.tx_table.tag,
            offset,
            || Value::known(F::from(TxFieldTag::Null as u64)),
        )?;
        region.assign_advice(
            || "index",
            self.tx_table.index,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "tx_value",
            self.tx_table.value,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "tx_value_inv",
            self.tx_value_inv,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "is_final",
            self.is_final,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "gas_cost",
            self.calldata_gas_cost,
            offset,
            || Value::known(F::zero()),
        )?;
        Ok(())
    }
    /// Assigns a tx_table row and stores the values in a vec for the
    /// raw_public_inputs column
    #[allow(clippy::too_many_arguments)]
    fn assign_tx_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tag: TxFieldTag,
        index: usize,
        tx_value: F,
        raw_pi_vals: &mut [F],
    ) -> Result<(), Error> {
        let tx_id = F::from(tx_id as u64);
        // tx_id_inv = (tag - CallDataLength)^(-1)
        let tx_id_inv = if tag != TxFieldTag::CallDataLength {
            let x = F::from(tag as u64) - F::from(TxFieldTag::CallDataLength as u64);
            x.invert().unwrap_or(F::zero())
        } else {
            F::zero()
        };
        let tag = F::from(tag as u64);
        let index = F::from(index as u64);
        let tx_value = tx_value;
        let tx_value_inv = tx_value.invert().unwrap_or(F::zero());

        self.q_tx_table.enable(region, offset)?;

        // Assign vals to Tx_table
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            offset,
            || Value::known(tx_id),
        )?;
        region.assign_advice(|| "tag", self.tx_table.tag, offset, || Value::known(tag))?;
        region.assign_advice(
            || "index",
            self.tx_table.index,
            offset,
            || Value::known(index),
        )?;
        region.assign_advice(
            || "tx_value",
            self.tx_table.value,
            offset,
            || Value::known(tx_value),
        )?;
        region.assign_advice(
            || "tx_id_inv",
            self.tx_id_inv,
            offset,
            || Value::known(tx_id_inv),
        )?;
        region.assign_advice(
            || "tx_value_inverse",
            self.tx_value_inv,
            offset,
            || Value::known(tx_value_inv),
        )?;

        // Assign vals to raw_public_inputs column
        let tx_table_len = TX_LEN * self.max_txs + 1;

        let id_offset = BLOCK_LEN + 1 + EXTRA_LEN;
        let index_offset = id_offset + tx_table_len;
        let value_offset = index_offset + tx_table_len;

        region.assign_advice(
            || "raw_pi.tx_id",
            self.raw_public_inputs,
            offset + id_offset,
            || Value::known(tx_id),
        )?;

        region.assign_advice(
            || "raw_pi.tx_index",
            self.raw_public_inputs,
            offset + index_offset,
            || Value::known(index),
        )?;

        region.assign_advice(
            || "raw_pi.tx_value",
            self.raw_public_inputs,
            offset + value_offset,
            || Value::known(tx_value),
        )?;

        // Add copy to vec
        raw_pi_vals[offset + id_offset] = tx_id;
        raw_pi_vals[offset + index_offset] = index;
        raw_pi_vals[offset + value_offset] = tx_value;

        Ok(())
    }

    /// Assigns one calldata row
    #[allow(clippy::too_many_arguments)]
    fn assign_tx_calldata_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        tx_id: usize,
        tx_id_next: usize,
        index: usize,
        tx_value: F,
        is_final: bool,
        gas_cost: F,
        raw_pi_vals: &mut [F],
    ) -> Result<(), Error> {
        let tx_id = F::from(tx_id as u64);
        let tx_id_inv = tx_id.invert().unwrap_or(F::zero());
        let tx_id_diff = F::from(tx_id_next as u64) - tx_id;
        let tx_id_diff_inv = tx_id_diff.invert().unwrap_or(F::zero());
        let tag = F::from(TxFieldTag::CallData as u64);
        let index = F::from(index as u64);
        let tx_value = tx_value;
        let tx_value_inv = tx_value.invert().unwrap_or(F::zero());
        let is_final = if is_final { F::one() } else { F::zero() };

        // Assign vals to raw_public_inputs column
        let tx_table_len = TX_LEN * self.max_txs + 1;
        let calldata_offset = tx_table_len + offset;

        self.q_tx_calldata.enable(region, calldata_offset)?;

        // Assign vals to Tx_table
        region.assign_advice(
            || "tx_id",
            self.tx_table.tx_id,
            calldata_offset,
            || Value::known(tx_id),
        )?;
        region.assign_advice(
            || "tx_id_inv",
            self.tx_id_inv,
            calldata_offset,
            || Value::known(tx_id_inv),
        )?;
        region.assign_advice(
            || "tag",
            self.tx_table.tag,
            calldata_offset,
            || Value::known(tag),
        )?;
        region.assign_advice(
            || "index",
            self.tx_table.index,
            calldata_offset,
            || Value::known(index),
        )?;
        region.assign_advice(
            || "tx_value",
            self.tx_table.value,
            calldata_offset,
            || Value::known(tx_value),
        )?;
        region.assign_advice(
            || "tx_value_inv",
            self.tx_value_inv,
            calldata_offset,
            || Value::known(tx_value_inv),
        )?;
        region.assign_advice(
            || "tx_id_diff_inv",
            self.tx_id_diff_inv,
            calldata_offset,
            || Value::known(tx_id_diff_inv),
        )?;
        region.assign_advice(
            || "is_final",
            self.is_final,
            calldata_offset,
            || Value::known(is_final),
        )?;
        region.assign_advice(
            || "gas_cost",
            self.calldata_gas_cost,
            calldata_offset,
            || Value::known(gas_cost),
        )?;

        let value_offset = BLOCK_LEN + 1 + EXTRA_LEN + 3 * tx_table_len;

        region.assign_advice(
            || "raw_pi.tx_value",
            self.raw_public_inputs,
            offset + value_offset,
            || Value::known(tx_value),
        )?;

        // Add copy to vec
        raw_pi_vals[offset + value_offset] = tx_value;

        Ok(())
    }

    /// Assigns the values for block table in the block_table column
    /// and in the raw_public_inputs column. A copy is also stored in
    /// a vector for computing RLC(raw_public_inputs)
    fn assign_block_table(
        &self,
        region: &mut Region<'_, F>,
        block_values: BlockValues,
        randomness: F,
        raw_pi_vals: &mut [F],
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut offset = 0;
        for i in 0..BLOCK_LEN + 1 {
            self.q_block_table.enable(region, offset + i)?;
        }

        // zero row
        region.assign_advice(
            || "zero",
            self.block_table.value,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || "zero",
            self.raw_public_inputs,
            offset,
            || Value::known(F::zero()),
        )?;
        raw_pi_vals[offset] = F::zero();
        offset += 1;

        // coinbase
        let coinbase = block_values.coinbase.to_scalar().unwrap();
        region.assign_advice(
            || "coinbase",
            self.block_table.value,
            offset,
            || Value::known(coinbase),
        )?;
        region.assign_advice(
            || "coinbase",
            self.raw_public_inputs,
            offset,
            || Value::known(coinbase),
        )?;
        raw_pi_vals[offset] = coinbase;
        offset += 1;

        // gas_limit
        let gas_limit = F::from(block_values.gas_limit);
        region.assign_advice(
            || "gas_limit",
            self.block_table.value,
            offset,
            || Value::known(gas_limit),
        )?;
        region.assign_advice(
            || "gas_limit",
            self.raw_public_inputs,
            offset,
            || Value::known(gas_limit),
        )?;
        raw_pi_vals[offset] = gas_limit;
        offset += 1;

        // number
        let number = F::from(block_values.number);
        region.assign_advice(
            || "number",
            self.block_table.value,
            offset,
            || Value::known(number),
        )?;
        region.assign_advice(
            || "number",
            self.raw_public_inputs,
            offset,
            || Value::known(number),
        )?;
        raw_pi_vals[offset] = number;
        offset += 1;

        // timestamp
        let timestamp = F::from(block_values.timestamp);
        region.assign_advice(
            || "timestamp",
            self.block_table.value,
            offset,
            || Value::known(timestamp),
        )?;
        region.assign_advice(
            || "timestamp",
            self.raw_public_inputs,
            offset,
            || Value::known(timestamp),
        )?;
        raw_pi_vals[offset] = timestamp;
        offset += 1;

        // difficulty
        let difficulty = rlc(block_values.difficulty.to_le_bytes(), randomness);
        region.assign_advice(
            || "difficulty",
            self.block_table.value,
            offset,
            || Value::known(difficulty),
        )?;
        region.assign_advice(
            || "difficulty",
            self.raw_public_inputs,
            offset,
            || Value::known(difficulty),
        )?;
        raw_pi_vals[offset] = difficulty;
        offset += 1;

        // base_fee
        let base_fee = rlc(block_values.base_fee.to_le_bytes(), randomness);
        region.assign_advice(
            || "base_fee",
            self.block_table.value,
            offset,
            || Value::known(base_fee),
        )?;
        region.assign_advice(
            || "base_fee",
            self.raw_public_inputs,
            offset,
            || Value::known(base_fee),
        )?;
        raw_pi_vals[offset] = base_fee;
        offset += 1;

        // chain_id
        let chain_id = F::from(block_values.chain_id);
        region.assign_advice(
            || "chain_id",
            self.block_table.value,
            offset,
            || Value::known(chain_id),
        )?;
        let chain_id_cell = region.assign_advice(
            || "chain_id",
            self.raw_public_inputs,
            offset,
            || Value::known(chain_id),
        )?;
        raw_pi_vals[offset] = chain_id;
        offset += 1;

        for prev_hash in block_values.history_hashes {
            let prev_hash = rlc(prev_hash.to_fixed_bytes(), randomness);
            region.assign_advice(
                || "prev_hash",
                self.block_table.value,
                offset,
                || Value::known(prev_hash),
            )?;
            region.assign_advice(
                || "prev_hash",
                self.raw_public_inputs,
                offset,
                || Value::known(prev_hash),
            )?;
            raw_pi_vals[offset] = prev_hash;
            offset += 1;
        }

        Ok(chain_id_cell)
    }

    /// Assigns the extra fields (not in block or tx tables):
    ///   - state root
    ///   - previous block state root
    /// to the raw_public_inputs column and stores a copy in a
    /// vector for computing RLC(raw_public_inputs).
    fn assign_extra_fields(
        &self,
        region: &mut Region<'_, F>,
        extra: ExtraValues,
        randomness: F,
        raw_pi_vals: &mut [F],
    ) -> Result<[AssignedCell<F, F>; 2], Error> {
        let mut offset = BLOCK_LEN + 1;
        // block hash
        // let block_hash = rlc(extra.block_hash.to_fixed_bytes(), randomness);
        // region.assign_advice(
        //     || "block.hash",
        //     self.raw_public_inputs,
        //     offset,
        //     || Ok(block_hash),
        // )?;
        // raw_pi_vals[offset] = block_hash;
        // offset += 1;

        // block state root
        let state_root = rlc(extra.state_root.to_fixed_bytes(), randomness);
        let state_root_cell = region.assign_advice(
            || "state.root",
            self.raw_public_inputs,
            offset,
            || Value::known(state_root),
        )?;
        raw_pi_vals[offset] = state_root;
        offset += 1;

        // previous block state root
        let prev_state_root = rlc(extra.prev_state_root.to_fixed_bytes(), randomness);
        let prev_state_root_cell = region.assign_advice(
            || "parent_block.hash",
            self.raw_public_inputs,
            offset,
            || Value::known(prev_state_root),
        )?;
        raw_pi_vals[offset] = prev_state_root;
        Ok([state_root_cell, prev_state_root_cell])
    }

    /// Assign `rpi_rlc_acc` and `rand_rpi` columns
    #[allow(clippy::type_complexity)]
    fn assign_rlc_pi(
        &self,
        region: &mut Region<'_, F>,
        rand_rpi: F,
        raw_pi_vals: Vec<F>,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let circuit_len = self.circuit_len();
        assert_eq!(circuit_len, raw_pi_vals.len());

        // Last row
        let offset = circuit_len - 1;
        let mut rpi_rlc_acc = raw_pi_vals[offset];
        region.assign_advice(
            || "rpi_rlc_acc",
            self.rpi_rlc_acc,
            offset,
            || Value::known(rpi_rlc_acc),
        )?;
        region.assign_advice(
            || "rand_rpi",
            self.rand_rpi,
            offset,
            || Value::known(rand_rpi),
        )?;
        self.q_end.enable(region, offset)?;

        // Next rows
        for offset in (1..circuit_len - 1).rev() {
            rpi_rlc_acc *= rand_rpi;
            rpi_rlc_acc += raw_pi_vals[offset];
            region.assign_advice(
                || "rpi_rlc_acc",
                self.rpi_rlc_acc,
                offset,
                || Value::known(rpi_rlc_acc),
            )?;
            region.assign_advice(
                || "rand_rpi",
                self.rand_rpi,
                offset,
                || Value::known(rand_rpi),
            )?;
            self.q_not_end.enable(region, offset)?;
        }

        // First row
        rpi_rlc_acc *= rand_rpi;
        rpi_rlc_acc += raw_pi_vals[0];
        let rpi_rlc = region.assign_advice(
            || "rpi_rlc_acc",
            self.rpi_rlc_acc,
            0,
            || Value::known(rpi_rlc_acc),
        )?;
        let rpi_rand =
            region.assign_advice(|| "rand_rpi", self.rand_rpi, 0, || Value::known(rand_rpi))?;
        self.q_not_end.enable(region, 0)?;
        Ok((rpi_rand, rpi_rlc))
    }
}

/// Public Inputs Circuit
#[derive(Clone, Default, Debug)]
pub struct PiCircuit<F: Field> {
    max_txs: usize,
    max_calldata: usize,
    /// Randomness for RLC encdoing
    pub randomness: F,
    /// Randomness for PI encoding
    pub rand_rpi: F,
    /// PublicInputs data known by the verifier
    pub public_data: PublicData,
}

impl<F: Field> PiCircuit<F> {
    /// Creates a new PiCircuit
    pub fn new(
        max_txs: usize,
        max_calldata: usize,
        randomness: impl Into<F>,
        rand_rpi: impl Into<F>,
        public_data: PublicData,
    ) -> Self {
        Self {
            max_txs,
            max_calldata,
            randomness: randomness.into(),
            rand_rpi: rand_rpi.into(),
            public_data,
        }
    }
}

impl<F: Field> SubCircuit<F> for PiCircuit<F> {
    type Config = PiCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        let context = block
            .context
            .ctxs
            .iter()
            .next()
            .map(|(_k, v)| v.clone())
            .unwrap_or_default();
        let public_data = PublicData {
            chain_id: context.chain_id,
            history_hashes: context.history_hashes.clone(),
            transactions: context.eth_block.transactions.clone(),
            state_root: context.eth_block.state_root,
            prev_state_root: H256::from_uint(&block.prev_state_root),
            block_constants: BlockConstants {
                coinbase: context.coinbase,
                timestamp: context.timestamp,
                number: context.number.as_u64().into(),
                difficulty: context.difficulty,
                gas_limit: context.gas_limit.into(),
                base_fee: context.base_fee,
            },
        };
        PiCircuit::new(
            block.circuits_params.max_txs,
            block.circuits_params.max_calldata,
            block.randomness,
            block.randomness + F::from_u128(1),
            public_data,
        )
    }

    /// Compute the public inputs for this circuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let rlc_rpi_col = raw_public_inputs_col::<F>(
            self.max_txs,
            self.max_calldata,
            &self.public_data,
            self.randomness,
        );
        assert_eq!(
            rlc_rpi_col.len(),
            BLOCK_LEN + 1 + EXTRA_LEN + 3 * (TX_LEN * self.max_txs + 1) + self.max_calldata
        );

        // Computation of raw_pulic_inputs
        let rlc_rpi = rlc_rpi_col
            .iter()
            .rev()
            .fold(F::zero(), |acc, val| acc * self.rand_rpi + val);

        // let block_hash = public_data
        //     .eth_block
        //     .hash
        //     .unwrap_or_else(H256::zero)
        //     .to_fixed_bytes();
        let public_inputs = vec![
            self.rand_rpi,
            rlc_rpi,
            F::from(self.public_data.chain_id.as_u64()),
            rlc(
                self.public_data.state_root.to_fixed_bytes(),
                self.randomness,
            ),
            rlc(
                self.public_data.prev_state_root.to_fixed_bytes(),
                self.randomness,
            ),
        ];

        vec![public_inputs]
    }

    /// Make the assignments to the PiCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed u16 table",
            |mut region| {
                for i in 0..(1 << 16) {
                    region.assign_fixed(
                        || format!("row_{}", i),
                        config.fixed_u16,
                        i,
                        || Value::known(F::from(i as u64)),
                    )?;
                }

                Ok(())
            },
        )?;
        let pi_cells = layouter.assign_region(
            || "region 0",
            |mut region| {
                let circuit_len = config.circuit_len();
                let mut raw_pi_vals = vec![F::zero(); circuit_len];

                // Assign block table
                let block_values = self.public_data.get_block_table_values();
                let chain_id = config.assign_block_table(
                    &mut region,
                    block_values,
                    self.randomness,
                    &mut raw_pi_vals,
                )?;

                // Assign extra fields
                let extra_vals = self.public_data.get_extra_values();
                let [state_root, prev_state_root] = config.assign_extra_fields(
                    &mut region,
                    extra_vals,
                    self.randomness,
                    &mut raw_pi_vals,
                )?;

                let mut offset = 0;
                // Assign Tx table
                let txs = self.public_data.get_tx_table_values();
                assert!(txs.len() <= config.max_txs);
                let tx_default = TxValues::default();

                // Add empty row
                config.assign_tx_row(
                    &mut region,
                    offset,
                    0,
                    TxFieldTag::Null,
                    0,
                    F::zero(),
                    &mut raw_pi_vals,
                )?;
                offset += 1;

                for i in 0..config.max_txs {
                    let tx = if i < txs.len() { &txs[i] } else { &tx_default };

                    for (tag, value) in &[
                        (
                            TxFieldTag::Nonce,
                            rlc(tx.nonce.to_le_bytes(), self.randomness),
                        ),
                        (TxFieldTag::Gas, rlc(tx.gas.to_le_bytes(), self.randomness)),
                        (
                            TxFieldTag::GasPrice,
                            rlc(tx.gas_price.to_le_bytes(), self.randomness),
                        ),
                        (
                            TxFieldTag::CallerAddress,
                            tx.from_addr.to_scalar().expect("tx.from too big"),
                        ),
                        (
                            TxFieldTag::CalleeAddress,
                            tx.to_addr.to_scalar().expect("tx.to too big"),
                        ),
                        (TxFieldTag::IsCreate, F::from(tx.is_create)),
                        (
                            TxFieldTag::Value,
                            rlc(tx.value.to_le_bytes(), self.randomness),
                        ),
                        (TxFieldTag::CallDataLength, F::from(tx.call_data_len)),
                        (TxFieldTag::CallDataGasCost, F::from(tx.call_data_gas_cost)),
                        (
                            TxFieldTag::TxSignHash,
                            rlc(tx.tx_sign_hash, self.randomness),
                        ),
                    ] {
                        config.assign_tx_row(
                            &mut region,
                            offset,
                            i + 1,
                            *tag,
                            0,
                            *value,
                            &mut raw_pi_vals,
                        )?;
                        offset += 1;
                    }
                }
                // Tx Table CallData
                let mut calldata_count = 0;
                config.q_calldata_start.enable(&mut region, offset)?;
                // the call data bytes assignment starts at offset 0
                offset = 0;
                let txs = self.public_data.txs();
                for (i, tx) in self.public_data.txs().iter().enumerate() {
                    let call_data_length = tx.call_data.0.len();
                    let mut gas_cost = F::zero();
                    for (index, byte) in tx.call_data.0.iter().enumerate() {
                        assert!(calldata_count < config.max_calldata);
                        let is_final = index == call_data_length - 1;
                        gas_cost += if *byte == 0 {
                            F::from(ZERO_BYTE_GAS_COST)
                        } else {
                            F::from(NONZERO_BYTE_GAS_COST)
                        };
                        let tx_id_next = if is_final {
                            let mut j = i + 1;
                            while j < txs.len() && txs[j].call_data.0.is_empty() {
                                j += 1;
                            }
                            if j >= txs.len() {
                                0
                            } else {
                                j + 1
                            }
                        } else {
                            i + 1
                        };

                        config.assign_tx_calldata_row(
                            &mut region,
                            offset,
                            i + 1,
                            tx_id_next as usize,
                            index,
                            F::from(*byte as u64),
                            is_final,
                            gas_cost,
                            &mut raw_pi_vals,
                        )?;
                        offset += 1;
                        calldata_count += 1;
                    }
                }
                for _ in calldata_count..config.max_calldata {
                    config.assign_tx_calldata_row(
                        &mut region,
                        offset,
                        0, // tx_id
                        0,
                        0,
                        F::zero(),
                        false,
                        F::zero(),
                        &mut raw_pi_vals,
                    )?;
                    offset += 1;
                }
                // NOTE: we add this empty row so as to pass mock prover's check
                //      otherwise it will emit CellNotAssigned Error
                let tx_table_len = TX_LEN * self.max_txs + 1;
                config.assign_tx_empty_row(&mut region, tx_table_len + offset)?;

                // rpi_rlc and rand_rpi cols
                let (rpi_rand, rpi_rlc) =
                    config.assign_rlc_pi(&mut region, self.rand_rpi, raw_pi_vals)?;

                Ok(vec![
                    rpi_rand,
                    rpi_rlc,
                    chain_id,
                    state_root,
                    prev_state_root,
                ])
            },
        )?;

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
pub struct PiTestCircuit<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    pub PiCircuit<F>,
);

#[cfg(any(feature = "test", test))]
impl<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize> Circuit<F>
    for PiTestCircuit<F, MAX_TXS, MAX_CALLDATA>
{
    type Config = (PiCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        (
            PiCircuitConfig::new(
                meta,
                PiCircuitConfigArgs {
                    max_txs: MAX_TXS,
                    max_calldata: MAX_CALLDATA,
                    block_table,
                    tx_table,
                },
            ),
            Challenges::construct(meta),
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        self.0.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

/// Compute the raw_public_inputs column from the verifier's perspective.
fn raw_public_inputs_col<F: Field>(
    max_txs: usize,
    max_calldata: usize,
    public_data: &PublicData,
    randomness: F, // For RLC encoding
) -> Vec<F> {
    let block = public_data.get_block_table_values();
    let extra = public_data.get_extra_values();
    let txs = public_data.get_tx_table_values();

    let mut offset = 0;
    let mut result =
        vec![F::zero(); BLOCK_LEN + 1 + EXTRA_LEN + 3 * (TX_LEN * max_txs + 1) + max_calldata];

    //  Insert Block Values
    // zero row
    result[offset] = F::zero();
    offset += 1;
    // coinbase
    result[offset] = block.coinbase.to_scalar().unwrap();
    offset += 1;
    // gas_limit
    result[offset] = F::from(block.gas_limit);
    offset += 1;
    // number
    result[offset] = F::from(block.number);
    offset += 1;
    // timestamp
    result[offset] = F::from(block.timestamp);
    offset += 1;
    // difficulty
    result[offset] = rlc(block.difficulty.to_le_bytes(), randomness);
    offset += 1;
    // base_fee
    result[offset] = rlc(block.base_fee.to_le_bytes(), randomness);
    offset += 1;
    // chain_id
    result[offset] = F::from(block.chain_id);
    offset += 1;
    // Previous block hashes
    for prev_hash in block.history_hashes {
        result[offset] = rlc(prev_hash.to_fixed_bytes(), randomness);
        offset += 1;
    }

    // Insert Extra Values
    // block Root
    result[BLOCK_LEN + 1] = rlc(extra.state_root.to_fixed_bytes(), randomness);
    // parent block hash
    result[BLOCK_LEN + 2] = rlc(extra.prev_state_root.to_fixed_bytes(), randomness);

    // Insert Tx table
    offset = 0;
    assert!(txs.len() <= max_txs);
    let tx_default = TxValues::default();

    let tx_table_len = TX_LEN * max_txs + 1;

    let id_offset = BLOCK_LEN + 1 + EXTRA_LEN;
    let index_offset = id_offset + tx_table_len;
    let value_offset = index_offset + tx_table_len;

    // Insert zero row
    result[id_offset + offset] = F::zero();
    result[index_offset + offset] = F::zero();
    result[value_offset + offset] = F::zero();

    offset += 1;

    for i in 0..max_txs {
        let tx = if i < txs.len() { &txs[i] } else { &tx_default };

        for val in &[
            rlc(tx.nonce.to_le_bytes(), randomness),
            rlc(tx.gas.to_le_bytes(), randomness),
            rlc(tx.gas_price.to_le_bytes(), randomness),
            tx.from_addr.to_scalar().expect("tx.from too big"),
            tx.to_addr.to_scalar().expect("tx.to too big"),
            F::from(tx.is_create),
            rlc(tx.value.to_le_bytes(), randomness),
            F::from(tx.call_data_len),
            F::from(tx.call_data_gas_cost),
            rlc(tx.tx_sign_hash, randomness),
        ] {
            result[id_offset + offset] = F::from((i + 1) as u64);
            result[index_offset + offset] = F::zero();
            result[value_offset + offset] = *val;

            offset += 1;
        }
    }
    // Tx Table CallData
    let mut calldata_count = 0;
    for (_i, tx) in public_data.txs().iter().enumerate() {
        for (_index, byte) in tx.call_data.0.iter().enumerate() {
            assert!(calldata_count < max_calldata);
            result[value_offset + offset] = F::from(*byte as u64);
            offset += 1;
            calldata_count += 1;
        }
    }
    for _ in calldata_count..max_calldata {
        result[value_offset + offset] = F::zero();
        offset += 1;
    }

    result
}

#[cfg(test)]
mod pi_circuit_test {
    use super::*;

    use crate::test_util::rand_tx;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure},
        halo2curves::bn256::Fr,
    };
    use pretty_assertions::assert_eq;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
        k: u32,
        public_data: PublicData,
    ) -> Result<(), Vec<VerifyFailure>> {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let randomness = F::random(&mut rng);
        let rand_rpi = F::random(&mut rng);

        let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
            MAX_TXS,
            MAX_CALLDATA,
            randomness,
            rand_rpi,
            public_data,
        ));
        let public_inputs = circuit.0.instance();

        let prover = match MockProver::run(k, &circuit, public_inputs) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        prover.verify()
    }

    #[test]
    fn test_default_pi() {
        const MAX_TXS: usize = 2;
        const MAX_CALLDATA: usize = 8;
        let public_data = PublicData::default();

        let k = 17;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    }

    #[test]
    fn test_simple_pi() {
        const MAX_TXS: usize = 8;
        const MAX_CALLDATA: usize = 200;

        let mut rng = ChaCha20Rng::seed_from_u64(2);

        let mut public_data = PublicData::default();
        let chain_id = 1337u64;
        public_data.chain_id = Word::from(chain_id);

        let n_tx = 4;
        for i in 0..n_tx {
            let eth_tx = eth_types::Transaction::from(&rand_tx(&mut rng, chain_id, i & 2 == 0));
            public_data.transactions.push(eth_tx);
        }

        let k = 17;
        assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
    }
}
