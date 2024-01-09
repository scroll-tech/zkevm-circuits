//! The Copy circuit implements constraints and lookups for read-write steps for
//! copied bytes while execution opcodes such as CALLDATACOPY, CODECOPY, LOGS,
//! etc.
mod copy_gadgets;
pub(crate) mod util;

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
#[cfg(any(feature = "test", test))]
mod test;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use dev::CopyCircuit as TestCopyCircuit;

use crate::{evm_circuit::param::N_BYTES_MEMORY_ADDRESS, util::word};
use bus_mapping::circuit_input_builder::{CopyDataType, CopyEvent};
use eth_types::{Field, Word};
use gadgets::{
    binary_number::BinaryNumberChip,
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    less_than::LtInstruction,
    util::{not, select, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use std::{array, collections::BTreeMap, marker::PhantomData};

use gadgets::less_than::{LtChip, LtConfig};
#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;
use halo2_proofs::plonk::TableColumn;

use crate::{
    evm_circuit::util::{constraint_builder::BaseConstraintBuilder, math_gadget::LtGadget},
    table::{
        BytecodeFieldTag, BytecodeTable, CopyTable, LookupTable, RwTable, RwTableTag,
        TxContextFieldTag, TxTable, U8Table,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
    witness::{Bytecode, RwMap, Transaction},
};

use self::copy_gadgets::{
    constrain_address, constrain_event_rlc_acc, constrain_first_last, constrain_forward_parameters,
    constrain_id, constrain_is_pad, constrain_must_terminate, constrain_non_pad_non_mask,
    constrain_rw_counter, constrain_tag, constrain_value_rlc,
};

/// The current row.
const CURRENT: Rotation = Rotation(0);
/// The next row. Constraints with NEXT_ROW connect reader-to-writer or writer-to-reader.
const NEXT_ROW: Rotation = Rotation(1);
/// The next step, processing the next byte. This connects reader-to-reader or writer-to-writer.
const NEXT_STEP: Rotation = Rotation(2);

// Rows to enable but not use, that can be queried safely by the last event.
const UNUSED_ROWS: usize = 2;
// Rows to disable, so they do not query into Halo2 reserved rows.
const DISABLED_ROWS: usize = 2;

/// The rw table shared between evm circuit and state circuit
#[derive(Clone, Debug)]
pub struct CopyCircuitConfig<F> {
    /// Whether this row denotes a step.
    /// A read row is a step and a write row is not.
    pub q_step: Selector,
    /// Whether the row is the last read-write pair for a copy event.
    pub is_last: Column<Advice>,
    /// The half-word limbs copied in this copy step.
    pub value_limbs: [Column<Advice>; 16],
    /// The word value for memory lookup.
    pub value_word: Column<Advice>,
    /// The word value for memory lookup, before the write.
    pub value_word_prev: Column<Advice>,
    /// Random linear combination accumulator of the non-masked copied data.
    pub value_acc: Column<Advice>,
    /// Whether the cell is part of the front mask, before the copy data.
    /// is_front_mask == true when address < addr_copy_start,
    /// LtGadget compares address < addr_copy_start
    pub is_front_mask: [LtConfig<F, N_BYTES_MEMORY_ADDRESS>; 16],
    /// Whether the cell is not part of the back mask, after the copy data.
    /// is_back_mask == !is_front_mask == true when address >= addr_copy_end,
    /// LtGadget compares address < addr_copy_end
    pub is_not_back_mask: [LtConfig<F, N_BYTES_MEMORY_ADDRESS>; 16],
    /// Whether the cell is in bound reads when source address < src_addr_end.
    /// LtGadget compares address < src_addr_end
    pub is_inbound_read: [LtConfig<F, N_BYTES_MEMORY_ADDRESS>; 16],
    /// non pad and non mask witness to reduce the degree of lookups.
    pub non_pad_non_mask: [Column<Advice>; 16],
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_tx_calldata: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_bytecode: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_memory: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_tx_log: Column<Advice>,
    /// Booleans to indicate if `CopyDataType::AccessListAddresses` exists at
    /// the current row.
    pub is_access_list_address: Column<Advice>,
    /// Booleans to indicate if `CopyDataType::AccessListStorageKeys` exists at
    /// the current row.
    pub is_access_list_storage_key: Column<Advice>,
    /// Whether the row is enabled or not.
    pub q_enable: Column<Fixed>,
    /// The Copy Table contains the columns that are exposed via the lookup
    /// expressions
    pub copy_table: CopyTable,
    // External tables
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// u8 lookup Table
    pub u8_table: U8Table,
}

/// Circuit configuration arguments
pub struct CopyCircuitConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// CopyTable
    pub copy_table: CopyTable,
    /// q_enable
    pub q_enable: Column<Fixed>,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
    /// u8 lookup Table
    pub u8_table: U8Table,
}

impl<F: Field> SubCircuitConfig<F> for CopyCircuitConfig<F> {
    type ConfigArgs = CopyCircuitConfigArgs<F>;

    /// Configure the Copy Circuit constraining read-write steps and doing
    /// appropriate lookups to the Tx Table, RW Table and Bytecode Table.
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            tx_table,
            rw_table,
            bytecode_table,
            copy_table,
            q_enable,
            challenges,
            u8_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let q_step = meta.complex_selector();
        let is_last = meta.advice_column();
        let value_limbs = array::from_fn(|_| meta.advice_column());

        // RLC accumulators in the second phase.
        // let code_hash = word::Word::new([meta.advice_column(), meta.advice_column()]);

        let value_word = meta.advice_column();
        let value_word_prev = meta.advice_column();
        let value_acc = meta.advice_column_in(SecondPhase);

        let [is_pad, is_tx_calldata, is_bytecode, is_memory, is_tx_log, is_access_list_address, is_access_list_storage_key] =
            array::from_fn(|_| meta.advice_column());
        let is_first = copy_table.is_first;
        let id = copy_table.id;
        let addr = copy_table.addr;
        let src_addr_end = copy_table.src_addr_end;
        let addr_copy_start = copy_table.addr_copy_start;
        let addr_copy_end = copy_table.addr_copy_end;
        let real_bytes_left = copy_table.real_bytes_left;

        let mut lt_init = |lhs_base: Column<Advice>, rhs: Column<Advice>| {
            array::from_fn(|idx| {
                LtChip::configure(
                    meta,
                    |meta| meta.query_selector(q_step),
                    |meta| meta.query_advice(lhs_base, CURRENT) + idx.expr(),
                    |meta| meta.query_advice(rhs, CURRENT),
                    u8_table.into(),
                )
            })
        };
        let is_front_mask = lt_init(addr, addr_copy_start);
        let is_not_back_mask = lt_init(addr, addr_copy_end);
        let is_inbound_read = lt_init(addr, src_addr_end);

        let rlc_acc = copy_table.rlc_acc;
        let rw_counter = copy_table.rw_counter;
        let rwc_inc_left = copy_table.rwc_inc_left;
        let tag = copy_table.tag;

        // annotate table columns
        tx_table.annotate_columns(meta);
        rw_table.annotate_columns(meta);
        bytecode_table.annotate_columns(meta);
        copy_table.annotate_columns(meta);

        let non_pad_non_mask = array::from_fn(|_| meta.advice_column());

        constrain_tag(
            meta,
            q_enable,
            &tag,
            is_tx_calldata,
            is_bytecode,
            is_memory,
            is_tx_log,
            is_access_list_address,
            is_access_list_storage_key,
        );

        meta.create_gate("verify copy events", |meta| {
            let cb = &mut BaseConstraintBuilder::default();

            let is_reader = meta.query_selector(q_step);
            // Detect the first row of an event. When true, both reader and writer are initialized.
            let is_first = meta.query_advice(is_first, CURRENT);
            // Detect the last step of an event. This works on both reader and writer rows.
            // This is a boolean since is_last cannot be true on both rows because of constraint
            // "is_last == 0 when q_step == 1" and the alternating values of q_step.
            let is_last_step =
                meta.query_advice(is_last, CURRENT) + meta.query_advice(is_last, NEXT_ROW);
            // Whether this row is part of an event but not the last step. When true, the next step
            // is derived from the current step.
            let is_continue = not::expr(is_last_step.expr());
            // Detect the last row of an event, which is always a writer row.
            let is_last_col = is_last;
            let is_last = meta.query_advice(is_last, CURRENT);
            let is_front_mask_exprs = is_front_mask.clone().map(|chip| chip.is_lt(meta, None));
            let is_not_back_mask_exprs =
                is_not_back_mask.clone().map(|chip| chip.is_lt(meta, None));
            let is_not_back_mask_exprs = is_inbound_read.clone().map(|chip| chip.is_lt(meta, None));
            let is_inbound_read_exprs = is_inbound_read.clone().map(|chip| chip.is_lt(meta, None));

            constrain_id(
                cb,
                meta,
                //is_bytecode,
                is_tx_log,
                is_tx_calldata,
                is_memory,
                id,
                is_pad,
            );

            let is_tx_log = meta.query_advice(is_tx_log, CURRENT);
            let is_access_list = meta.query_advice(is_access_list_address, CURRENT)
                + meta.query_advice(is_access_list_storage_key, CURRENT);

            constrain_first_last(cb, is_reader.expr(), is_first.expr(), is_last.expr());

            constrain_must_terminate(cb, meta, q_enable, &tag);

            constrain_forward_parameters(cb, meta, is_continue.expr(), id, tag, src_addr_end);

            // let (is_pad, is_pad_next) = constrain_is_pad(
            //     cb,
            //     meta,
            //     is_reader.expr(),
            //     is_first.expr(),
            //     is_last_col,
            //     is_pad,
            //     addr,
            //     src_addr_end,
            //     &is_src_end,
            // );

            // let (mask, mask_next, front_mask) = {
            //     // The first 31 bytes may be front_mask, but not the last byte of the first word.
            //     // LOG, access-list address and storage-key have no front mask at all.
            //     let forbid_front_mask =
            //         is_word_end.expr() + is_tx_log.expr() + is_access_list.expr();
            //
            //     constrain_mask(
            //         cb,
            //         meta,
            //         is_first.expr(),
            //         is_continue.expr(),
            //         mask,
            //         front_mask,
            //         forbid_front_mask,
            //     )
            // };

            constrain_non_pad_non_mask(
                cb,
                meta,
                non_pad_non_mask,
                is_front_mask_exprs.clone(),
                is_not_back_mask_exprs.clone(),
                is_inbound_read_exprs.clone(),
            );

            //constrain_masked_value(cb, meta, mask.expr(), value, value_prev);

            constrain_value_rlc(
                cb,
                meta,
                is_first.expr(),
                is_continue.expr(),
                is_last_col,
                non_pad_non_mask,
                is_inbound_read.clone(),
                value_acc,
                value_limbs,
                challenges.keccak_input(),
            );

            constrain_event_rlc_acc(cb, meta, is_last_col, value_acc, rlc_acc, is_bytecode, tag);

            // no word_rlc required after word hi lo
            // Apply the same constraints for the RLCs of words before and after the write.
            // let word_rlc_both = [(value_word, value), (value_word_prev, value_prev)];
            // for (word_rlc, value) in word_rlc_both {
            //     constrain_word_rlc(
            //         cb,
            //         meta,
            //         is_first.expr(),
            //         is_continue.expr(),
            //         is_word_end.expr(),
            //         word_rlc,
            //         value,
            //         challenges.evm_word(),
            //     );
            // }

            constrain_address(cb, meta, is_continue.expr(), addr);

            {
                let is_rw_word_type = meta.query_advice(is_memory, CURRENT) + is_tx_log.expr();
                let is_rw_type = is_rw_word_type.expr() + is_access_list.expr();

                constrain_rw_counter(
                    cb,
                    meta,
                    is_last.expr(),
                    is_rw_type.expr(),
                    rw_counter,
                    rwc_inc_left,
                );
            }

            cb.gate(meta.query_fixed(q_enable, CURRENT))
        });

        // TODO: feat/copy-hi-lo
        // // memory word lookup
        // meta.lookup_any("Memory word lookup", |meta| {
        //     let cond = meta.query_fixed(q_enable, CURRENT)
        //         * meta.query_advice(is_memory, CURRENT)
        //         * is_word_end.is_equal_expression.expr();
        //
        //     let addr_slot = meta.query_advice(addr, CURRENT) - 31.expr();
        //
        //     vec![
        //         1.expr(),
        //         meta.query_advice(rw_counter, CURRENT),
        //         not::expr(meta.query_selector(q_step)),
        //         RwTableTag::Memory.expr(),
        //         meta.query_advice(id.lo(), Rotation::cur()), // call_id
        //         addr_slot,
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         meta.query_advice(value_word.lo(), CURRENT),
        //         meta.query_advice(value_word.hi(), CURRENT),
        //         meta.query_advice(value_word_prev.lo(), CURRENT),
        //         meta.query_advice(value_word_prev.hi(), CURRENT),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //     ]
        //     .into_iter()
        //     .zip(rw_table.table_exprs(meta))
        //     .map(|(arg, table)| (cond.clone() * arg, table))
        //     .collect()
        // });

        // TODO: feat/copy-hi-lo
        // meta.lookup_any("TxLog word lookup", |meta| {
        //     let cond = meta.query_fixed(q_enable, CURRENT)
        //         * meta.query_advice(is_tx_log, CURRENT)
        //         * is_word_end.is_equal_expression.expr();
        //
        //     let addr_slot = meta.query_advice(addr, CURRENT) - 31.expr();
        //
        //     vec![
        //         1.expr(),
        //         meta.query_advice(rw_counter, CURRENT),
        //         1.expr(),
        //         RwTableTag::TxLog.expr(),
        //         //meta.query_advice(id, CURRENT), // tx_id
        //         meta.query_advice(id.lo(), CURRENT), // tx_id
        //         addr_slot,                           // byte_index || field_tag || log_id
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         meta.query_advice(value_word.lo(), CURRENT),
        //         meta.query_advice(value_word.hi(), CURRENT),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //     ]
        //     .into_iter()
        //     .zip(rw_table.table_exprs(meta))
        //     .map(|(arg, table)| (cond.clone() * arg, table))
        //     .collect()
        // });

        // TODO: feat/copy-hi-lo
        // meta.lookup_any("Bytecode lookup", |meta| {
        //     let cond = meta.query_fixed(q_enable, CURRENT)
        //         * meta.query_advice(is_bytecode, CURRENT)
        //         * meta.query_advice(non_pad_non_mask, CURRENT);
        //
        //     vec![
        //         1.expr(),
        //         meta.query_advice(id.lo(), CURRENT),
        //         meta.query_advice(id.hi(), CURRENT),
        //         BytecodeFieldTag::Byte.expr(),
        //         meta.query_advice(addr, CURRENT),
        //         meta.query_advice(value, CURRENT),
        //     ]
        //     .into_iter()
        //     .zip_eq(bytecode_table.table_exprs_mini(meta))
        //     .map(|(arg, table)| (cond.clone() * arg, table))
        //     .collect()
        // });
        //
        // meta.lookup_any("Tx calldata lookup", |meta| {
        //     let cond = meta.query_fixed(q_enable, CURRENT)
        //         * meta.query_advice(is_tx_calldata, CURRENT)
        //         * meta.query_advice(non_pad_non_mask, CURRENT);
        //
        //     vec![
        //         1.expr(),
        //         meta.query_advice(id.lo(), CURRENT),
        //         TxContextFieldTag::CallData.expr(),
        //         meta.query_advice(addr, CURRENT),
        //         meta.query_advice(value, CURRENT),
        //     ]
        //     .into_iter()
        //     .zip(tx_table.table_exprs(meta))
        //     .map(|(arg, table)| (cond.clone() * arg, table))
        //     .collect()
        // });

        /* TODO: enable tx lookup for access list after merging EIP-1559 PR with tx-table update.

                meta.lookup_any("Tx access list address lookup", |meta| {
                    let cond = meta.query_fixed(q_enable, CURRENT)
                        * meta.query_advice(is_access_list_address, CURRENT);

                    let tx_id = meta.query_advice(id, CURRENT);
                    let index = meta.query_advice(addr, CURRENT);
                    let address = meta.query_advice(value, CURRENT);

                    vec![
                        1.expr(),
                        tx_id,
                        TxContextFieldTag::AccessListAddress.expr(),
                        index,
                        address.expr(),
                        address,
                    ]
                    .into_iter()
                    .zip(tx_table.table_exprs(meta))
                    .map(|(arg, table)| (cond.clone() * arg, table))
                    .collect()
                });
        */

        // TODO: feat/copy-hi-lo
        // meta.lookup_any("Rw access list address lookup", |meta| {
        //     let cond = meta.query_fixed(q_enable, CURRENT)
        //         * meta.query_advice(is_access_list_address, CURRENT);
        //
        //     let tx_id = meta.query_advice(id.lo(), CURRENT);
        //     let address = meta.query_advice(value, CURRENT);
        //
        //     vec![
        //         1.expr(),
        //         meta.query_advice(rw_counter, CURRENT),
        //         1.expr(),
        //         RwTableTag::TxAccessListAccount.expr(),
        //         tx_id,
        //         address, // access list address
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         1.expr(), // is_warm_lo
        //         0.expr(), // is_warm_hi
        //         0.expr(), // is_warm_prev_lo
        //         0.expr(), // is_warm_prev_hi
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //     ]
        //     .into_iter()
        //     .zip(rw_table.table_exprs(meta))
        //     .map(|(arg, table)| (cond.clone() * arg, table))
        //     .collect()
        // });

        /* TODO: enable tx lookup for access list after merging EIP-1559 PR with tx-table update.

                meta.lookup_any("Tx access list storage key lookup", |meta| {
                    let cond = meta.query_fixed(q_enable, CURRENT)
                        * meta.query_advice(is_access_list_storage_key, CURRENT);

                    let tx_id = meta.query_advice(id, CURRENT);
                    let index = meta.query_advice(addr, CURRENT);
                    let address = meta.query_advice(value, CURRENT);
                    let storage_key = meta.query_advice(value_prev, CURRENT);

                    vec![
                        1.expr(),
                        tx_id,
                        TxContextFieldTag::AccessListStorageKey.expr(),
                        index,
                        storage_key,
                        address,
                    ]
                    .into_iter()
                    .zip(tx_table.table_exprs(meta))
                    .map(|(arg, table)| (cond.clone() * arg, table))
                    .collect()
                });
        */

        // TODO: feat/copy-hi-lo
        // meta.lookup_any("Rw access list storage key lookup", |meta| {
        //     let cond = meta.query_fixed(q_enable, CURRENT)
        //         * meta.query_advice(is_access_list_storage_key, CURRENT);
        //
        //     let tx_id = meta.query_advice(id.lo(), CURRENT);
        //     let address = meta.query_advice(value, CURRENT);
        //     let storage_key_lo = meta.query_advice(value_word_prev.lo(), CURRENT);
        //     let storage_key_hi = meta.query_advice(value_word_prev.hi(), CURRENT);
        //
        //     vec![
        //         1.expr(),
        //         meta.query_advice(rw_counter, CURRENT),
        //         1.expr(),
        //         RwTableTag::TxAccessListAccountStorage.expr(),
        //         tx_id,
        //         address, // access list address
        //         0.expr(),
        //         storage_key_lo, // access list storage_key_lo
        //         storage_key_hi, // access list storage_key_hi
        //         1.expr(),       // is_warm_lo
        //         0.expr(),       // is_warm_hi
        //         0.expr(),       // is_warm_prev_lo
        //         0.expr(),       // is_warm_prev_hi
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //     ]
        //     .into_iter()
        //     .zip(rw_table.table_exprs(meta))
        //     .map(|(arg, table)| (cond.clone() * arg, table))
        //     .collect()
        // });

        Self {
            q_step,
            is_last,
            value_limbs,
            value_word,
            value_word_prev,
            value_acc,
            is_front_mask,
            is_not_back_mask,
            is_inbound_read,
            non_pad_non_mask,
            is_tx_calldata,
            is_bytecode,
            is_memory,
            is_tx_log,
            is_access_list_address,
            is_access_list_storage_key,
            q_enable,
            copy_table,
            tx_table,
            rw_table,
            bytecode_table,
            u8_table,
        }
    }
}

impl<F: Field> CopyCircuitConfig<F> {
    /// Assign an individual copy event to the Copy Circuit.
    #[allow(clippy::too_many_arguments)]
    pub fn assign_copy_event(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        is_front_mask_chip: &[LtChip<F, N_BYTES_MEMORY_ADDRESS>; 16],
        is_not_back_mask_chip: &[LtChip<F, N_BYTES_MEMORY_ADDRESS>; 16],
        is_inbound_read_chip: &[LtChip<F, N_BYTES_MEMORY_ADDRESS>; 16],
        tag_chip: &BinaryNumberChip<F, CopyDataType, { CopyDataType::N_BITS }>,
        challenges: Challenges<Value<F>>,
        copy_event: &CopyEvent,
    ) -> Result<(), Error> {
        for (step_idx, (tag, table_row, circuit_row)) in
            CopyTable::assignments(copy_event, challenges)
                .iter()
                .enumerate()
        {
            let is_read = step_idx % 2 == 0;

            // Copy table assignments
            table_row.assign(&self.copy_table, region, *offset)?;

            // q_step
            if is_read {
                self.q_step.enable(region, *offset)?;
            }
            // q_enable
            region.assign_fixed(
                || "q_enable",
                self.q_enable,
                *offset,
                || Value::known(F::one()),
            )?;

            // is_last, value_word, value_word_prev, value_acc
            circuit_row.assign(self, region, *offset)?;
            for (idx, ((is_front_mask, is_not_back_mask), is_inbound_read)) in is_front_mask_chip
                .iter()
                .zip(is_not_back_mask_chip)
                .zip(is_inbound_read_chip)
                .enumerate()
            {
                let address = table_row.addr + F::from(idx as u64);
                is_front_mask.assign(region, *offset, address, table_row.addr_copy_start)?;
                is_not_back_mask.assign(region, *offset, address, table_row.addr_copy_end)?;
                is_inbound_read.assign(region, *offset, address, table_row.src_addr_end)?;

                let is_front_mask = address < table_row.addr_copy_start;
                let is_not_back_mask = address < table_row.addr_copy_end;
                let is_masked = is_front_mask || !is_not_back_mask;
                let is_inbound_read = address < table_row.src_addr_end;
                let non_pad_non_mask = !is_masked && is_inbound_read;
                region.assign_advice(
                    || format!("non_pad_non_mask[{idx}] at row: {offset}"),
                    self.non_pad_non_mask[idx],
                    *offset,
                    || Value::known(F::from(non_pad_non_mask)),
                )?;
            }

            // tag
            tag_chip.assign(region, *offset, tag)?;

            region.assign_advice(
                || format!("is_tx_calldata at row: {}", *offset),
                self.is_tx_calldata,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::TxCalldata))),
            )?;
            region.assign_advice(
                || format!("is_bytecode at row: {}", *offset),
                self.is_bytecode,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::Bytecode))),
            )?;
            region.assign_advice(
                || format!("is_memory at row: {}", *offset),
                self.is_memory,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::Memory))),
            )?;
            region.assign_advice(
                || format!("is_tx_log at row: {}", *offset),
                self.is_tx_log,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::TxLog))),
            )?;
            region.assign_advice(
                || format!("is_access_list_address at row: {}", *offset),
                self.is_access_list_address,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::AccessListAddresses))),
            )?;
            region.assign_advice(
                || format!("is_access_list_storage_key at row: {}", *offset),
                self.is_access_list_storage_key,
                *offset,
                || Value::known(F::from(tag.eq(&CopyDataType::AccessListStorageKeys))),
            )?;

            *offset += 1;
        }

        Ok(())
    }

    /// Assign vec of copy events
    pub fn assign_copy_events(
        &self,
        layouter: &mut impl Layouter<F>,
        copy_events: &[CopyEvent],
        max_copy_rows: usize,
        challenges: Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let copy_rows_needed = copy_events
            .iter()
            .map(|c| c.full_length() as usize * 2)
            .sum::<usize>();
        let max_copy_rows = if max_copy_rows == 0 {
            // dynamic
            copy_rows_needed + DISABLED_ROWS + UNUSED_ROWS
        } else {
            assert!(
                copy_rows_needed + DISABLED_ROWS + UNUSED_ROWS <= max_copy_rows,
                "copy rows not enough {copy_rows_needed} vs {max_copy_rows}"
            );
            max_copy_rows
        };
        let filler_rows = max_copy_rows - copy_rows_needed - DISABLED_ROWS;

        let is_front_mask_chip = self.is_front_mask.map(LtChip::construct);
        let is_not_back_mask_chip = self.is_not_back_mask.map(LtChip::construct);
        let is_inbound_read_chip = self.is_inbound_read.map(LtChip::construct);
        let tag_chip = BinaryNumberChip::construct(self.copy_table.tag);

        layouter.assign_region(
            || "assign copy table",
            |mut region| {
                region.name_column(|| "is_last", self.is_last);
                region.name_column(|| "value_word", self.value_word);
                region.name_column(|| "value_word_prev", self.value_word_prev);
                region.name_column(|| "value_acc", self.value_acc);
                for i in 0..16 {
                    region.name_column(|| format!("value_limbs[{}]", i), self.value_limbs[i]);
                    region.name_column(
                        || format!("is_front_mask[{}].lt", i),
                        self.is_front_mask[i].lt,
                    );
                    region.name_column(
                        || format!("is_not_back_mask[{}].lt", i),
                        self.is_not_back_mask[i].lt,
                    );
                    region.name_column(
                        || format!("is_inbound_read[{}].lt", i),
                        self.is_inbound_read[i].lt,
                    );
                    region.name_column(
                        || format!("non_pad_non_mask[{}]", i),
                        self.non_pad_non_mask[i],
                    );
                }

                let mut offset = 0;
                for (ev_idx, copy_event) in copy_events.iter().enumerate() {
                    log::trace!(
                        "offset is {} before {}th copy event(bytes len: {}): {:?}",
                        offset,
                        ev_idx,
                        copy_event.full_length(),
                        {
                            CopyEvent {
                                copy_bytes: Default::default(),
                                ..copy_event.clone()
                            }
                        }
                    );
                    self.assign_copy_event(
                        &mut region,
                        &mut offset,
                        &is_front_mask_chip,
                        &is_not_back_mask_chip,
                        &is_inbound_read_chip,
                        &tag_chip,
                        challenges,
                        copy_event,
                    )?;
                    log::trace!("offset after {}th copy event: {}", ev_idx, offset);
                }

                for _ in 0..filler_rows {
                    self.assign_padding_row(
                        &mut region,
                        &mut offset,
                        true,
                        &is_front_mask_chip,
                        &is_not_back_mask_chip,
                        &is_inbound_read_chip,
                        &tag_chip,
                    )?;
                }
                assert_eq!(offset % 2, 0, "enabled rows must come in pairs");

                for _ in 0..DISABLED_ROWS {
                    self.assign_padding_row(
                        &mut region,
                        &mut offset,
                        false,
                        &is_front_mask_chip,
                        &is_not_back_mask_chip,
                        &is_inbound_read_chip,
                        &tag_chip,
                    )?;
                }

                Ok(())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_padding_row(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        enabled: bool,
        is_front_mask_chip: &[LtChip<F, N_BYTES_MEMORY_ADDRESS>; 16],
        is_not_back_mask_chip: &[LtChip<F, N_BYTES_MEMORY_ADDRESS>; 16],
        is_inbound_read_chip: &[LtChip<F, N_BYTES_MEMORY_ADDRESS>; 16],
        tag_chip: &BinaryNumberChip<F, CopyDataType, { CopyDataType::N_BITS }>,
    ) -> Result<(), Error> {
        // q_enable
        region.assign_fixed(
            || "q_enable",
            self.q_enable,
            *offset,
            || Value::known(F::from(enabled)),
        )?;
        // q_step
        if enabled && *offset % 2 == 0 {
            self.q_step.enable(region, *offset)?;
        }

        // is_first
        region.assign_advice(
            || format!("assign is_first {}", *offset),
            self.copy_table.is_first,
            *offset,
            || Value::known(F::zero()),
        )?;
        // is_last
        region.assign_advice(
            || format!("assign is_last {}", *offset),
            self.is_last,
            *offset,
            || Value::known(F::from(*offset % 2 == 1)),
        )?;
        // id
        region.assign_advice(
            || format!("assign id lo {}", *offset),
            self.copy_table.id.lo(),
            *offset,
            || Value::known(F::zero()),
        )?;
        region.assign_advice(
            || format!("assign id hi {}", *offset),
            self.copy_table.id.hi(),
            *offset,
            || Value::known(F::zero()),
        )?;
        // addr
        region.assign_advice(
            || format!("assign addr {}", *offset),
            self.copy_table.addr,
            *offset,
            || Value::known(F::zero()),
        )?;
        // src_addr_end
        region.assign_advice(
            || format!("assign src_addr_end {}", *offset),
            self.copy_table.src_addr_end,
            *offset,
            || Value::known(F::one()),
        )?;
        // real_bytes_left
        region.assign_advice(
            || format!("assign bytes_left {}", *offset),
            self.copy_table.real_bytes_left,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value
        for (i, col) in self.value_limbs.iter().enumerate() {
            region.assign_advice(
                || format!("assign value_limbs[{i}] {offset}"),
                *col,
                *offset,
                || Value::known(F::zero()),
            )?;
        }
        // value_word_rlc
        region.assign_advice(
            || format!("assign value_word {}", *offset),
            self.value_word,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value_word_rlc_prev
        region.assign_advice(
            || format!("assign value_word_prev {}", *offset),
            self.value_word_prev,
            *offset,
            || Value::known(F::zero()),
        )?;

        // value_acc
        region.assign_advice(
            || format!("assign value_acc {}", *offset),
            self.value_acc,
            *offset,
            || Value::known(F::zero()),
        )?;
        // rlc_acc
        region.assign_advice(
            || format!("assign rlc_acc {}", *offset),
            self.copy_table.rlc_acc,
            *offset,
            || Value::known(F::zero()),
        )?;
        // rw_counter
        region.assign_advice(
            || format!("assign rw_counter {}", *offset),
            self.copy_table.rw_counter,
            *offset,
            || Value::known(F::zero()),
        )?;

        // rwc_inc_left
        region.assign_advice(
            || format!("assign rwc_inc_left {}", *offset),
            self.copy_table.rwc_inc_left,
            *offset,
            || Value::known(F::zero()),
        )?;
        // tag
        tag_chip.assign(region, *offset, &CopyDataType::Padding)?;

        for ((is_front_mask, is_not_back_mask), is_inbound_read) in is_front_mask_chip
            .iter()
            .zip(is_not_back_mask_chip)
            .zip(is_inbound_read_chip)
        {
            is_front_mask.assign(region, *offset, F::one(), F::zero())?;
            is_not_back_mask.assign(region, *offset, F::one(), F::zero())?;
            is_inbound_read.assign(region, *offset, F::one(), F::zero())?;
        }

        for (idx, non_pad_non_mask) in self.non_pad_non_mask.iter().enumerate() {
            region.assign_advice(
                || format!("non_pad_non_mask[{idx}] at row: {offset}"),
                *non_pad_non_mask,
                *offset,
                || Value::known(F::zero()),
            )?;
        }

        for column in [
            self.is_tx_calldata,
            self.is_bytecode,
            self.is_memory,
            self.is_tx_log,
            self.is_access_list_address,
            self.is_access_list_storage_key,
        ] {
            region.assign_advice(
                || format!("assigning padding row: {}", *offset),
                column,
                *offset,
                || Value::known(F::zero()),
            )?;
        }

        *offset += 1;

        Ok(())
    }
}

/// Struct for external data, specifies values for related lookup tables
#[derive(Clone, Debug, Default)]
pub struct ExternalData {
    /// TxCircuit -> max_txs
    pub max_txs: usize,
    /// TxCircuit -> max_calldata
    pub max_calldata: usize,
    /// TxCircuit -> txs
    pub txs: Vec<Transaction>,
    /// StateCircuit -> max_rws
    pub max_rws: usize,
    /// StateCircuit -> rws
    pub rws: RwMap,
    /// BytecodeCircuit -> bytecodes
    pub bytecodes: BTreeMap<Word, Bytecode>,
}

/// Copy Circuit
#[derive(Clone, Debug, Default)]
pub struct CopyCircuit<F: Field> {
    /// Copy events
    pub copy_events: Vec<CopyEvent>,
    /// Max number of rows in copy circuit
    pub max_copy_rows: usize,
    _marker: PhantomData<F>,
    /// Data for external lookup tables
    pub external_data: ExternalData,
}

impl<F: Field> CopyCircuit<F> {
    /// Return a new CopyCircuit
    pub fn new(copy_events: Vec<CopyEvent>, max_copy_rows: usize) -> Self {
        Self {
            copy_events,
            max_copy_rows,
            _marker: PhantomData,
            external_data: ExternalData::default(),
        }
    }

    /// Return a new CopyCircuit with external data
    pub fn new_with_external_data(
        copy_events: Vec<CopyEvent>,
        max_copy_rows: usize,
        external_data: ExternalData,
    ) -> Self {
        Self {
            copy_events,
            max_copy_rows,
            _marker: PhantomData,
            external_data,
        }
    }

    /// Return a new CopyCircuit from a block without the external data required
    /// to assign lookup tables.  This constructor is only suitable to be
    /// used by the SuperCircuit, which already assigns the external lookup
    /// tables.
    pub fn new_from_block_no_external(block: &witness::Block<F>) -> Self {
        Self::new(
            block.copy_events.clone(),
            block.circuits_params.max_copy_rows,
        )
    }
}

impl<F: Field> SubCircuit<F> for CopyCircuit<F> {
    type Config = CopyCircuitConfig<F>;

    fn unusable_rows() -> usize {
        // No column queried at more than 3 distinct rotations, so returns 6 as
        // minimum unusable rows.
        6
    }

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new_with_external_data(
            block.copy_events.clone(),
            block.circuits_params.max_copy_rows,
            ExternalData {
                max_txs: block.circuits_params.max_txs,
                max_calldata: block.circuits_params.max_calldata,
                txs: block.txs.clone(),
                max_rws: block.circuits_params.max_rws,
                rws: block.rws.clone(),
                bytecodes: block.bytecodes.clone(),
            },
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let row_num = block
            .copy_events
            .iter()
            .map(|c| c.full_length() as usize * 2)
            .sum::<usize>()
            + UNUSED_ROWS
            + DISABLED_ROWS;
        (row_num, row_num.max(block.circuits_params.max_copy_rows))
    }

    /// Make the assignments to the CopyCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign_copy_events(layouter, &self.copy_events, self.max_copy_rows, *challenges)
    }
}

fn unwrap_value<F: Field>(value: Value<F>) -> F {
    let mut f = F::zero();
    value.map(|v| f = v);
    f
}

#[cfg(test)]
mod copy_circuit_stats {
    use crate::{
        evm_circuit::step::ExecutionState,
        stats::{bytecode_prefix_op_big_rws, print_circuit_stats_by_states},
    };

    /// Prints the stats of Copy circuit per execution state.  See
    /// `print_circuit_stats_by_states` for more details.
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release --all-features
    /// get_evm_states_stats -- --nocapture --ignored`
    #[ignore]
    #[test]
    fn get_copy_states_stats() {
        print_circuit_stats_by_states(
            |state| {
                // TODO: Enable CREATE/CREATE2 once they are supported
                matches!(
                    state,
                    ExecutionState::RETURNDATACOPY
                        | ExecutionState::CODECOPY
                        | ExecutionState::LOG
                        | ExecutionState::CALLDATACOPY
                        | ExecutionState::EXTCODECOPY
                        | ExecutionState::RETURN_REVERT
                )
            },
            bytecode_prefix_op_big_rws,
            |block, _, _| {
                assert!(block.copy_events.len() <= 1);
                block
                    .copy_events
                    .iter()
                    .map(|c| c.copy_bytes.bytes.len() * 2)
                    .sum::<usize>()
            },
        );
    }
}
