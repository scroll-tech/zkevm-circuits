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

use bus_mapping::circuit_input_builder::{CopyDataType, CopyEvent};
use eth_types::{Field, Word};

use gadgets::{
    binary_number::BinaryNumberChip,
    is_equal::{IsEqualChip, IsEqualConfig, IsEqualInstruction},
    util::{not, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use std::{collections::BTreeMap, marker::PhantomData};

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use crate::{
    evm_circuit::util::constraint_builder::BaseConstraintBuilder,
    table::{
        BytecodeFieldTag, BytecodeTable, CopyTable, LookupTable, RwTable, RwTableTag,
        TxContextFieldTag, TxTable,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
    witness::{Bytecode, RwMap, Transaction},
};

use self::copy_gadgets::{
    constrain_address, constrain_bytes_left, constrain_event_rlc_acc, constrain_first_last,
    constrain_forward_parameters, constrain_is_pad, constrain_mask, constrain_masked_value,
    constrain_must_terminate, constrain_non_pad_non_mask, constrain_rw_counter, constrain_tag,
    constrain_value_rlc, constrain_word_index, constrain_word_rlc,
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
    /// Whether this row denotes a step. A read row is a step and a write row is
    /// not.
    pub q_step: Selector,
    /// Whether the row is the last read-write pair for a copy event.
    pub is_last: Column<Advice>,
    /// The value copied in this copy step.
    pub value: Column<Advice>,
    /// The value before the write.
    pub value_prev: Column<Advice>,
    /// The word value for memory lookup.
    pub value_word_rlc: Column<Advice>,
    /// The word value for memory lookup, before the write.
    pub value_word_rlc_prev: Column<Advice>,
    /// The index of the current byte within a word [0..31].
    pub word_index: Column<Advice>,
    /// mask indicates when a row is not part of the copy, but it is needed to complete the front
    /// or the back of the first or last memory word.
    pub mask: Column<Advice>,
    /// Whether the row is part of the front mask, before the copy data.
    pub front_mask: Column<Advice>,
    /// Random linear combination accumulator of the non-masked copied data.
    pub value_acc: Column<Advice>,
    /// Whether the row is padding for out-of-bound reads when source address >= src_addr_end.
    pub is_pad: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_tx_calldata: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_bytecode: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_memory: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_tx_log: Column<Advice>,
    /// Whether the row is enabled or not.
    pub q_enable: Column<Fixed>,
    /// The Copy Table contains the columns that are exposed via the lookup
    /// expressions
    pub copy_table: CopyTable,
    /// Detect when the address reaches the limit src_addr_end.
    pub is_src_end: IsEqualConfig<F>,
    /// Whether this is the end of a word (last byte).
    pub is_word_end: IsEqualConfig<F>,
    /// non pad and non mask witness to reduce the degree of lookups.
    pub non_pad_non_mask: Column<Advice>,
    // External tables
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
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
        }: Self::ConfigArgs,
    ) -> Self {
        let q_step = meta.complex_selector();
        let is_last = meta.advice_column();
        let value = meta.advice_column();
        let value_prev = meta.advice_column();

        // RLC accumulators in the second phase.
        let value_word_rlc = meta.advice_column_in(SecondPhase);
        let value_word_rlc_prev = meta.advice_column_in(SecondPhase);
        let value_acc = meta.advice_column_in(SecondPhase);

        let (is_tx_calldata, is_bytecode, is_memory, is_tx_log) = (
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        let is_pad = meta.advice_column();
        let is_first = copy_table.is_first;
        let id = copy_table.id;
        let addr = copy_table.addr;
        let src_addr_end = copy_table.src_addr_end;
        let real_bytes_left = copy_table.real_bytes_left;
        let word_index = meta.advice_column();
        let mask = meta.advice_column();
        let front_mask = meta.advice_column();

        let rlc_acc = copy_table.rlc_acc;
        let rw_counter = copy_table.rw_counter;
        let rwc_inc_left = copy_table.rwc_inc_left;
        let tag = copy_table.tag;

        // annotate table columns
        tx_table.annotate_columns(meta);
        rw_table.annotate_columns(meta);
        bytecode_table.annotate_columns(meta);
        copy_table.annotate_columns(meta);

        let is_src_end = IsEqualChip::configure(
            meta,
            |meta| meta.query_selector(q_step),
            |meta| meta.query_advice(addr, CURRENT),
            |meta| meta.query_advice(src_addr_end, CURRENT),
        );

        let is_word_end = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, CURRENT),
            |meta| meta.query_advice(word_index, CURRENT),
            |_meta| 31.expr(),
        );

        let non_pad_non_mask = meta.advice_column();

        constrain_tag(
            meta,
            q_enable,
            &tag,
            is_tx_calldata,
            is_bytecode,
            is_memory,
            is_tx_log,
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
            // Detect the rows which process the last byte of a word. The next word starts at
            // NEXT_STEP.
            let is_word_end = is_word_end.expr();
            let is_tx_log = meta.query_advice(is_tx_log, CURRENT);

            constrain_first_last(cb, is_reader.expr(), is_first.expr(), is_last.expr());

            constrain_must_terminate(cb, meta, q_enable, &tag);

            constrain_forward_parameters(cb, meta, is_continue.expr(), id, tag, src_addr_end);

            let (is_pad, is_pad_next) = constrain_is_pad(
                cb,
                meta,
                is_reader.expr(),
                is_first.expr(),
                is_last_col,
                is_pad,
                addr,
                src_addr_end,
                &is_src_end,
            );

            let (mask, mask_next, front_mask) = {
                // The first 31 bytes may be front_mask, but not the last byte of the first word.
                // LOG has no front mask at all.
                let forbid_front_mask = is_word_end.expr() + is_tx_log.expr();

                constrain_mask(
                    cb,
                    meta,
                    is_first.expr(),
                    is_continue.expr(),
                    mask,
                    front_mask,
                    forbid_front_mask,
                )
            };

            constrain_non_pad_non_mask(cb, meta, non_pad_non_mask, is_pad.expr(), mask.expr());

            constrain_masked_value(cb, meta, mask.expr(), value, value_prev);

            constrain_value_rlc(
                cb,
                meta,
                is_first.expr(),
                is_continue.expr(),
                is_last_col,
                non_pad_non_mask,
                is_pad_next.expr(),
                mask_next.expr(),
                value_acc,
                value,
                challenges.keccak_input(),
            );

            constrain_event_rlc_acc(cb, meta, is_last_col, value_acc, rlc_acc, is_bytecode, tag);

            // Apply the same constraints for the RLCs of words before and after the write.
            let word_rlc_both = [(value_word_rlc, value), (value_word_rlc_prev, value_prev)];
            for (word_rlc, value) in word_rlc_both {
                constrain_word_rlc(
                    cb,
                    meta,
                    is_first.expr(),
                    is_continue.expr(),
                    is_word_end.expr(),
                    word_rlc,
                    value,
                    challenges.evm_word(),
                );
            }

            constrain_word_index(
                cb,
                meta,
                is_first.expr(),
                is_continue.expr(),
                is_word_end.expr(),
                word_index,
            );

            constrain_bytes_left(
                cb,
                meta,
                is_first.expr(),
                is_continue.expr(),
                mask.expr(),
                real_bytes_left,
            );

            constrain_address(cb, meta, is_continue.expr(), front_mask.expr(), addr);

            {
                let is_rw_type = meta.query_advice(is_memory, CURRENT) + is_tx_log.expr();

                constrain_rw_counter(
                    cb,
                    meta,
                    is_last.expr(),
                    is_last_step.expr(),
                    is_rw_type.expr(),
                    is_word_end.expr(),
                    rw_counter,
                    rwc_inc_left,
                );
            }

            cb.gate(meta.query_fixed(q_enable, CURRENT))
        });

        // memory word lookup
        meta.lookup_any("Memory word lookup", |meta| {
            let cond = meta.query_fixed(q_enable, CURRENT)
                * meta.query_advice(is_memory, CURRENT)
                * is_word_end.is_equal_expression.expr();

            let addr_slot = meta.query_advice(addr, CURRENT) - 31.expr();

            vec![
                1.expr(),
                meta.query_advice(rw_counter, CURRENT),
                not::expr(meta.query_selector(q_step)),
                RwTableTag::Memory.expr(),
                meta.query_advice(id, CURRENT), // call_id
                addr_slot,
                0.expr(),
                0.expr(),
                meta.query_advice(value_word_rlc, CURRENT),
                meta.query_advice(value_word_rlc_prev, CURRENT),
                0.expr(),
                0.expr(),
            ]
            .into_iter()
            .zip(rw_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("TxLog word lookup", |meta| {
            let cond = meta.query_fixed(q_enable, CURRENT)
                * meta.query_advice(is_tx_log, CURRENT)
                * is_word_end.is_equal_expression.expr();

            let addr_slot = meta.query_advice(addr, CURRENT) - 31.expr();

            vec![
                1.expr(),
                meta.query_advice(rw_counter, CURRENT),
                1.expr(),
                RwTableTag::TxLog.expr(),
                meta.query_advice(id, CURRENT), // tx_id
                addr_slot,                      // byte_index || field_tag || log_id
                0.expr(),
                0.expr(),
                meta.query_advice(value_word_rlc, CURRENT),
                0.expr(),
                0.expr(),
                0.expr(),
            ]
            .into_iter()
            .zip(rw_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("Bytecode lookup", |meta| {
            let cond = meta.query_fixed(q_enable, CURRENT)
                * meta.query_advice(is_bytecode, CURRENT)
                * meta.query_advice(non_pad_non_mask, CURRENT);

            vec![
                1.expr(),
                meta.query_advice(id, CURRENT),
                BytecodeFieldTag::Byte.expr(),
                meta.query_advice(addr, CURRENT),
                meta.query_advice(value, CURRENT),
            ]
            .into_iter()
            .zip_eq(bytecode_table.table_exprs_mini(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("Tx calldata lookup", |meta| {
            let cond = meta.query_fixed(q_enable, CURRENT)
                * meta.query_advice(is_tx_calldata, CURRENT)
                * meta.query_advice(non_pad_non_mask, CURRENT);

            vec![
                1.expr(),
                meta.query_advice(id, CURRENT),
                TxContextFieldTag::CallData.expr(),
                meta.query_advice(addr, CURRENT),
                meta.query_advice(value, CURRENT),
            ]
            .into_iter()
            .zip(tx_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        Self {
            q_step,
            is_last,
            value,
            value_prev,
            value_word_rlc,
            value_word_rlc_prev,
            word_index,
            mask,
            front_mask,
            value_acc,
            is_pad,
            is_tx_calldata,
            is_bytecode,
            is_memory,
            is_tx_log,
            q_enable,
            is_src_end,
            is_word_end,
            non_pad_non_mask,
            copy_table,
            tx_table,
            rw_table,
            bytecode_table,
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
        tag_chip: &BinaryNumberChip<F, CopyDataType, { CopyDataType::N_BITS }>,
        is_src_end_chip: &IsEqualChip<F>,
        lt_word_end_chip: &IsEqualChip<F>,
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
            for (&column, &(value, label)) in
                <CopyTable as LookupTable<F>>::advice_columns(&self.copy_table)
                    .iter()
                    .zip_eq(table_row)
            {
                region.assign_advice(
                    || format!("{label} at row: {offset}"),
                    column,
                    *offset,
                    || value,
                )?;
            }

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

            // is_last, value, is_pad
            for (column, &(value, label)) in [
                self.is_last,
                self.value,
                self.value_prev,
                self.value_word_rlc,
                self.value_word_rlc_prev,
                self.value_acc,
                self.is_pad,
                self.mask,
                self.front_mask,
                self.word_index,
            ]
            .iter()
            .zip_eq(circuit_row)
            {
                region.assign_advice(
                    || format!("{} at row: {}", label, *offset),
                    *column,
                    *offset,
                    || value,
                )?;
            }

            // tag
            tag_chip.assign(region, *offset, tag)?;

            // lt chip
            if is_read {
                let addr = table_row[2].0;
                is_src_end_chip.assign(
                    region,
                    *offset,
                    addr,
                    Value::known(F::from(copy_event.src_addr_end)),
                )?;
            }

            lt_word_end_chip.assign(
                region,
                *offset,
                Value::known(F::from((step_idx as u64 / 2) % 32)), // word index
                Value::known(F::from(31u64)),
            )?;

            let pad = unwrap_value(circuit_row[6].0);
            let mask = unwrap_value(circuit_row[7].0);
            let non_pad_non_mask = pad.is_zero_vartime() && mask.is_zero_vartime();
            region.assign_advice(
                || format!("non_pad_non_mask at row: {offset}"),
                self.non_pad_non_mask,
                *offset,
                || Value::known(F::from(non_pad_non_mask)),
            )?;

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

        let tag_chip = BinaryNumberChip::construct(self.copy_table.tag);
        let is_src_end_chip = IsEqualChip::construct(self.is_src_end.clone());
        let lt_word_end_chip = IsEqualChip::construct(self.is_word_end.clone());

        layouter.assign_region(
            || "assign copy table",
            |mut region| {
                region.name_column(|| "is_last", self.is_last);
                region.name_column(|| "value", self.value);
                region.name_column(|| "value_prev", self.value_prev);
                region.name_column(|| "value_word_rlc", self.value_word_rlc);
                region.name_column(|| "value_word_rlc_prev", self.value_word_rlc_prev);
                region.name_column(|| "word_index", self.word_index);
                region.name_column(|| "mask", self.mask);
                region.name_column(|| "front_mask", self.front_mask);
                region.name_column(|| "is_pad", self.is_pad);
                region.name_column(|| "non_pad_non_mask", self.non_pad_non_mask);

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
                        &tag_chip,
                        &is_src_end_chip,
                        &lt_word_end_chip,
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
                        &tag_chip,
                        &is_src_end_chip,
                        &lt_word_end_chip,
                    )?;
                }
                assert_eq!(offset % 2, 0, "enabled rows must come in pairs");

                for _ in 0..DISABLED_ROWS {
                    self.assign_padding_row(
                        &mut region,
                        &mut offset,
                        false,
                        &tag_chip,
                        &is_src_end_chip,
                        &lt_word_end_chip,
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
        tag_chip: &BinaryNumberChip<F, CopyDataType, { CopyDataType::N_BITS }>,
        is_src_end_chip: &IsEqualChip<F>,
        lt_word_end_chip: &IsEqualChip<F>,
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
            || format!("assign id {}", *offset),
            self.copy_table.id,
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
        region.assign_advice(
            || format!("assign value {}", *offset),
            self.value,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value_prev
        region.assign_advice(
            || format!("assign value_prev {}", *offset),
            self.value_prev,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value_word_rlc
        region.assign_advice(
            || format!("assign value_word_rlc {}", *offset),
            self.value_word_rlc,
            *offset,
            || Value::known(F::zero()),
        )?;
        // value_word_rlc_prev
        region.assign_advice(
            || format!("assign value_word_rlc_prev {}", *offset),
            self.value_word_rlc_prev,
            *offset,
            || Value::known(F::zero()),
        )?;
        // word_index
        region.assign_advice(
            || format!("assign word_index {}", *offset),
            self.word_index,
            *offset,
            || Value::known(F::zero()),
        )?;
        // mask
        region.assign_advice(
            || format!("assign mask {}", *offset),
            self.mask,
            *offset,
            || Value::known(F::one()),
        )?;
        // front mask
        region.assign_advice(
            || format!("assign front mask {}", *offset),
            self.front_mask,
            *offset,
            || Value::known(F::one()),
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
        // is_pad
        region.assign_advice(
            || format!("assign is_pad {}", *offset),
            self.is_pad,
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
        // Assign IsEqual gadgets
        is_src_end_chip.assign(
            region,
            *offset,
            Value::known(F::zero()),
            Value::known(F::one()),
        )?;
        lt_word_end_chip.assign(
            region,
            *offset,
            Value::known(F::zero()),
            Value::known(F::from(31u64)),
        )?;
        region.assign_advice(
            || format!("non_pad_non_mask at row: {offset}"),
            self.non_pad_non_mask,
            *offset,
            || Value::known(F::zero()),
        )?;

        for column in [
            self.is_tx_calldata,
            self.is_bytecode,
            self.is_memory,
            self.is_tx_log,
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
            _marker: PhantomData::default(),
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
            _marker: PhantomData::default(),
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
