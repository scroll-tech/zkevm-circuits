//! The Copy circuit implements constraints and lookups for read-write steps for
//! copied bytes while execution opcodes such as CALLDATACOPY, CODECOPY, LOGS,
//! etc.
pub(crate) mod util;

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
#[cfg(any(feature = "test", test))]
mod test;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub use dev::CopyCircuit as TestCopyCircuit;

use bus_mapping::{
    circuit_input_builder::{CopyDataType, CopyEvent},
    precompile::PrecompileCalls,
};
use eth_types::{Field, Word};

use gadgets::{
    binary_number::BinaryNumberChip,
    less_than::{LtChip, LtConfig, LtInstruction},
    util::{and, not, or, sum, Expr},
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
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{
        BytecodeFieldTag, BytecodeTable, CopyTable, LookupTable, RwTable, RwTableTag,
        TxContextFieldTag, TxTable,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
    witness::{Bytecode, RwMap, Transaction},
};

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
    /// Random linear combination accumulator value.
    pub value_acc: Column<Advice>,
    /// Whether the row is padding.
    pub is_pad: Column<Advice>,
    /// In case of a bytecode tag, this denotes whether or not the copied byte
    /// is an opcode or push data byte.
    pub is_code: Column<Advice>,
    /// Indicates whether or not the copy event copies bytes to a precompiled call or copies bytes
    /// from a precompiled call back to caller.
    pub is_precompiled: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_tx_calldata: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_bytecode: Column<Advice>,
    /// Booleans to indicate what copy data type exists at the current row.
    pub is_memory: Column<Advice>,
    /// Whether the row is enabled or not.
    pub q_enable: Column<Fixed>,
    /// The Copy Table contains the columns that are exposed via the lookup
    /// expressions
    pub copy_table: CopyTable,
    /// Lt chip to check: src_addr < src_addr_end.
    /// Since `src_addr` and `src_addr_end` are u64, 8 bytes are sufficient for
    /// the Lt chip.
    pub addr_lt_addr_end: LtConfig<F, 8>,
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
        let value = meta.advice_column_in(SecondPhase);
        let value_acc = meta.advice_column_in(SecondPhase);
        let is_code = meta.advice_column();
        let (is_precompiled, is_tx_calldata, is_bytecode, is_memory) = (
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
        let bytes_left = copy_table.bytes_left;
        let rlc_acc = copy_table.rlc_acc;
        let rw_counter = copy_table.rw_counter;
        let rwc_inc_left = copy_table.rwc_inc_left;
        let tag = copy_table.tag;

        // annotate table columns
        tx_table.annotate_columns(meta);
        rw_table.annotate_columns(meta);
        bytecode_table.annotate_columns(meta);
        copy_table.annotate_columns(meta);

        let addr_lt_addr_end = LtChip::configure(
            meta,
            |meta| meta.query_selector(q_step),
            |meta| meta.query_advice(addr, Rotation::cur()),
            |meta| meta.query_advice(src_addr_end, Rotation::cur()),
        );

        meta.create_gate("is precompile", |meta| {
            let enabled = meta.query_fixed(q_enable, Rotation::cur());
            let is_precompile = meta.query_advice(is_precompiled, Rotation::cur());
            let is_tx_calldata = meta.query_advice(is_tx_calldata, Rotation::cur());
            let is_bytecode = meta.query_advice(is_bytecode, Rotation::cur());
            let is_memory = meta.query_advice(is_memory, Rotation::cur());
            let precompiles = sum::expr([
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Ecrecover),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Sha256),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Ripemd160),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Identity),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Modexp),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Bn128Add),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Bn128Mul),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Bn128Pairing),
                    Rotation::cur(),
                )(meta),
                tag.value_equals(
                    CopyDataType::Precompile(PrecompileCalls::Blake2F),
                    Rotation::cur(),
                )(meta),
            ]);
            vec![
                enabled.expr() * (is_precompile - precompiles),
                enabled.expr()
                    * (is_tx_calldata
                        - tag.value_equals(CopyDataType::TxCalldata, Rotation::cur())(meta)),
                enabled.expr()
                    * (is_bytecode
                        - tag.value_equals(CopyDataType::Bytecode, Rotation::cur())(meta)),
                enabled.expr()
                    * (is_memory - tag.value_equals(CopyDataType::Memory, Rotation::cur())(meta)),
            ]
        });

        meta.create_gate("verify row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_first is boolean",
                meta.query_advice(is_first, Rotation::cur()),
            );
            cb.require_boolean(
                "is_last is boolean",
                meta.query_advice(is_last, Rotation::cur()),
            );
            cb.require_zero(
                "is_first == 0 when q_step == 0",
                and::expr([
                    not::expr(meta.query_selector(q_step)),
                    meta.query_advice(is_first, Rotation::cur()),
                ]),
            );
            cb.require_zero(
                "is_last == 0 when q_step == 1",
                and::expr([
                    meta.query_advice(is_last, Rotation::cur()),
                    meta.query_selector(q_step),
                ]),
            );

            let not_last_two_rows = 1.expr()
                - meta.query_advice(is_last, Rotation::cur())
                - meta.query_advice(is_last, Rotation::next());
            cb.condition(
                not_last_two_rows
                    * (not::expr(tag.value_equals(CopyDataType::Padding, Rotation::cur())(
                        meta,
                    ))),
                |cb| {
                    cb.require_equal(
                        "rows[0].id == rows[2].id",
                        meta.query_advice(id, Rotation::cur()),
                        meta.query_advice(id, Rotation(2)),
                    );
                    cb.require_equal(
                        "rows[0].tag == rows[2].tag",
                        tag.value(Rotation::cur())(meta),
                        tag.value(Rotation(2))(meta),
                    );
                    cb.require_equal(
                        "rows[0].addr + 1 == rows[2].addr",
                        meta.query_advice(addr, Rotation::cur()) + 1.expr(),
                        meta.query_advice(addr, Rotation(2)),
                    );
                    cb.require_equal(
                        "rows[0].src_addr_end == rows[2].src_addr_end for non-last step",
                        meta.query_advice(src_addr_end, Rotation::cur()),
                        meta.query_advice(src_addr_end, Rotation(2)),
                    );
                },
            );

            let rw_diff = and::expr([
                or::expr([
                    meta.query_advice(is_memory, Rotation::cur()),
                    tag.value_equals(CopyDataType::TxLog, Rotation::cur())(meta),
                ]),
                not::expr(meta.query_advice(is_pad, Rotation::cur())),
            ]);
            cb.condition(
                not::expr(meta.query_advice(is_last, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "rows[0].rw_counter + rw_diff == rows[1].rw_counter",
                        meta.query_advice(rw_counter, Rotation::cur()) + rw_diff.clone(),
                        meta.query_advice(rw_counter, Rotation::next()),
                    );
                    cb.require_equal(
                        "rows[0].rwc_inc_left - rw_diff == rows[1].rwc_inc_left",
                        meta.query_advice(rwc_inc_left, Rotation::cur()) - rw_diff.clone(),
                        meta.query_advice(rwc_inc_left, Rotation::next()),
                    );
                    cb.require_equal(
                        "rows[0].rlc_acc == rows[1].rlc_acc",
                        meta.query_advice(rlc_acc, Rotation::cur()),
                        meta.query_advice(rlc_acc, Rotation::next()),
                    );
                },
            );
            cb.condition(meta.query_advice(is_last, Rotation::cur()), |cb| {
                cb.require_equal(
                    "rwc_inc_left == rw_diff for last row in the copy slot",
                    meta.query_advice(rwc_inc_left, Rotation::cur()),
                    rw_diff,
                );
            });

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate(
            "Last Step (check value accumulator) Memory => Precompile or Precompile => Memory",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.require_equal(
                    "value_acc == rlc_acc on the last row",
                    meta.query_advice(value_acc, Rotation::next()),
                    meta.query_advice(rlc_acc, Rotation::next()),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_last, Rotation::next()),
                    or::expr([
                        meta.query_advice(is_precompiled, Rotation::cur()),
                        meta.query_advice(is_precompiled, Rotation::next()),
                    ]),
                ]))
            },
        );

        meta.create_gate(
            "Last Step (check value accumulator) Memory => Bytecode",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                cb.require_equal(
                    "value_acc == rlc_acc on the last row",
                    meta.query_advice(value_acc, Rotation::next()),
                    meta.query_advice(rlc_acc, Rotation::next()),
                );

                cb.gate(and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    meta.query_advice(is_last, Rotation::next()),
                    and::expr([
                        meta.query_advice(is_memory, Rotation::cur()),
                        meta.query_advice(is_bytecode, Rotation::next()),
                    ]),
                ]))
            },
        );

        meta.create_gate("Last Step (check value accumulator) RlcAcc", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "value_acc == rlc_acc on the last row",
                meta.query_advice(value_acc, Rotation::next()),
                meta.query_advice(rlc_acc, Rotation::next()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(is_last, Rotation::next()),
                tag.value_equals(CopyDataType::RlcAcc, Rotation::next())(meta),
            ]))
        });

        meta.create_gate("verify step (q_step == 1)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "bytes_left == 1 for last step",
                and::expr([
                    meta.query_advice(is_last, Rotation::next()),
                    1.expr() - meta.query_advice(bytes_left, Rotation::cur()),
                ]),
            );
            cb.condition(
                not::expr(meta.query_advice(is_last, Rotation::next()))
                    * (not::expr(tag.value_equals(CopyDataType::Padding, Rotation::cur())(
                        meta,
                    ))),
                |cb| {
                    cb.require_equal(
                        "bytes_left == bytes_left_next + 1 for non-last step",
                        meta.query_advice(bytes_left, Rotation::cur()),
                        meta.query_advice(bytes_left, Rotation(2)) + 1.expr(),
                    );
                },
            );
            cb.require_equal(
                "write value == read value",
                meta.query_advice(value, Rotation::cur()),
                meta.query_advice(value, Rotation::next()),
            );
            cb.require_equal(
                "value_acc is same for read-write rows",
                meta.query_advice(value_acc, Rotation::cur()),
                meta.query_advice(value_acc, Rotation::next()),
            );
            cb.condition(
                and::expr([
                    not::expr(meta.query_advice(is_last, Rotation::next())),
                    not::expr(meta.query_advice(is_pad, Rotation::cur())),
                ]),
                |cb| {
                    cb.require_equal(
                        "value_acc(2) == value_acc(0) * r + value(2)",
                        meta.query_advice(value_acc, Rotation(2)),
                        meta.query_advice(value_acc, Rotation::cur()) * challenges.keccak_input()
                            + meta.query_advice(value, Rotation(2)),
                    );
                },
            );
            cb.require_zero(
                "value == 0 when is_pad == 1 for read",
                and::expr([
                    meta.query_advice(is_pad, Rotation::cur()),
                    meta.query_advice(value, Rotation::cur()),
                ]),
            );
            cb.require_equal(
                "is_pad == 1 - (src_addr < src_addr_end) for read row",
                1.expr() - addr_lt_addr_end.is_lt(meta, None),
                meta.query_advice(is_pad, Rotation::cur()),
            );
            cb.require_zero(
                "is_pad == 0 for write row",
                meta.query_advice(is_pad, Rotation::next()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_selector(q_step),
            ]))
        });

        meta.lookup_any("Memory lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * meta.query_advice(is_memory, Rotation::cur())
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
                1.expr(),
                meta.query_advice(rw_counter, Rotation::cur()),
                not::expr(meta.query_selector(q_step)),
                RwTableTag::Memory.expr(),
                meta.query_advice(id, Rotation::cur()), // call_id
                meta.query_advice(addr, Rotation::cur()), // memory address
                0.expr(),
                0.expr(),
                meta.query_advice(value, Rotation::cur()),
                0.expr(),
                0.expr(),
                0.expr(),
            ]
            .into_iter()
            .zip(rw_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("TxLog lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * tag.value_equals(CopyDataType::TxLog, Rotation::cur())(meta);
            vec![
                1.expr(),
                meta.query_advice(rw_counter, Rotation::cur()),
                1.expr(),
                RwTableTag::TxLog.expr(),
                meta.query_advice(id, Rotation::cur()), // tx_id
                meta.query_advice(addr, Rotation::cur()), // byte_index || field_tag || log_id
                0.expr(),
                0.expr(),
                meta.query_advice(value, Rotation::cur()),
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
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * meta.query_advice(is_bytecode, Rotation::cur())
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
                1.expr(),
                meta.query_advice(id, Rotation::cur()),
                BytecodeFieldTag::Byte.expr(),
                meta.query_advice(addr, Rotation::cur()),
                meta.query_advice(is_code, Rotation::cur()),
                meta.query_advice(value, Rotation::cur()),
            ]
            .into_iter()
            .zip_eq(bytecode_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("Tx calldata lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * meta.query_advice(is_tx_calldata, Rotation::cur())
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
                1.expr(),
                meta.query_advice(id, Rotation::cur()),
                TxContextFieldTag::CallData.expr(),
                meta.query_advice(addr, Rotation::cur()),
                meta.query_advice(value, Rotation::cur()),
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
            value_acc,
            is_pad,
            is_code,
            is_precompiled,
            is_tx_calldata,
            is_bytecode,
            is_memory,
            q_enable,
            addr_lt_addr_end,
            copy_table,
            tx_table,
            rw_table,
            bytecode_table,
        }
    }
}

impl<F: Field> CopyCircuitConfig<F> {
    /// Assign an individual copy event to the Copy Circuit.
    pub fn assign_copy_event(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        tag_chip: &BinaryNumberChip<F, CopyDataType, 4>,
        lt_chip: &LtChip<F, 8>,
        challenges: Challenges<Value<F>>,
        copy_event: &CopyEvent,
    ) -> Result<(), Error> {
        for (step_idx, (tag, table_row, circuit_row)) in
            CopyTable::assignments(copy_event, challenges)
                .iter()
                .enumerate()
        {
            let is_read = step_idx % 2 == 0;

            region.assign_fixed(
                || format!("q_enable at row: {}", offset),
                self.q_enable,
                *offset,
                || Value::known(F::one()),
            )?;

            // Copy table assignments
            for (&column, &(value, label)) in
                <CopyTable as LookupTable<F>>::advice_columns(&self.copy_table)
                    .iter()
                    .zip_eq(table_row)
            {
                // Leave sr_addr_end and bytes_left unassigned when !is_read
                if !is_read && (label == "src_addr_end" || label == "bytes_left") {
                } else {
                    region.assign_advice(
                        || format!("{} at row: {}", label, offset),
                        column,
                        *offset,
                        || value,
                    )?;
                }
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

            // is_last, value, is_pad, is_code
            for (column, &(value, label)) in [
                self.is_last,
                self.value,
                self.value_acc,
                self.is_pad,
                self.is_code,
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
                lt_chip.assign(
                    region,
                    *offset,
                    F::from(copy_event.src_addr + u64::try_from(step_idx).unwrap() / 2u64),
                    F::from(copy_event.src_addr_end),
                )?;
            }

            // if the memory copy operation is related to precompile calls.
            let is_precompiled = CopyDataType::precompile_types().contains(tag);
            region.assign_advice(
                || format!("is_precompiled at row: {}", *offset),
                self.is_precompiled,
                *offset,
                || Value::known(F::from(is_precompiled)),
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
        let copy_rows_needed = copy_events.iter().map(|c| c.bytes.len() * 2).sum::<usize>();

        // The `+ 2` is used to take into account the two extra empty copy rows needed
        // to satisfy the query at `Rotation(2)` performed inside of the
        // `rows[2].value == rows[0].value * r + rows[1].value` requirement in the RLC
        // Accumulation gate.
        assert!(
            copy_rows_needed + 2 <= max_copy_rows,
            "copy rows not enough {} vs {}",
            copy_rows_needed,
            max_copy_rows
        );

        let tag_chip = BinaryNumberChip::construct(self.copy_table.tag);
        let lt_chip = LtChip::construct(self.addr_lt_addr_end);

        layouter.assign_region(
            || "assign copy table",
            |mut region| {
                region.name_column(|| "is_last", self.is_last);
                region.name_column(|| "value", self.value);
                region.name_column(|| "is_code", self.is_code);
                region.name_column(|| "is_pad", self.is_pad);

                let mut offset = 0;
                for (ev_idx, copy_event) in copy_events.iter().enumerate() {
                    log::trace!(
                        "offset is {} before {}th copy event(bytes len: {}): {:?}",
                        offset,
                        ev_idx,
                        copy_event.bytes.len(),
                        {
                            let mut copy_event = copy_event.clone();
                            copy_event.bytes.clear();
                            copy_event
                        }
                    );
                    self.assign_copy_event(
                        &mut region,
                        &mut offset,
                        &tag_chip,
                        &lt_chip,
                        challenges,
                        copy_event,
                    )?;
                    log::trace!("offset after {}th copy event: {}", ev_idx, offset);
                }

                for _ in 0..max_copy_rows - copy_rows_needed - 2 {
                    self.assign_padding_row(&mut region, &mut offset, false, &tag_chip, &lt_chip)?;
                }

                self.assign_padding_row(&mut region, &mut offset, true, &tag_chip, &lt_chip)?;
                self.assign_padding_row(&mut region, &mut offset, true, &tag_chip, &lt_chip)?;

                Ok(())
            },
        )
    }

    fn assign_padding_row(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        is_last_two: bool,
        tag_chip: &BinaryNumberChip<F, CopyDataType, 4>,
        lt_chip: &LtChip<F, 8>,
    ) -> Result<(), Error> {
        if !is_last_two {
            // q_enable
            region.assign_fixed(
                || "q_enable",
                self.q_enable,
                *offset,
                || Value::known(F::one()),
            )?;
            // q_step
            if *offset % 2 == 0 {
                self.q_step.enable(region, *offset)?;
            }
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
            || Value::known(F::zero()),
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
        // bytes_left
        region.assign_advice(
            || format!("assign bytes_left {}", *offset),
            self.copy_table.bytes_left,
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
        // is_code
        region.assign_advice(
            || format!("assign is_code {}", *offset),
            self.is_code,
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
        // Assign LT gadget
        lt_chip.assign(region, *offset, F::zero(), F::one())?;
        for column in [
            self.is_precompiled,
            self.is_tx_calldata,
            self.is_bytecode,
            self.is_memory,
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
        (
            block
                .copy_events
                .iter()
                .map(|c| c.bytes.len() * 2)
                .sum::<usize>()
                + 2,
            block.circuits_params.max_copy_rows,
        )
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
                    .map(|c| c.bytes.len() * 2)
                    .sum::<usize>()
            },
        );
    }
}
