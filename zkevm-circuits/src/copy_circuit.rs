//! The Copy circuit implements constraints and lookups for read-write steps for
//! copied bytes while execution opcodes such as CALLDATACOPY, CODECOPY, LOGS,
//! etc.

use bus_mapping::circuit_input_builder::{CopyDataType, CopyEvent, NumberOrHash};
use eth_types::Field;
use eth_types::Word;
use gadgets::{
    binary_number::BinaryNumberChip,
    less_than::{LtChip, LtConfig, LtInstruction},
    util::{and, not, or, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use std::collections::HashMap;
use std::marker::PhantomData;

use crate::witness::{Bytecode, RwMap, Transaction};
#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use crate::{
    evm_circuit::util::{constraint_builder::BaseConstraintBuilder, rlc},
    table::{
        BytecodeTable, CopyTable, LookupTable, RwTable, RwTableTag, TxContextFieldTag, TxTable,
    },
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
use halo2_proofs::{
    circuit::SimpleFloorPlanner,
    plonk::{Challenge, Circuit},
};

/// Encode the type `NumberOrHash` into a field element
pub fn number_or_hash_to_field<F: Field>(v: &NumberOrHash, challenge: Value<F>) -> Value<F> {
    match v {
        NumberOrHash::Number(n) => Value::known(F::from(*n as u64)),
        NumberOrHash::Hash(h) => {
            // since code hash in the bytecode table is represented in
            // the little-endian form, we reverse the big-endian bytes
            // of H256.
            let le_bytes = {
                let mut b = h.to_fixed_bytes();
                b.reverse();
                b
            };
            challenge.map(|challenge| rlc::value(&le_bytes, challenge))
        }
    }
}

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
    /// Whether the row is padding.
    pub is_pad: Column<Advice>,
    /// In case of a bytecode tag, this denotes whether or not the copied byte
    /// is an opcode or push data byte.
    pub is_code: Column<Advice>,
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
        let is_code = meta.advice_column();
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
                    tag.value_equals(CopyDataType::Memory, Rotation::cur())(meta),
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
            cb.condition(
                and::expr([
                    meta.query_advice(is_last, Rotation::cur()),
                    tag.value_equals(CopyDataType::RlcAcc, Rotation::cur())(meta),
                ]),
                |cb| {
                    cb.require_equal(
                        "value == rlc_acc at the last row for RlcAcc",
                        meta.query_advice(value, Rotation::cur()),
                        meta.query_advice(rlc_acc, Rotation::cur()),
                    );
                },
            );

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
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
            cb.condition(
                not::expr(tag.value_equals(CopyDataType::RlcAcc, Rotation::next())(
                    meta,
                )),
                |cb| {
                    cb.require_equal(
                        "write value == read value (if not rlc acc)",
                        meta.query_advice(value, Rotation::cur()),
                        meta.query_advice(value, Rotation::next()),
                    );
                },
            );
            cb.condition(meta.query_advice(is_first, Rotation::cur()), |cb| {
                cb.require_equal(
                    "write value == read value (is_first == 1)",
                    meta.query_advice(value, Rotation::cur()),
                    meta.query_advice(value, Rotation::next()),
                );
            });
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

            cb.gate(meta.query_selector(q_step))
        });

        meta.create_gate("verify_step (q_step == 0)", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "rows[2].value == rows[0].value * r + rows[1].value",
                meta.query_advice(value, Rotation(2)),
                meta.query_advice(value, Rotation::cur()) * challenges.keccak_input()
                    + meta.query_advice(value, Rotation::next()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_selector(q_step)),
                not::expr(meta.query_advice(is_last, Rotation::cur())),
                tag.value_equals(CopyDataType::RlcAcc, Rotation::cur())(meta),
                not::expr(meta.query_advice(is_pad, Rotation::cur())),
            ]))
        });

        meta.lookup_any("Memory lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * tag.value_equals(CopyDataType::Memory, Rotation::cur())(meta)
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
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

        // create case unimplemented for poseidon hash
        #[cfg(feature = "codehash")]
        meta.lookup_any("Bytecode lookup", |meta| {
            use crate::table::BytecodeFieldTag;
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * tag.value_equals(CopyDataType::Bytecode, Rotation::cur())(meta)
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
                meta.query_advice(id, Rotation::cur()),
                BytecodeFieldTag::Byte.expr(),
                meta.query_advice(addr, Rotation::cur()),
                meta.query_advice(is_code, Rotation::cur()),
                meta.query_advice(value, Rotation::cur()),
            ]
            .into_iter()
            .zip(bytecode_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("Tx calldata lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * tag.value_equals(CopyDataType::TxCalldata, Rotation::cur())(meta)
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
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
            is_pad,
            is_code,
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
        tag_chip: &BinaryNumberChip<F, CopyDataType, 3>,
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
            // FIXME: finish padding of copy circuit
            // Now temporarily set it to 0 to make vk univeral
            // q_enable
            region.assign_fixed(
                || "q_enable",
                self.q_enable,
                *offset,
                || Value::known(F::one()),
            )?;

            // is_last, value, is_pad, is_code
            for (column, &(value, label)) in [self.is_last, self.value, self.is_pad, self.is_code]
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

            //tag
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
        assert!(copy_rows_needed + 2 <= max_copy_rows);

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
                    log::debug!(
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
                    log::debug!("offset after {}th copy event: {}", ev_idx, offset);
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
        tag_chip: &BinaryNumberChip<F, CopyDataType, 3>,
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
    pub bytecodes: HashMap<Word, Bytecode>,
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

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
impl<F: Field> Circuit<F> for CopyCircuit<F> {
    type Config = (CopyCircuitConfig<F>, Challenges<Challenge>);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let rw_table = RwTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let q_enable = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_enable);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);

        (
            CopyCircuitConfig::new(
                meta,
                CopyCircuitConfigArgs {
                    tx_table,
                    rw_table,
                    bytecode_table,
                    copy_table,
                    q_enable,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let challenge_values = config.1.values(&layouter);

        config.0.tx_table.load(
            &mut layouter,
            &self.external_data.txs,
            self.external_data.max_txs,
            self.external_data.max_calldata,
            0,
            &challenge_values,
        )?;

        config.0.rw_table.load(
            &mut layouter,
            &self.external_data.rws.table_assignments(),
            self.external_data.max_rws,
            challenge_values.evm_word(),
        )?;

        config.0.bytecode_table.load(
            &mut layouter,
            self.external_data.bytecodes.values(),
            &challenge_values,
        )?;
        self.synthesize_sub(&config.0, &challenge_values, &mut layouter)
    }
}

/// Dev helpers
#[cfg(any(feature = "test", test))]
pub mod dev {
    use crate::copy_circuit::*;
    use crate::witness::Block;
    use halo2_proofs::dev::{MockProver, VerifyFailure};

    /// Test copy circuit from copy events and test data
    pub fn test_copy_circuit<F: Field>(
        k: u32,
        copy_events: Vec<CopyEvent>,
        max_copy_rows: usize,
        external_data: ExternalData,
    ) -> Result<(), Vec<VerifyFailure>> {
        let circuit =
            CopyCircuit::<F>::new_with_external_data(copy_events, max_copy_rows, external_data);

        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        prover.verify_par()
    }

    /// Test copy circuit with the provided block witness
    pub fn test_copy_circuit_from_block<F: Field>(
        k: u32,
        block: Block<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        test_copy_circuit::<F>(
            k,
            block.copy_events,
            block.circuits_params.max_copy_rows,
            ExternalData {
                max_txs: block.circuits_params.max_txs,
                max_calldata: block.circuits_params.max_calldata,
                txs: block.txs,
                max_rws: block.circuits_params.max_rws,
                rws: block.rws,
                bytecodes: block.bytecodes,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::dev::test_copy_circuit_from_block;
    use crate::evm_circuit::test::rand_bytes;
    use crate::evm_circuit::witness::block_convert;
    use bus_mapping::evm::{gen_sha3_code, MemoryKind};
    use bus_mapping::{
        circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
        mock::BlockData,
    };
    use eth_types::{bytecode, geth_types::GethData, ToWord, Word};
    use halo2_proofs::dev::VerifyFailure;
    use halo2_proofs::halo2curves::bn256::Fr;
    use mock::test_ctx::helpers::account_0_code_account_1_no_code;
    use mock::{TestContext, MOCK_ACCOUNTS};
    use pretty_assertions::assert_eq;

    fn gen_calldatacopy_data() -> CircuitInputBuilder {
        let length = 0x0fffusize;
        let code = bytecode! {
            PUSH32(Word::from(length))
            PUSH32(Word::from(0x00))
            PUSH32(Word::from(0x00))
            CALLDATACOPY
            STOP
        };
        let calldata = rand_bytes(length);
        let test_ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .input(calldata.into());
            },
            |block, _txs| block.number(0xcafeu64),
        )
        .unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data_with_params(
            block.clone(),
            CircuitsParams {
                max_rws: 8192,
                max_copy_rows: 8192 + 2,
                max_calldata: 5000,
                ..Default::default()
            },
        )
        .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    fn gen_codecopy_data() -> CircuitInputBuilder {
        let code = bytecode! {
            PUSH32(Word::from(0x20))
            PUSH32(Word::from(0x00))
            PUSH32(Word::from(0x00))
            CODECOPY
            STOP
        };
        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    fn gen_extcodecopy_data() -> CircuitInputBuilder {
        let external_address = MOCK_ACCOUNTS[0];
        let code = bytecode! {
            PUSH1(0x30usize)
            PUSH1(0x0usize)
            PUSH1(0x0usize)
            PUSH20(external_address.to_word())
            EXTCODECOPY
            STOP
        };
        let code_ext = rand_bytes(0x0fffusize);
        let test_ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[1]).code(code.clone());

                accs[1].address(external_address).code(code_ext.clone());

                accs[2]
                    .address(MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    fn gen_sha3_data() -> CircuitInputBuilder {
        let (code, _) = gen_sha3_code(0x20, 0x200, MemoryKind::EqualToSize);
        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data_with_params(
            block.clone(),
            CircuitsParams {
                max_rws: 2000,
                max_copy_rows: 0x200 * 2 + 2,
                ..Default::default()
            },
        )
        .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    fn gen_tx_log_data() -> CircuitInputBuilder {
        let code = bytecode! {
            PUSH32(200)         // value
            PUSH32(0)           // offset
            MSTORE
            PUSH32(Word::MAX)   // topic
            PUSH1(32)           // length
            PUSH1(0)            // offset
            LOG1
            STOP
        };
        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    #[test]
    fn copy_circuit_valid_calldatacopy() {
        let builder = gen_calldatacopy_data();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        assert_eq!(test_copy_circuit_from_block(14, block), Ok(()));
    }

    #[test]
    fn copy_circuit_valid_codecopy() {
        let builder = gen_codecopy_data();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        assert_eq!(test_copy_circuit_from_block(10, block), Ok(()));
    }

    #[test]
    fn copy_circuit_valid_extcodecopy() {
        let builder = gen_extcodecopy_data();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        assert_eq!(test_copy_circuit_from_block(14, block), Ok(()));
    }

    #[test]
    fn copy_circuit_valid_sha3() {
        let builder = gen_sha3_data();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        assert_eq!(test_copy_circuit_from_block(14, block), Ok(()));
    }

    #[test]
    fn copy_circuit_valid_tx_log() {
        let builder = gen_tx_log_data();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        assert_eq!(test_copy_circuit_from_block(10, block), Ok(()));
    }

    #[test]
    fn copy_circuit_invalid_calldatacopy() {
        let mut builder = gen_calldatacopy_data();

        // modify first byte of first copy event
        builder.block.copy_events[0].bytes[0].0 =
            builder.block.copy_events[0].bytes[0].0.wrapping_add(1);

        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

        assert_error_matches(
            test_copy_circuit_from_block(14, block),
            vec!["Memory lookup", "Tx calldata lookup"],
        );
    }

    #[ignore = "codehash related"]
    #[test]
    fn copy_circuit_invalid_codecopy() {
        let mut builder = gen_codecopy_data();

        // modify first byte of first copy event
        builder.block.copy_events[0].bytes[0].0 =
            builder.block.copy_events[0].bytes[0].0.wrapping_add(1);

        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

        assert_error_matches(
            test_copy_circuit_from_block(10, block),
            vec!["Memory lookup", "Bytecode lookup"],
        );
    }

    #[ignore = "codehash related"]
    #[test]
    fn copy_circuit_invalid_extcodecopy() {
        let mut builder = gen_extcodecopy_data();

        // modify first byte of first copy event
        builder.block.copy_events[0].bytes[0].0 =
            builder.block.copy_events[0].bytes[0].0.wrapping_add(1);

        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

        assert_error_matches(
            test_copy_circuit_from_block(14, block),
            vec!["Memory lookup", "Bytecode lookup"],
        );
    }

    #[test]
    fn copy_circuit_invalid_sha3() {
        let mut builder = gen_sha3_data();

        // modify first byte of first copy event
        builder.block.copy_events[0].bytes[0].0 =
            builder.block.copy_events[0].bytes[0].0.wrapping_add(1);

        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

        assert_error_matches(
            test_copy_circuit_from_block(14, block),
            vec!["Memory lookup"],
        );
    }

    #[test]
    fn copy_circuit_invalid_tx_log() {
        let mut builder = gen_tx_log_data();

        // modify first byte of first copy event
        builder.block.copy_events[0].bytes[0].0 =
            builder.block.copy_events[0].bytes[0].0.wrapping_add(1);

        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();

        assert_error_matches(
            test_copy_circuit_from_block(10, block),
            vec!["Memory lookup", "TxLog lookup"],
        );
    }

    fn assert_error_matches(result: Result<(), Vec<VerifyFailure>>, names: Vec<&str>) {
        let errors = result.expect_err("result is not an error");
        assert_eq!(errors.len(), names.len(), "{:?}", errors);
        for i in 0..names.len() {
            match &errors[i] {
                VerifyFailure::Lookup {
                    name: lookup_name, ..
                } => {
                    assert_eq!(lookup_name, &names[i])
                }
                VerifyFailure::ConstraintNotSatisfied { .. } => panic!(),
                VerifyFailure::CellNotAssigned { .. } => panic!(),
                VerifyFailure::ConstraintPoisoned { .. } => panic!(),
                VerifyFailure::Permutation { .. } => panic!(),
            }
        }
    }
}
