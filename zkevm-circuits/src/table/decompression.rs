use array_init::array_init;
use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    is_equal::{IsEqualChip, IsEqualConfig},
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use strum::IntoEnumIterator;

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::BitwiseOp,
    witness::{
        FseAuxiliaryTableData, FseSymbol, FseTableData, HuffmanCodesData, N_BITS_SYMBOL,
        N_MAX_SYMBOLS,
    },
};

use super::{BitwiseOpTable, LookupTable, Pow2Table, RangeTable, U8Table};

/// The finite state entropy table in its default view, i.e. when the ``state`` increments.
///
/// | State | Symbol | Baseline | Nb  |
/// |-------|--------|----------|-----|
/// | 0x00  | s0     | 0x04     | 1   |
/// | 0x01  | s0     | 0x06     | 1   |
/// | 0x02  | s0     | 0x08     | 1   |
/// | ...   | ...    | ...      | ... |
/// | 0x1d  | s0     | 0x03     | 0   |
/// | 0x1e  | s1     | 0x0c     | 2   |
/// | 0x1f  | s2     | 0x10     | 4   |
///
/// An example for FseTable with AL (accuracy log) 5, i.e. 1 << 5 states is demonstrated above. For
/// more details, refer the [zstd worked example][doclink]
///
/// [doclink]: https://nigeltao.github.io/blog/2022/zstandard-part-5-fse.html#state-machine
#[derive(Clone, Debug)]
pub struct FseTable<F> {
    /// Fixed column to denote whether the constraints will be enabled or not.
    pub q_enabled: Column<Fixed>,
    /// The byte offset within the data instance where the encoded FSE table begins. This is
    /// 1-indexed, i.e. byte_offset == 1 at the first byte.
    pub byte_offset: Column<Advice>,
    /// Helper gadget to know when we are done handling a single canonical Huffman code.
    pub byte_offset_cmp: ComparatorConfig<F, 8>,
    /// The size of the FSE table that starts at byte_offset.
    pub table_size: Column<Advice>,
    /// Incremental index for this specific FSE table.
    pub idx: Column<Advice>,
    /// Incremental state that starts at 0x00 and increments by 1 until it reaches table_size - 1
    /// at the final row.
    pub state: Column<Advice>,
    /// Denotes the weight from the canonical Huffman code representation of the Huffman code. This
    /// is also the symbol emitted from the FSE table at this row's state.
    pub symbol: Column<Advice>,
    /// Denotes the baseline field.
    pub baseline: Column<Advice>,
    /// The number of bits to be read from bitstream at this state.
    pub nb: Column<Advice>,
}

impl<F: Field> FseTable<F> {
    /// Construct the FSE table with its columns constrained.
    pub fn construct(
        meta: &mut ConstraintSystem<F>,
        aux_table: FseAuxiliaryTable<F>,
        u8_table: U8Table,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let byte_offset = meta.advice_column();
        let table = Self {
            q_enabled,
            byte_offset,
            byte_offset_cmp: ComparatorChip::configure(
                meta,
                |meta| meta.query_fixed(q_enabled, Rotation::cur()),
                |meta| meta.query_advice(byte_offset, Rotation::cur()),
                |meta| meta.query_advice(byte_offset, Rotation::next()),
                u8_table.into(),
            ),
            table_size: meta.advice_column(),
            idx: meta.advice_column(),
            state: meta.advice_column(),
            symbol: meta.advice_column(),
            baseline: meta.advice_column(),
            nb: meta.advice_column(),
        };

        // Constraints common to all rows.
        meta.create_gate("FseTable: all rows", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (gt, eq) = table.byte_offset_cmp.expr(meta, None);
            cb.require_equal("byte offset is increasing", gt + eq, 1.expr());

            cb.gate(meta.query_fixed(table.q_enabled, Rotation::cur()))
        });

        // Constraints while we are in the same instance of FseTable.
        meta.create_gate("FseTable: while traversing the same table", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Table size remains unchanged.
            cb.require_equal(
                "while byte_offset' == byte_offset: table_size remain unchanged",
                meta.query_advice(table.table_size, Rotation::next()),
                meta.query_advice(table.table_size, Rotation::cur()),
            );

            // Index is incremental.
            cb.require_equal(
                "idx' == idx + 1",
                meta.query_advice(table.idx, Rotation::next()),
                meta.query_advice(table.idx, Rotation::cur()) + 1.expr(),
            );

            // State is incremental.
            cb.require_equal(
                "state' == state + 1",
                meta.query_advice(table.state, Rotation::next()),
                meta.query_advice(table.state, Rotation::cur()) + 1.expr(),
            );

            let (_gt, eq) = table.byte_offset_cmp.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                eq,
            ]))
        });

        // Constraints for last row of an FSE table.
        meta.create_gate("FseTable: last row of the table", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Constraint for idx == table_size.
            cb.require_equal(
                "idx == table_size",
                meta.query_advice(table.idx, Rotation::cur()),
                meta.query_advice(table.table_size, Rotation::cur()),
            );

            // Constraint for state == table_size - 1.
            cb.require_equal(
                "state == table_size - 1",
                meta.query_advice(table.state, Rotation::cur()) + 1.expr(),
                meta.query_advice(table.table_size, Rotation::cur()),
            );

            let (gt, _eq) = table.byte_offset_cmp.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                gt,
            ]))
        });

        // Validate the (state, symbol) tuple against auxiliary table.
        meta.lookup_any(
            "FseTable: validate (state, symbol) against auxiliary table",
            |meta| {
                let condition = meta.query_fixed(table.q_enabled, Rotation::cur());

                [
                    meta.query_advice(table.byte_offset, Rotation::cur()),
                    meta.query_advice(table.table_size, Rotation::cur()),
                    meta.query_advice(table.state, Rotation::cur()),
                    meta.query_advice(table.symbol, Rotation::cur()),
                    meta.query_advice(table.baseline, Rotation::cur()),
                    meta.query_advice(table.nb, Rotation::cur()),
                ]
                .into_iter()
                .zip(aux_table.table_exprs_state_check(meta))
                .map(|(input, table)| (input * condition.expr(), table))
                .collect::<Vec<_>>()
            },
        );

        debug_assert!(meta.degree() <= 9);

        table
    }

    /// Dev mode: load witness to the FSE table.
    pub fn dev_load(
        &self,
        layouter: &mut impl Layouter<F>,
        data: Vec<FseTableData>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "FseTable: dev",
            |mut region| {
                let mut offset = 0;
                for fse_table in data.iter() {
                    let byte_offset = Value::known(F::from(fse_table.byte_offset));
                    let table_size = Value::known(F::from(fse_table.table_size));
                    for row in fse_table.rows.iter() {
                        for (annotation, column, value) in [
                            ("byte_offset", self.byte_offset, byte_offset),
                            ("table_size", self.table_size, table_size),
                            ("idx", self.idx, Value::known(row.idx.into())),
                            ("state", self.state, Value::known(F::from(row.state as u64))),
                            (
                                "symbol",
                                self.symbol,
                                Value::known(F::from(row.symbol as u64)),
                            ),
                            (
                                "baseline",
                                self.baseline,
                                Value::known(F::from(row.baseline as u64)),
                            ),
                            ("nb", self.nb, Value::known(F::from(row.num_bits as u64))),
                        ] {
                            region.assign_advice(
                                || format!("FseTable(dev): {annotation}"),
                                column,
                                offset,
                                || value,
                            )?;
                        }

                        offset += 1;
                    }
                }

                let cmp_chip = ComparatorChip::construct(self.byte_offset_cmp.clone());
                offset = 0;

                // if there is a single table.
                if data.len() == 1 {
                    let byte_offset = data[0].byte_offset;
                    let n_rows = data[0].table_size;
                    for _ in 0..n_rows - 1 {
                        cmp_chip.assign(
                            &mut region,
                            offset,
                            F::from(byte_offset),
                            F::from(byte_offset),
                        )?;
                        offset += 1;
                    }
                    cmp_chip.assign(&mut region, offset, F::from(byte_offset), F::zero())?;
                }

                // if there are multiple tables.
                if data.len() > 1 {
                    for window in data.windows(2) {
                        let byte_offset_1 = window[0].byte_offset;
                        let byte_offset_2 = window[1].byte_offset;
                        let n_rows = window[0].table_size;
                        for _ in 0..n_rows - 1 {
                            cmp_chip.assign(
                                &mut region,
                                offset,
                                F::from(byte_offset_1),
                                F::from(byte_offset_1),
                            )?;
                            offset += 1;
                        }
                        cmp_chip.assign(
                            &mut region,
                            offset,
                            F::from(byte_offset_1),
                            F::from(byte_offset_2),
                        )?;
                        offset += 1;
                    }
                    // handle the last table.
                    if let Some(last_table) = data.last() {
                        let byte_offset = last_table.byte_offset;
                        let n_rows = last_table.table_size;
                        for _ in 0..n_rows - 1 {
                            cmp_chip.assign(
                                &mut region,
                                offset,
                                F::from(byte_offset),
                                F::from(byte_offset),
                            )?;
                            offset += 1;
                        }
                        cmp_chip.assign(&mut region, offset, F::from(byte_offset), F::zero())?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for FseTable<F> {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![self.byte_offset.into(), self.table_size.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![String::from("byte_offset"), String::from("table_size")]
    }
}

/// An auxiliary table used to ensure that the FSE table was reconstructed appropriately. Contrary
/// to the FseTable where the state is incremental, in the Auxiliary table we club together rows by
/// symbol. Which means, we will have rows with symbol s0 (and varying, but not necessarily
/// incremental states) clubbed together, followed by symbol s1 and so on.
///
/// | State | Symbol | Baseline | Nb  | Baseline Mark |
/// |-------|--------|----------|-----|---------------|
/// | 0x00  | s0     | ...      | ... | 0             |
/// | 0x01  | s0     | ...      | ... | 0             |
/// | 0x02  | s0     | ...      | ... | 0             |
/// | ...   | s0     | ...      | ... | ...           |
/// | 0x1d  | s0     | ...      | ... | 0             |
/// | 0x03  | s1  -> | 0x10     | ... | 0             |
/// | 0x0c  | s1  -> | 0x18     | ... | 0             |
/// | 0x11  | s1  -> | 0x00     | ... | 1             |
/// | 0x15  | s1  -> | 0x04     | ... | 1             |
/// | 0x1a  | s1  -> | 0x08     | ... | 1             |
/// | 0x1e  | s1  -> | 0x0c     | ... | 1             |
/// | 0x08  | s2     | ...      | ... | 0             |
/// | ...   | ...    | ...      | ... | 0             |
/// | 0x09  | s6     | ...      | ... | 0             |
///
/// Above is a representation of this table. Primarily we are interested in verifying that:
/// - next state (for the same symbol) was assigned correctly
/// - the number of times this symbol appears is assigned correctly
///
/// For more details, refer the [FSE reconstruction][doclink] section.
///
/// [doclink]: https://nigeltao.github.io/blog/2022/zstandard-part-5-fse.html#fse-reconstruction
#[derive(Clone, Debug)]
pub struct FseAuxiliaryTable<F> {
    /// Fixed column to denote whether the constraints will be enabled or not.
    pub q_enabled: Column<Fixed>,
    /// The byte offset within the data instance where the encoded FSE table begins. This is
    /// 1-indexed, i.e. byte_offset == 1 at the first byte.
    pub byte_offset: Column<Advice>,
    /// Helper gadget to know when we are done handling a single canonical Huffman code.
    pub byte_offset_cmp: ComparatorConfig<F, 8>,
    /// The size of the FSE table that starts at byte_offset.
    pub table_size: Column<Advice>,
    /// Helper column for (table_size >> 1).
    pub table_size_rs_1: Column<Advice>,
    /// Helper column for (table_size >> 3).
    pub table_size_rs_3: Column<Advice>,
    /// Incremental index.
    pub idx: Column<Advice>,
    /// The symbol (weight) assigned to this state.
    pub symbol: Column<Advice>,
    /// Helper gadget to know whether the symbol is the same or not.
    pub symbol_eq: IsEqualConfig<F>,
    /// Represents the number of times this symbol appears in the FSE table. This value does not
    /// change while the symbol in the table remains the same.
    pub symbol_count: Column<Advice>,
    /// An accumulator that resets to 1 each time we encounter a new symbol in the Auxiliary table
    /// and increments by 1 while the symbol remains the same. On the row where symbol' != symbol
    /// we have: symbol_count == symbol_count_acc.
    pub symbol_count_acc: Column<Advice>,
    /// The state in FSE. In the Auxiliary table, it does not increment by 1. Instead, it follows:
    /// - state'' == state   + table_size_rs_1 + table_size_rs_3 + 3
    /// - state'  == state'' & (table_size - 1)
    ///
    /// where state' is the next row's state.
    pub state: Column<Advice>,
    /// Denotes the baseline field.
    pub baseline: Column<Advice>,
    /// Helper column to mark the baseline observed at the last occurence of a symbol.
    pub last_baseline: Column<Advice>,
    /// The number of bits to be read from bitstream at this state.
    pub nb: Column<Advice>,
    /// The smaller power of two assigned to this state. The following must hold:
    /// - 2 ^ nb == SPoT.
    pub spot: Column<Advice>,
    /// An accumulator over SPoT value.
    pub spot_acc: Column<Advice>,
    /// Helper column to remember the smallest spot for that symbol.
    pub smallest_spot: Column<Advice>,
    /// Helper boolean column which is set only from baseline == 0x00.
    pub baseline_mark: Column<Advice>,
}

impl<F: Field> FseAuxiliaryTable<F> {
    pub fn construct(
        meta: &mut ConstraintSystem<F>,
        bitwise_op_table: BitwiseOpTable,
        pow2_table: Pow2Table,
        range_table: RangeTable<8>,
        u8_table: U8Table,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let byte_offset = meta.advice_column();
        let symbol = meta.advice_column();
        let spot = meta.advice_column();
        let smallest_spot = meta.advice_column();
        let table = Self {
            q_enabled,
            byte_offset,
            byte_offset_cmp: ComparatorChip::configure(
                meta,
                |meta| meta.query_fixed(q_enabled, Rotation::cur()),
                |meta| meta.query_advice(byte_offset, Rotation::cur()),
                |meta| meta.query_advice(byte_offset, Rotation::next()),
                u8_table.into(),
            ),
            table_size: meta.advice_column(),
            table_size_rs_1: meta.advice_column(),
            table_size_rs_3: meta.advice_column(),
            idx: meta.advice_column(),
            symbol,
            symbol_eq: IsEqualChip::configure(
                meta,
                |meta| meta.query_fixed(q_enabled, Rotation::cur()),
                |meta| meta.query_advice(symbol, Rotation::cur()),
                |meta| meta.query_advice(symbol, Rotation::next()),
            ),
            symbol_count: meta.advice_column(),
            symbol_count_acc: meta.advice_column(),
            state: meta.advice_column(),
            baseline: meta.advice_column(),
            last_baseline: meta.advice_column(),
            nb: meta.advice_column(),
            spot,
            spot_acc: meta.advice_column(),
            smallest_spot,
            baseline_mark: meta.advice_column(),
        };

        // All rows.
        meta.create_gate("FseAuxiliaryTable: all rows", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "baseline_mark == [0, 1]",
                meta.query_advice(table.baseline_mark, Rotation::cur()),
            );

            let (gt, eq) = table.byte_offset_cmp.expr(meta, None);
            cb.require_equal("byte offset is increasing", gt + eq, 1.expr());

            cb.gate(meta.query_fixed(table.q_enabled, Rotation::cur()))
        });

        // Validate SPoT assignment: all rows.
        meta.lookup_any("FseAuxiliaryTable: SPoT == 2 ^ Nb", |meta| {
            let condition = meta.query_fixed(table.q_enabled, Rotation::cur());

            [
                meta.query_advice(table.nb, Rotation::cur()),
                meta.query_advice(table.spot, Rotation::cur()),
            ]
            .into_iter()
            .zip(pow2_table.table_exprs(meta))
            .map(|(input, table)| (input * condition.clone(), table))
            .collect::<Vec<_>>()
        });

        // Constraints while traversing an FSE table.
        meta.create_gate("FseAuxiliaryTable: table size and helper columns", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Table size, and the right-shifted helper values remain unchanged.
            for col in [
                table.table_size,
                table.table_size_rs_1,
                table.table_size_rs_3,
            ] {
                cb.require_equal(
                    "while byte_offset' == byte_offset: table_size and helpers remain unchanged",
                    meta.query_advice(col, Rotation::next()),
                    meta.query_advice(col, Rotation::cur()),
                );
            }

            // Index is incremental.
            cb.require_equal(
                "idx' == idx + 1",
                meta.query_advice(table.idx, Rotation::next()),
                meta.query_advice(table.idx, Rotation::cur()) + 1.expr(),
            );

            cb.require_boolean(
                "symbol' == symbol or symbol' == symbol + 1",
                meta.query_advice(table.symbol, Rotation::next())
                    - meta.query_advice(table.symbol, Rotation::cur()),
            );

            let (_gt, eq) = table.byte_offset_cmp.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                eq,
            ]))
        });

        // Constraints for last row of an FSE table.
        meta.create_gate("FseAuxiliaryTable: table shift right ops", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Constraint for table_size >> 1.
            cb.require_boolean(
                "table_size >> 1",
                meta.query_advice(table.table_size, Rotation::cur())
                    - (meta.query_advice(table.table_size_rs_1, Rotation::cur()) * 2.expr()),
            );

            // Constraint for idx == table_size.
            cb.require_equal(
                "idx == table_size",
                meta.query_advice(table.idx, Rotation::cur()),
                meta.query_advice(table.table_size, Rotation::cur()),
            );

            let (gt, _eq) = table.byte_offset_cmp.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                gt,
            ]))
        });

        // Constraint for table_size >> 3. Only check on the last row.
        meta.lookup("FseAuxiliaryTable: table shift right ops", |meta| {
            let (gt, _eq) = table.byte_offset_cmp.expr(meta, None);
            let condition = and::expr([meta.query_fixed(q_enabled, Rotation::cur()), gt]);

            let range_value = meta.query_advice(table.table_size, Rotation::cur())
                - (meta.query_advice(table.table_size_rs_3, Rotation::cur()) * 8.expr());

            vec![(condition * range_value, range_table.into())]
        });

        // Constraint for state' calculation. We wish to constrain:
        //
        // - state' == state'' & (table_size - 1)
        // - state'' == state + (table_size >> 3) + (table_size >> 1) + 3
        meta.lookup_any("FseAuxiliaryTable: next state computation", |meta| {
            let (_gt, eq) = table.byte_offset_cmp.expr(meta, None);
            let condition = and::expr([meta.query_fixed(table.q_enabled, Rotation::cur()), eq]);

            let lhs = meta.query_advice(table.state, Rotation::cur())
                + meta.query_advice(table.table_size_rs_3, Rotation::cur())
                + meta.query_advice(table.table_size_rs_1, Rotation::cur())
                + 3.expr();
            let rhs = meta.query_advice(table.table_size, Rotation::cur()) - 1.expr();
            let output = meta.query_advice(table.state, Rotation::next());

            [BitwiseOp::AND.expr(), lhs, rhs, output]
                .into_iter()
                .zip(bitwise_op_table.table_exprs(meta))
                .map(|(input, table)| (input * condition.clone(), table))
                .collect::<Vec<_>>()
        });

        // Constraints for same FSE table and same symbol.
        meta.create_gate("FseAuxiliaryTable: symbol' == symbol", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Symbol's count remains unchanged while symbol remained unchanged.
            cb.require_equal(
                "if symbol' == symbol: symbol_count' == symbol_count",
                meta.query_advice(table.symbol_count, Rotation::next()),
                meta.query_advice(table.symbol_count, Rotation::cur()),
            );

            // SPoT at baseline == 0x00 remains unchanged over these rows.
            cb.require_equal(
                "if symbol' == symbol: smallest SPoT is unchanged",
                meta.query_advice(table.smallest_spot, Rotation::next()),
                meta.query_advice(table.smallest_spot, Rotation::cur()),
            );

            // last baseline remains unchanged over these rows.
            cb.require_equal(
                "if symbol' == symbol: last baseline is unchanged",
                meta.query_advice(table.last_baseline, Rotation::next()),
                meta.query_advice(table.last_baseline, Rotation::cur()),
            );

            // Symbol count accumulator increments.
            cb.require_equal(
                "if symbol' == symbol: symbol count accumulator increments",
                meta.query_advice(table.symbol_count_acc, Rotation::next()),
                meta.query_advice(table.symbol_count_acc, Rotation::cur()) + 1.expr(),
            );

            // SPoT accumulation.
            cb.require_equal(
                "SPoT_acc::next == SPoT_acc::cur + SPoT::next",
                meta.query_advice(table.spot_acc, Rotation::next()),
                meta.query_advice(table.spot_acc, Rotation::cur())
                    + meta.query_advice(table.spot, Rotation::next()),
            );

            // baseline_mark can only transition from 0 to 1 once.
            cb.require_boolean(
                "baseline_mark transition",
                meta.query_advice(table.baseline_mark, Rotation::next())
                    - meta.query_advice(table.baseline_mark, Rotation::cur()),
            );

            let is_next_baseline_0x00 = meta.query_advice(table.baseline_mark, Rotation::next())
                - meta.query_advice(table.baseline_mark, Rotation::cur());
            cb.condition(is_next_baseline_0x00.expr(), |cb| {
                cb.require_equal(
                    "baseline::next == 0x00",
                    meta.query_advice(table.baseline, Rotation::next()),
                    0x00.expr(),
                );
            });
            cb.condition(not::expr(is_next_baseline_0x00.expr()), |cb| {
                cb.require_equal(
                    "baseline::next == baseline::cur + spot::cur",
                    meta.query_advice(table.baseline, Rotation::next()),
                    meta.query_advice(table.baseline, Rotation::cur())
                        + meta.query_advice(table.spot, Rotation::cur()),
                );
            });

            let (_gt, eq) = table.byte_offset_cmp.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                eq,
                table.symbol_eq.expr(),
            ]))
        });

        // Constraints when symbol changes in an FSE table, i.e. symbol' != symbol.
        meta.create_gate("FseAuxiliaryTable: symbol' != symbol", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Constraint for idx == table_size.
            cb.require_equal(
                "symbol_count_acc == symbol_count",
                meta.query_advice(table.symbol_count_acc, Rotation::cur()),
                meta.query_advice(table.symbol_count, Rotation::cur()),
            );

            // SPoT accumulator == table_size at the end of processing the symbol.
            cb.require_equal(
                "SPoT_acc == table_size",
                meta.query_advice(table.spot_acc, Rotation::cur()),
                meta.query_advice(table.table_size, Rotation::cur()),
            );

            // The SPoT at baseline == 0x00 matches this SPoT.
            cb.require_equal(
                "last symbol occurrence => SPoT == SPoT at baseline 0x00",
                meta.query_advice(table.smallest_spot, Rotation::cur()),
                meta.query_advice(table.spot, Rotation::cur()),
            );

            // last baseline matches.
            cb.require_equal(
                "baseline == last_baseline",
                meta.query_advice(table.baseline, Rotation::cur()),
                meta.query_advice(table.last_baseline, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(q_enabled, Rotation::cur()),
                not::expr(table.symbol_eq.expr()),
            ]))
        });

        // Constraints for the first occurence of a particular symbol in the table.
        meta.create_gate("FseAuxiliaryTable: new symbol", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let is_baseline_marked = meta.query_advice(table.baseline_mark, Rotation::cur());
            cb.condition(is_baseline_marked.expr(), |cb| {
                cb.require_equal(
                    "baseline == 0x00",
                    meta.query_advice(table.baseline, Rotation::cur()),
                    0x00.expr(),
                );
            });

            cb.condition(not::expr(is_baseline_marked.expr()), |cb| {
                cb.require_equal(
                    "baseline == last_baseline + smallest_spot",
                    meta.query_advice(table.baseline, Rotation::cur()),
                    meta.query_advice(table.last_baseline, Rotation::cur())
                        + meta.query_advice(table.smallest_spot, Rotation::cur()),
                );
            });

            let symbol_prev = meta.query_advice(table.symbol, Rotation::prev());
            let symbol_cur = meta.query_advice(table.symbol, Rotation::cur());
            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                not::expr(
                    table
                        .symbol_eq
                        .expr_at(meta, Rotation::prev(), symbol_prev, symbol_cur),
                ),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        table
    }

    pub fn dev_load(
        &self,
        layouter: &mut impl Layouter<F>,
        data: Vec<FseAuxiliaryTableData>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "FseAuxiliaryTable: dev load",
            |mut region| {
                let mut offset = 0;
                for table in data.iter() {
                    let byte_offset = Value::known(F::from(table.byte_offset));
                    let table_size = Value::known(F::from(table.table_size));
                    let table_size_rs_1 = Value::known(F::from(table.table_size >> 1));
                    let table_size_rs_3 = Value::known(F::from(table.table_size >> 3));
                    for (&symbol, rows) in table.sym_to_states.iter() {
                        let symbol_count = rows.len() as u64;
                        let smallest_spot = rows
                            .iter()
                            .map(|fse_row| 1 << fse_row.num_bits)
                            .min()
                            .expect("symbol should have at least 1 row");
                        let spot_acc_iter = rows.iter().scan(0, |spot_acc, fse_row| {
                            *spot_acc += 1 << fse_row.num_bits;
                            Some(*spot_acc)
                        });
                        // TODO: byte_offset_cmp
                        // TODO: symbol_eq
                        // TODO: baseline_mark
                        // TODO: last_baseline
                        // TODO: q_enabled
                        for (i, (fse_row, spot_acc)) in rows.iter().zip(spot_acc_iter).enumerate() {
                            for (annotation, col, value) in [
                                ("byte_offset", self.byte_offset, byte_offset),
                                ("table_size", self.table_size, table_size),
                                ("table_size_rs_1", self.table_size_rs_1, table_size_rs_1),
                                ("table_size_rs_3", self.table_size_rs_3, table_size_rs_3),
                                ("symbol", self.symbol, Value::known(F::from(symbol as u64))),
                                (
                                    "symbol_count",
                                    self.symbol_count,
                                    Value::known(F::from(symbol_count)),
                                ),
                                (
                                    "symbol_count_acc",
                                    self.symbol_count_acc,
                                    Value::known(F::from(i as u64 + 1)),
                                ),
                                ("state", self.state, Value::known(F::from(fse_row.state))),
                                (
                                    "baseline",
                                    self.baseline,
                                    Value::known(F::from(fse_row.baseline)),
                                ),
                                ("nb", self.nb, Value::known(F::from(fse_row.num_bits))),
                                (
                                    "spot",
                                    self.spot,
                                    Value::known(F::from(1 << fse_row.num_bits)),
                                ),
                                (
                                    "smallest_spot",
                                    self.smallest_spot,
                                    Value::known(F::from(smallest_spot)),
                                ),
                                ("spot_acc", self.spot_acc, Value::known(F::from(spot_acc))),
                                ("idx", self.idx, Value::known(F::from(fse_row.idx))),
                            ] {
                                region.assign_advice(
                                    || format!("FseAuxiliaryTable: {}", annotation),
                                    col,
                                    offset,
                                    || value,
                                )?;
                            }
                            offset += 1;
                        }
                    }
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> FseAuxiliaryTable<F> {
    /// Lookup table expressions for (state, symbol) tuple check.
    pub fn table_exprs_state_check(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.byte_offset, Rotation::cur()),
            meta.query_advice(self.table_size, Rotation::cur()),
            meta.query_advice(self.state, Rotation::cur()),
            meta.query_advice(self.symbol, Rotation::cur()),
            meta.query_advice(self.baseline, Rotation::cur()),
            meta.query_advice(self.nb, Rotation::cur()),
        ]
    }

    /// Lookup table expressions for (symbol, symbol_count) tuple check.
    pub fn table_exprs_symbol_count_check(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.byte_offset, Rotation::cur()),
            meta.query_advice(self.table_size, Rotation::cur()),
            meta.query_advice(self.symbol, Rotation::cur()),
            meta.query_advice(self.symbol_count, Rotation::cur()),
            meta.query_advice(self.symbol_count_acc, Rotation::cur()),
        ]
    }
}

/// The Huffman codes table maps the canonical weights (symbols as per FseTable) to the Huffman
/// codes.
#[derive(Clone, Debug)]
pub struct HuffmanCodesTable<F> {
    /// Fixed column to denote whether the constraints will be enabled or not.
    pub q_enabled: Column<Fixed>,
    /// Fixed column to mark the first row in the table.
    pub q_first: Column<Fixed>,
    /// The byte offset within the data instance where the encoded FSE table begins. This is
    /// 1-indexed, i.e. byte_offset == 1 at the first byte.
    pub byte_offset: Column<Advice>,
    /// Helper gadget to know when we are done handling a single canonical Huffman code.
    pub byte_offset_cmp: ComparatorConfig<F, 8>,
    /// The byte that is being encoded by a Huffman code.
    pub symbol: Column<Advice>,
    /// The weight assigned to this symbol as per the canonical Huffman code weights.
    pub weight: Column<Advice>,
    /// A binary representation of the weight's value.
    pub weight_bits: BinaryNumberConfig<FseSymbol, N_BITS_SYMBOL>,
    /// An accumulator over the weight values.
    pub weight_acc: Column<Advice>,
    /// Helper column to denote 2 ^ (weight - 1).
    pub pow2_weight: Column<Advice>,
    /// The sum of canonical Huffman code weights. This value does not change over the rows for a
    /// specific Huffman code.
    pub sum_weights: Column<Advice>,
    /// The maximum length of a bitstring as per this Huffman code. Again, this value does not
    /// change over the rows for a specific Huffman code.
    pub max_bitstring_len: Column<Advice>,
    /// As per Huffman coding, every symbol is mapped to a bit value, which is then represented in
    /// binary form (padded) of length bitstring_len.
    pub bit_value: Column<Advice>,
    /// The last seen bit_value for each symbol in this Huffman coding.
    pub last_bit_values: [Column<Advice>; N_MAX_SYMBOLS],
    /// The last_bit_values assigned at the first row of a table.
    pub first_lbvs: [Column<Advice>; N_MAX_SYMBOLS],
}

impl<F: Field> HuffmanCodesTable<F> {
    pub fn construct(
        meta: &mut ConstraintSystem<F>,
        pow2_table: Pow2Table,
        u8_table: U8Table,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let byte_offset = meta.advice_column();
        let weight = meta.advice_column();
        let table = Self {
            q_enabled,
            q_first: meta.fixed_column(),
            byte_offset,
            byte_offset_cmp: ComparatorChip::configure(
                meta,
                |meta| meta.query_fixed(q_enabled, Rotation::cur()),
                |meta| meta.query_advice(byte_offset, Rotation::cur()),
                |meta| meta.query_advice(byte_offset, Rotation::next()),
                u8_table.into(),
            ),
            symbol: meta.advice_column(),
            weight,
            weight_bits: BinaryNumberChip::configure(meta, q_enabled, Some(weight.into())),
            pow2_weight: meta.advice_column(),
            weight_acc: meta.advice_column(),
            sum_weights: meta.advice_column(),
            max_bitstring_len: meta.advice_column(),
            bit_value: meta.advice_column(),
            last_bit_values: array_init(|_| meta.advice_column()),
            first_lbvs: array_init(|_| meta.advice_column()),
        };

        // All rows
        meta.create_gate("HuffmanCodesTable: all rows", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let (gt, eq) = table.byte_offset_cmp.expr(meta, None);
            cb.require_equal("byte_offset' >= byte_offset", gt + eq, 1.expr());

            // Weight == 0 implies the bit value is 0.
            cb.condition(
                table
                    .weight_bits
                    .value_equals(FseSymbol::S0, Rotation::cur())(meta),
                |cb| {
                    cb.require_zero(
                        "bit value == 0",
                        meta.query_advice(table.bit_value, Rotation::cur()),
                    );
                },
            );

            // Last bit value at weight == 0 is also 0.
            cb.require_zero(
                "last_bit_values[0] == 0",
                meta.query_advice(
                    table.last_bit_values[FseSymbol::S0 as usize],
                    Rotation::cur(),
                ),
            );

            cb.gate(meta.query_fixed(table.q_enabled, Rotation::cur()))
        });

        // The first row of the HuffmanCodesTable.
        meta.create_gate("HuffmanCodesTable: first (fixed) row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Canonical Huffman code starts with the weight of the first symbol, i.e. 0x00.
            cb.require_equal(
                "symbol == 0x00",
                meta.query_advice(table.symbol, Rotation::cur()),
                0x00.expr(),
            );

            // Weight accumulation starts with the first weight.
            cb.require_equal(
                "weight_acc == 2^(weight - 1)",
                meta.query_advice(table.weight_acc, Rotation::cur()),
                meta.query_advice(table.pow2_weight, Rotation::cur()),
            );

            // Constrain the last bit_value of the maximum bitstring length. Maximum bitstring
            // length implies weight == 1.
            cb.require_zero(
                "if first row: last_bit_values[1] == 0",
                meta.query_advice(
                    table.last_bit_values[FseSymbol::S1 as usize],
                    Rotation::cur(),
                ),
            );

            // Do an equality check for the last_bit_values at the first row.
            for i in FseSymbol::iter() {
                cb.require_equal(
                    "last bit value at the first row equality check",
                    meta.query_advice(table.last_bit_values[i as usize], Rotation::cur()),
                    meta.query_advice(table.first_lbvs[i as usize], Rotation::cur()),
                );
            }

            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                meta.query_fixed(table.q_first, Rotation::cur()),
            ]))
        });

        // While we are processing the weights of a particular canonical Huffman code
        // representation, i.e. byte_offset == byte_offset'.
        meta.create_gate(
            "HuffmanCodesTable: traversing a canonical huffman coding table",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // Sum of weights remains the same across all rows.
                cb.require_equal(
                    "sum_weights' == sum_weights",
                    meta.query_advice(table.sum_weights, Rotation::next()),
                    meta.query_advice(table.sum_weights, Rotation::cur()),
                );

                // Maximum bitstring length remains the same across all rows.
                cb.require_equal(
                    "max_bitstring_len' == max_bitstring_len",
                    meta.query_advice(table.max_bitstring_len, Rotation::next()),
                    meta.query_advice(table.max_bitstring_len, Rotation::cur()),
                );

                // The first row's last_bit_values remain the same.
                for col in table.first_lbvs {
                    cb.require_equal(
                        "first_lbvs[i]' == first_lbvs[i]",
                        meta.query_advice(col, Rotation::next()),
                        meta.query_advice(col, Rotation::cur()),
                    );
                }

                // Weight accumulation is assigned correctly.
                cb.require_equal(
                    "weight_acc' == weight_acc + 2^(weight - 1)",
                    meta.query_advice(table.weight_acc, Rotation::next()),
                    meta.query_advice(table.weight_acc, Rotation::cur())
                        + meta.query_advice(table.pow2_weight, Rotation::next()),
                );

                // pow2_weight is assigned correctly for weight == 0.
                cb.condition(
                    table
                        .weight_bits
                        .value_equals(FseSymbol::S0, Rotation::cur())(meta),
                    |cb| {
                        cb.require_zero(
                            "pow2_weight == 0 if weight == 0",
                            meta.query_advice(table.pow2_weight, Rotation::cur()),
                        );
                    },
                );

                // For all rows (except the first row of a canonical Huffman code representation, we
                // want to ensure the last_bit_values was assigned correctly.
                let (_gt, is_not_first) = table.byte_offset_cmp.expr(meta, Some(Rotation::prev()));
                cb.condition(is_not_first, |cb| {
                    for (symbol, &last_bit_value) in
                        FseSymbol::iter().zip(table.last_bit_values.iter())
                    {
                        cb.require_equal(
                            "last_bit_value_i::cur == last_bit_value::prev + (weight::cur == i)",
                            meta.query_advice(last_bit_value, Rotation::cur()),
                            meta.query_advice(last_bit_value, Rotation::prev())
                                + table.weight_bits.value_equals(symbol, Rotation::cur())(meta),
                        );
                    }
                });

                let (_gt, eq) = table.byte_offset_cmp.expr(meta, None);
                cb.gate(and::expr([
                    meta.query_fixed(table.q_enabled, Rotation::cur()),
                    eq,
                ]))
            },
        );

        // For every row, we want the pow2_weight column to be assigned correctly. We want:
        //
        // pow2_weight == 2^(weight - 1).
        //
        // Note that this is valid only if weight > 0. For weight == 0, we want pow2_weight == 0.
        meta.lookup_any("HuffmanCodesTable: pow2_weight assignment", |meta| {
            let condition = and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                not::expr(table
                    .weight_bits
                    .value_equals(FseSymbol::S0, Rotation::cur())(
                    meta
                )),
                // TODO: add padding column.
            ]);

            let exponent = meta.query_advice(table.weight, Rotation::cur()) - 1.expr();
            let exponentiation = meta.query_advice(table.pow2_weight, Rotation::cur());

            [exponent, exponentiation]
                .into_iter()
                .zip(pow2_table.table_exprs(meta))
                .map(|(input, table)| (input * condition.clone(), table))
                .collect::<Vec<_>>()
        });

        // When we end processing a huffman code, i.e. the byte_offset changes. No need to check if
        // the next row is padding or not.
        meta.create_gate("HuffmanCodesTable: end of huffman code", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // The total sum of weights is in fact the accumulated weight.
            cb.require_equal(
                "sum_weights == weight_acc",
                meta.query_advice(table.sum_weights, Rotation::cur()),
                meta.query_advice(table.weight_acc, Rotation::cur()),
            );

            // We want to check the following:
            //
            // if lbv_1: The last bit_value for weight i on the first row.
            // if lbv_2: The last bit_value for weight i+1 on the last row.
            //
            // then lbv_2 == (lbv_1 + 1) // 2
            // i.e. lbv_2 * 2 - lbv_1 is boolean.
            //
            // Note: we only do this check for weight > 0, hence we skip the FseSymbol::S0.
            for i in FseSymbol::iter().skip(1) {
                let i = i as usize;
                let lbv_1 = meta.query_advice(table.first_lbvs[i], Rotation::cur());
                let lbv_2 = meta.query_advice(table.last_bit_values[i + 1], Rotation::cur());
                cb.require_boolean(
                    "last bit value check for weights i and i+1 on the first and last rows",
                    lbv_2 * 2.expr() - lbv_1,
                );
            }

            let (gt, _eq) = table.byte_offset_cmp.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                gt,
            ]))
        });

        // The weight for the last symbol is assigned appropriately. The weight for the last
        // symbol should satisfy:
        //
        // last_weight == log2(nearest_pow2 - sum_weights) + 1
        // where nearest_pow2 is the nearest power of 2 greater than the sum of weights so far.
        //
        // i.e. 2^(last_weight - 1) + sum_weights == 2^(max_bitstring_len)
        meta.lookup_any("HuffmanCodesTable: weight of the last symbol", |meta| {
            let (gt, _eq) = table.byte_offset_cmp.expr(meta, None);
            let condition = and::expr([meta.query_fixed(table.q_enabled, Rotation::cur()), gt]);

            let exponent = meta.query_advice(table.max_bitstring_len, Rotation::cur());
            let exponentiation = meta.query_advice(table.pow2_weight, Rotation::cur())
                + meta.query_advice(table.sum_weights, Rotation::prev());

            [exponent, exponentiation]
                .into_iter()
                .zip(pow2_table.table_exprs(meta))
                .map(|(input, table)| (input * condition.clone(), table))
                .collect::<Vec<_>>()
        });

        // When we transition from one Huffman code to another, i.e. the byte_offset changes. We
        // also check that the next row is not a padding row.
        //
        // TODO: add the padding column.
        meta.create_gate("HuffmanCodesTable: new huffman code", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Canonical Huffman code starts with the weight of the first symbol, i.e. 0x00.
            cb.require_equal(
                "symbol == 0x00",
                meta.query_advice(table.symbol, Rotation::next()),
                0x00.expr(),
            );

            // Weight accumulation starts with the first weight.
            cb.require_equal(
                "weight_acc == 2^(weight - 1)",
                meta.query_advice(table.weight_acc, Rotation::next()),
                meta.query_advice(table.pow2_weight, Rotation::next()),
            );

            // Constrain the last bit_value of the maximum bitstring length. Maximum bitstring
            // length implies weight == 1.
            cb.require_zero(
                "if first row: last_bit_values[1] == 0",
                meta.query_advice(
                    table.last_bit_values[FseSymbol::S1 as usize],
                    Rotation::next(),
                ),
            );

            // Do an equality check for the last_bit_values at the first row.
            for i in FseSymbol::iter() {
                cb.require_equal(
                    "last bit value at the first row equality check",
                    meta.query_advice(table.last_bit_values[i as usize], Rotation::next()),
                    meta.query_advice(table.first_lbvs[i as usize], Rotation::next()),
                );
            }

            let (gt, _eq) = table.byte_offset_cmp.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                meta.query_fixed(table.q_enabled, Rotation::next()),
                gt,
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        table
    }

    pub fn dev_load(
        &self,
        layouter: &mut impl Layouter<F>,
        data: Vec<HuffmanCodesData>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "HuffmanCodesTable: dev load",
            |mut region| {
                let weight_bits = BinaryNumberChip::construct(self.weight_bits);
                let mut offset = 0;
                for code in data.iter() {
                    let byte_offset = Value::known(F::from(code.byte_offset));
                    let (max_bitstring_len, sym_map) = code.parse_canonical();
                    let max_bitstring_len = Value::known(F::from(max_bitstring_len));
                    let sum_weights = Value::known(F::from(
                        sym_map
                            .values()
                            .map(|(weight, _bit_value)| weight)
                            .sum::<u64>(),
                    ));
                    let weight_acc_iter = sym_map.values().scan(0, |acc, (weight, _bit_value)| {
                        *acc += weight;
                        Some(*acc)
                    });

                    for (i, weight_acc) in weight_acc_iter.enumerate() {
                        region.assign_advice(
                            || "HuffmanCodesTable: weight_acc",
                            self.weight_acc,
                            offset + i,
                            || Value::known(F::from(weight_acc)),
                        )?;
                    }
                    for (&symbol, &(weight, bit_value)) in sym_map.iter() {
                        for (annotation, column, value) in [
                            ("byte_offset", self.byte_offset, byte_offset),
                            (
                                "max_bitstring_len",
                                self.max_bitstring_len,
                                max_bitstring_len,
                            ),
                            ("sum_weights", self.sum_weights, sum_weights),
                            ("symbol", self.symbol, Value::known(F::from(symbol))),
                            ("weight", self.weight, Value::known(F::from(weight))),
                            (
                                "bit_value",
                                self.bit_value,
                                Value::known(F::from(bit_value)),
                            ),
                            (
                                "pow2_weight",
                                self.pow2_weight,
                                Value::known(F::from(if weight > 0 {
                                    (weight - 1).pow(2)
                                } else {
                                    0
                                })),
                            ),
                        ] {
                            region.assign_advice(
                                || format!("HuffmanCodesTable: {annotation}"),
                                column,
                                offset,
                                || value,
                            )?;
                        }
                        let fse_symbol: FseSymbol = (weight as usize).into();
                        weight_bits.assign(&mut region, offset, &fse_symbol)?;

                        offset += 1;
                    }

                    // TODO: assign last_bit_values
                }

                // Assign the byte offset comparison gadget.
                let cmp_chip = ComparatorChip::construct(self.byte_offset_cmp.clone());
                offset = 0;

                // if there is a single table.
                if data.len() == 1 {
                    let byte_offset = data[0].byte_offset;
                    let n_rows = data[0].weights.len() + 1;
                    for _ in 0..n_rows - 1 {
                        cmp_chip.assign(
                            &mut region,
                            offset,
                            F::from(byte_offset),
                            F::from(byte_offset),
                        )?;
                        offset += 1;
                    }
                    cmp_chip.assign(&mut region, offset, F::from(byte_offset), F::zero())?;
                }

                // if there are multiple tables.
                if data.len() > 1 {
                    for window in data.windows(2) {
                        let byte_offset_1 = window[0].byte_offset;
                        let byte_offset_2 = window[1].byte_offset;
                        let n_rows = window[0].weights.len() + 1;
                        for _ in 0..n_rows - 1 {
                            cmp_chip.assign(
                                &mut region,
                                offset,
                                F::from(byte_offset_1),
                                F::from(byte_offset_1),
                            )?;
                            offset += 1;
                        }
                        cmp_chip.assign(
                            &mut region,
                            offset,
                            F::from(byte_offset_1),
                            F::from(byte_offset_2),
                        )?;
                        offset += 1;
                    }
                    // handle the last table.
                    if let Some(last_table) = data.last() {
                        let byte_offset = last_table.byte_offset;
                        let n_rows = last_table.weights.len() + 1;
                        for _ in 0..n_rows - 1 {
                            cmp_chip.assign(
                                &mut region,
                                offset,
                                F::from(byte_offset),
                                F::from(byte_offset),
                            )?;
                            offset += 1;
                        }
                        cmp_chip.assign(&mut region, offset, F::from(byte_offset), F::zero())?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for HuffmanCodesTable<F> {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.byte_offset.into(),
            self.symbol.into(),
            self.weight.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("byte_offset"),
            String::from("symbol"),
            String::from("weight"),
        ]
    }
}

/// An auxiliary table for the Huffman Codes. In Huffman coding a symbol (byte) is mapped to a
/// bitstring of particular length such that more frequently occuring symbols are mapped to
/// bitstrings of smaller lengths.
///
/// We already have the symbols and their bit_value in the HuffmanCodesTable. However, we still
/// need to validate that the bit_value is in fact assigned correctly. Since bitstrings may not be
/// byte-aligned, i.e. a bitstring can span over 2 bytes (assuming a maximum bitstring length of 8)
/// we need to make sure that the bit_value is in fact the binary value represented by the bits of
/// that bitstring.
#[derive(Clone, Debug)]
pub struct HuffmanCodesBitstringAccumulationTable {
    /// Fixed column to denote whether the constraints will be enabled or not.
    pub q_enabled: Column<Fixed>,
    /// The byte offset within the data instance where the encoded FSE table begins. This is
    /// 1-indexed, i.e. byte_offset == 1 at the first byte.
    pub byte_offset: Column<Advice>,
    /// The byte offset of byte_1 in the zstd encoded data. byte_idx' == byte_idx
    /// while 0 <= bit_index < 15. At bit_index == 15, byte_idx' == byte_idx + 1.
    pub byte_idx_1: Column<Advice>,
    /// The byte offset of byte_2 in the zstd encoded data. byte_idx' == byte_idx
    /// while 0 <= bit_index < 15. At bit_index == 15, byte_idx' == byte_idx + 1.
    ///
    /// We also have byte_idx_2 == byte_idx_1 + 1.
    pub byte_idx_2: Column<Advice>,
    /// The byte value at byte_idx_1.
    pub byte_1: Column<Advice>,
    /// The byte value at byte_idx_2.
    pub byte_2: Column<Advice>,
    /// The index within these 2 bytes, i.e. 0 <= bit_index <= 15. bit_index increments until its
    /// 15 and then is reset to 0. Repeats while we finish bitstring accumulation of all bitstrings
    /// used in the Huffman codes.
    pub bit_index: Column<Fixed>,
    /// Helper column to know the start of a new chunk of 2 bytes, this is a fixed column as well
    /// as it is set only on bit_index == 0.
    pub q_first: Column<Fixed>,
    /// Helper column that is set if bit_index < 8.
    pub q_bit_index_lo: Column<Fixed>,
    /// The bit at bit_index. Accumulation of bits from 0 <= bit_index <= 7 denotes byte_1.
    /// Accumulation of 8 <= bit_index <= 15 denotes byte_2.
    pub bit: Column<Advice>,
    /// The accumulator over 0 <= bit_index <= 7.
    pub bit_value_acc_1: Column<Advice>,
    /// The accumulator over 8 <= bit_index <= 15.
    pub bit_value_acc_2: Column<Advice>,
    /// The final value of the bit accumulation for the set bits.
    pub bit_value: Column<Advice>,
    /// The length of the bitstring, i.e. the number of bits that were set.
    pub bitstring_len: Column<Advice>,
    /// The accumulator over bits from is_start to is_end, i.e. while is_set == 1.
    pub bit_value_acc: Column<Advice>,
    /// Boolean that is set from start of bit chunk to bit_index == 15.
    pub from_start: Column<Advice>,
    /// Boolean that is set from bit_index == 0 to end of bit chunk.
    pub until_end: Column<Advice>,
}

impl HuffmanCodesBitstringAccumulationTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let q_enabled = meta.fixed_column();
        let table = Self {
            q_enabled,
            byte_offset: meta.advice_column(),
            byte_idx_1: meta.advice_column(),
            byte_idx_2: meta.advice_column(),
            byte_1: meta.advice_column(),
            byte_2: meta.advice_column(),
            bit_index: meta.fixed_column(),
            q_first: meta.fixed_column(),
            q_bit_index_lo: meta.fixed_column(),
            bit: meta.advice_column(),
            bit_value_acc_1: meta.advice_column(),
            bit_value_acc_2: meta.advice_column(),
            bit_value: meta.advice_column(),
            bitstring_len: meta.advice_column(),
            bit_value_acc: meta.advice_column(),
            from_start: meta.advice_column(),
            until_end: meta.advice_column(),
        };

        meta.create_gate(
            "HuffmanCodesBitstringAccumulationTable: bit accumulation",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                let q_bit_idx_lo = meta.query_fixed(table.q_bit_index_lo, Rotation::cur());

                let is_first = meta.query_fixed(table.q_first, Rotation::cur());
                let is_lo_bit_idx = and::expr([not::expr(is_first.expr()), q_bit_idx_lo.expr()]);
                let is_hi_bit_idx = not::expr(q_bit_idx_lo);
                let is_bit_idx_eq_8 = and::expr([
                    meta.query_fixed(table.q_bit_index_lo, Rotation::prev()),
                    is_hi_bit_idx.expr(),
                ]);
                let is_last = meta.query_fixed(table.q_first, Rotation::next());

                // Constrain bit_value_acc's for bit_index == 0.
                cb.condition(is_first.expr(), |cb| {
                    cb.require_equal(
                        "if q_first == True: bit_value_acc_1 == bit",
                        meta.query_advice(table.bit_value_acc_1, Rotation::cur()),
                        meta.query_advice(table.bit, Rotation::cur()),
                    );
                    cb.require_equal(
                        "if q_first == True: bit_value_acc_2 == 0",
                        meta.query_advice(table.bit_value_acc_2, Rotation::cur()),
                        0.expr(),
                    );
                });

                // Constrain bit_value_acc's for 1 <= bit_index < 8.
                cb.condition(is_lo_bit_idx, |cb| {
                    cb.require_equal(
                        "if bit_index < 8: bit_value_acc_1 check",
                        meta.query_advice(table.bit_value_acc_1, Rotation::cur()),
                        meta.query_advice(table.bit_value_acc_1, Rotation::prev()) * 2.expr()
                            + meta.query_advice(table.bit, Rotation::cur()),
                    );
                    cb.require_equal(
                        "if bit_index < 8: bit_value_acc_2 check",
                        meta.query_advice(table.bit_value_acc_2, Rotation::cur()),
                        0.expr(),
                    );
                });

                // Constrain bit_value_acc's for bit_index >= 8.
                cb.condition(is_hi_bit_idx, |cb| {
                    cb.require_equal(
                        "if bit_index >= 8: bit_value_acc_1 eq",
                        meta.query_advice(table.bit_value_acc_1, Rotation::cur()),
                        meta.query_advice(table.bit_value_acc_1, Rotation::prev()),
                    );
                    cb.require_equal(
                        "if bit_index >= 8: bit_value_acc_2 check",
                        meta.query_advice(table.bit_value_acc_2, Rotation::cur()),
                        meta.query_advice(table.bit_value_acc_2, Rotation::prev()) * 2.expr()
                            + meta.query_advice(table.bit, Rotation::cur()),
                    );
                });

                // Constrain columns that are unchanged from 0 <= bit_idx <= 15.
                cb.condition(not::expr(is_first), |cb| {
                    for col in [table.byte_1, table.byte_2, table.bit_value] {
                        cb.require_equal(
                            "unchanged columns from 0 <= bit_idx <= 15",
                            meta.query_advice(col, Rotation::cur()),
                            meta.query_advice(col, Rotation::prev()),
                        );
                    }
                });

                // byte_1 is the accumulation of bit_value_acc_1.
                cb.condition(is_bit_idx_eq_8, |cb| {
                    cb.require_equal(
                        "if bit_index == 8: byte_1 == bit_value_acc_1",
                        meta.query_advice(table.byte_1, Rotation::cur()),
                        meta.query_advice(table.bit_value_acc_1, Rotation::cur()),
                    );
                });

                // byte_2 is the accumulation of bit_value_acc_2.
                cb.condition(is_last, |cb| {
                    cb.require_equal(
                        "if bit_index == 15: byte_2 == bit_value_acc_2",
                        meta.query_advice(table.byte_2, Rotation::cur()),
                        meta.query_advice(table.bit_value_acc_2, Rotation::cur()),
                    );
                });

                cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
            },
        );

        // Consider a bit chunk from bit_index == 4 to bit_index == 9. We will have:
        //
        // | bit index | from start | until end | bitstring len | bit | bit value acc |
        // |-----------|------------|-----------|---------------|-----|---------------|
        // | 0         | 1          | 0         | 0             | 0   | 0             |
        // | 1         | 1          | 0         | 0             | 0   | 0             |
        // | 2         | 1          | 0         | 0             | 1   | 0             |
        // | 3         | 1          | 0         | 0             | 0   | 0             |
        // | 4      -> | 1          | 1         | 1             | 1   | 1             |
        // | 5      -> | 1          | 1         | 2             | 0   | 1             |
        // | 6      -> | 1          | 1         | 3             | 1   | 5             |
        // | 7      -> | 1          | 1         | 4             | 1   | 13            |
        // | 8      -> | 1          | 1         | 5             | 0   | 13            |
        // | 9      -> | 1          | 1         | 6             | 1   | 45            |
        // | 10        | 0          | 1         | 6             | 0   | 45            |
        // | 11        | 0          | 1         | 6             | 0   | 45            |
        // | 12        | 0          | 1         | 6             | 0   | 45            |
        // | 13        | 0          | 1         | 6             | 1   | 45            |
        // | 14        | 0          | 1         | 6             | 1   | 45            |
        // | 15        | 0          | 1         | 6             | 0   | 45            |
        //
        // The bits for the bitstring are where from_start == until_end == 1.
        meta.create_gate(
            "HuffmanCodesBitstringAccumulationTable: bit value",
            |meta| {
                let mut cb = BaseConstraintBuilder::default();

                // Columns from_start and until_end are boolean.
                cb.require_boolean(
                    "from_start is boolean",
                    meta.query_advice(table.from_start, Rotation::cur()),
                );
                cb.require_boolean(
                    "until_end is boolean",
                    meta.query_advice(table.until_end, Rotation::cur()),
                );

                // Column from_start transitions from 1 to 0 only once.
                let is_first = meta.query_fixed(table.q_first, Rotation::cur());
                cb.condition(is_first.expr(), |cb| {
                    cb.require_equal(
                        "if q_first == True: from_start == 1",
                        meta.query_advice(table.from_start, Rotation::cur()),
                        1.expr(),
                    );
                });
                cb.condition(not::expr(is_first.expr()), |cb| {
                    cb.require_boolean(
                        "from_start transitions from 1 to 0 only once",
                        meta.query_advice(table.from_start, Rotation::prev())
                            - meta.query_advice(table.from_start, Rotation::cur()),
                    );
                });

                // Column until_end transitions from 0 to 1 only once.
                let is_last = meta.query_fixed(table.q_first, Rotation::next());
                cb.condition(is_last.expr(), |cb| {
                    cb.require_equal(
                        "if q_first::next == True: until_end == 1",
                        meta.query_advice(table.until_end, Rotation::cur()),
                        1.expr(),
                    );
                });
                cb.condition(not::expr(is_last.expr()), |cb| {
                    cb.require_boolean(
                        "until_end transitions from 0 to 1 only once",
                        meta.query_advice(table.until_end, Rotation::next())
                            - meta.query_advice(table.until_end, Rotation::cur()),
                    );
                });

                // Constraints at meaningful bits.
                let is_set = and::expr([
                    meta.query_advice(table.from_start, Rotation::cur()),
                    meta.query_advice(table.until_end, Rotation::cur()),
                ]);
                cb.condition(is_first.expr() * is_set.expr(), |cb| {
                    cb.require_equal(
                        "if is_first && is_set: bit == bit_value_acc",
                        meta.query_advice(table.bit, Rotation::cur()),
                        meta.query_advice(table.bit_value_acc, Rotation::cur()),
                    );
                    cb.require_equal(
                        "if is_first && is_set: bitstring_len == 1",
                        meta.query_advice(table.bitstring_len, Rotation::cur()),
                        1.expr(),
                    );
                });
                cb.condition(not::expr(is_first) * is_set, |cb| {
                    cb.require_equal(
                        "is_set: bit_value_acc == bit_value_acc::prev * 2 + bit",
                        meta.query_advice(table.bit_value_acc, Rotation::cur()),
                        meta.query_advice(table.bit_value_acc, Rotation::prev()) * 2.expr()
                            + meta.query_advice(table.bit, Rotation::cur()),
                    );
                    cb.require_equal(
                        "is_set: bitstring_len == bitstring_len::prev + 1",
                        meta.query_advice(table.bitstring_len, Rotation::cur()),
                        meta.query_advice(table.bitstring_len, Rotation::prev()) + 1.expr(),
                    );
                });

                // Constraints at bits to be ignored (at the start).
                let is_ignored = not::expr(meta.query_advice(table.until_end, Rotation::cur()));
                cb.condition(is_ignored, |cb| {
                    cb.require_zero(
                        "while until_end == 0: bitstring_len == 0",
                        meta.query_advice(table.bitstring_len, Rotation::cur()),
                    );
                    cb.require_zero(
                        "while until_end == 0: bit_value_acc == 0",
                        meta.query_advice(table.bit_value_acc, Rotation::cur()),
                    );
                });

                // Constraints at bits to be ignored (towards the end).
                let is_ignored = not::expr(meta.query_advice(table.from_start, Rotation::cur()));
                cb.condition(is_ignored, |cb| {
                    cb.require_equal(
                        "bitstring_len unchanged at the last ignored bits",
                        meta.query_advice(table.bitstring_len, Rotation::cur()),
                        meta.query_advice(table.bitstring_len, Rotation::prev()),
                    );
                    cb.require_equal(
                        "bit_value_acc unchanged at the last ignored bits",
                        meta.query_advice(table.bit_value_acc, Rotation::cur()),
                        meta.query_advice(table.bit_value_acc, Rotation::prev()),
                    );
                });

                cb.gate(meta.query_fixed(table.q_enabled, Rotation::cur()))
            },
        );

        debug_assert!(meta.degree() <= 9);

        table
    }

    pub fn dev_load<F: Field>(&self, _layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

impl HuffmanCodesBitstringAccumulationTable {
    /// Lookup table expressions for a bitsteam completely contained within the bits of a single
    /// byte in the encoded data.
    pub fn table_exprs_contained<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
    ) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.byte_offset, Rotation::cur()),
            meta.query_advice(self.byte_idx_1, Rotation::cur()),
            meta.query_advice(self.byte_1, Rotation::cur()),
            meta.query_advice(self.bit_value, Rotation::cur()),
            meta.query_advice(self.bitstring_len, Rotation::cur()),
            meta.query_fixed(self.bit_index, Rotation::cur()),
            meta.query_advice(self.from_start, Rotation::cur()),
            meta.query_advice(self.until_end, Rotation::cur()),
        ]
    }

    /// Lookup table expressions for a bitstream that spans over 2 consequtive bytes in the
    /// encoded data.
    pub fn table_exprs_spanned<F: Field>(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.byte_offset, Rotation::cur()),
            meta.query_advice(self.byte_idx_1, Rotation::cur()),
            meta.query_advice(self.byte_idx_2, Rotation::cur()),
            meta.query_advice(self.byte_1, Rotation::cur()),
            meta.query_advice(self.byte_2, Rotation::cur()),
            meta.query_advice(self.bit_value, Rotation::cur()),
            meta.query_advice(self.bitstring_len, Rotation::cur()),
            meta.query_fixed(self.bit_index, Rotation::cur()),
            meta.query_advice(self.from_start, Rotation::cur()),
            meta.query_advice(self.until_end, Rotation::cur()),
        ]
    }
}
