use eth_types::Field;
use gadgets::{
    comparator::{ComparatorChip, ComparatorConfig},
    is_equal::{IsEqualChip, IsEqualConfig},
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{BitwiseOp, BitwiseOpTable, LookupTable, Pow2Table, RangeTable},
    witness::FseAuxiliaryTableData,
};

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

impl<F: Field> FseTable<F> {
    /// Construct the auxiliary table for FSE codes.
    pub fn construct(
        meta: &mut ConstraintSystem<F>,
        bitwise_op_table: BitwiseOpTable,
        pow2_table: Pow2Table,
        range8: RangeTable<8>,
        range256: RangeTable<256>,
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
                range256.into(),
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

            vec![(condition * range_value, range8.into())]
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

    /// Load witness.
    pub fn assign(
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

impl<F: Field> FseTable<F> {
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
        ]
    }
}
