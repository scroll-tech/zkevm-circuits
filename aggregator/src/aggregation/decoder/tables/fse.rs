use gadgets::{
    comparator::{ComparatorChip, ComparatorConfig},
    is_equal::{IsEqualChip, IsEqualConfig},
    util::{and, not, select, Expr},
};
use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{BitwiseOp, BitwiseOpTable, LookupTable, Pow2Table, RangeTable, U8Table},
};

use crate::aggregation::decoder::tables::rom_fse_order::{FseTableKind, RomFseTableTransition};

/// An auxiliary table used to ensure that the FSE table was reconstructed appropriately. Contrary
/// to the FseTable where the state is incremental, in the Auxiliary table we club together rows by
/// symbol. Which means, we will have rows with symbol s0 (and varying, but not necessarily
/// incremental states) clubbed together, followed by symbol s1 and so on.
///
/// | State | Symbol | Baseline | Nb  | Baseline Mark |
/// |-------|--------|----------|-----|---------------|
/// | 0x00  | s0     | ...      | ... | 0             | <- q_start
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
/// | 0x00  | 0      | 0        | 0   | 0             | <- is_padding
/// | ...   | ...    | ...      | ... | ...           | <- is_padding
/// | 0x00  | 0      | 0        | 0   | 0             | <- is_padding
///
/// Above is a representation of this table. Primarily we are interested in verifying that:
/// - next state (for the same symbol) was assigned correctly
/// - the number of times this symbol appears is assigned correctly
///
/// For more details, refer the [FSE reconstruction][doclink] section.
///
/// [doclink]: https://nigeltao.github.io/blog/2022/zstandard-part-5-fse.html#fse-reconstruction
#[derive(Clone, Debug)]
pub struct FseTable {
    /// Fixed column to mark the first row of the FSE table layout. We reserve the first row to
    /// populate all 0s. q_start=1 starts from the second row onwards.
    q_first: Column<Fixed>,
    /// Fixed column to mark the start of a new FSE table. FSE tables for LLT, MOT and MLT have a
    /// maximum possible accuracy log of AL=9, i.e. we will have at the most 2^9=256 states in the
    /// FSE table. From the second row onwards, every 256th row will be marked with q_start=1 to
    /// indicate the start of a new FSE table. Within an FSE table, we will only have rows up to
    /// table_size (1 << AL), and the rest of the rows will be marked with is_padding=1.
    q_start: Column<Fixed>,
    /// Boolean column to mark whether the row is a padded row.
    is_padding: Column<Advice>,
    /// The block index in which this FSE table is found.
    block_idx: Column<Advice>,
    /// The table kind, i.e. LLT=1, MOT=2 or MLT=3.
    table_kind: Column<Advice>,
    /// The size of the FSE table.
    table_size: Column<Advice>,
    /// Helper column for (table_size >> 1).
    table_size_rs_1: Column<Advice>,
    /// Helper column for (table_size >> 3).
    table_size_rs_3: Column<Advice>,
    /// Incremental index given to a state, idx in 1..=table_size.
    idx: Column<Advice>,
    /// The FSE symbol, starting at symbol=0.
    symbol: Column<Advice>,
    /// Helper gadget to know whether the symbol is the same or not.
    symbol_cmp: ComparatorConfig<Fr, 1>,
    /// Boolean column to tell us when symbol is changing.
    is_symbol_change: Column<Advice>,
    /// Represents the number of times this symbol appears in the FSE table. This value does not
    /// change while the symbol in the table remains the same.
    symbol_count: Column<Advice>,
    /// An accumulator that resets to 1 each time we encounter a new symbol in the FSE table.
    /// It increments while the symbol remains the same. At the row where we encounter a symbol
    /// change, such that: symbol' != symbol, we have: symbol_count == symbol_count_acc.
    symbol_count_acc: Column<Advice>,
    /// The state in FSE. In the Auxiliary table, it does not increment by 1. Instead, it follows:
    /// - state'' == state   + table_size_rs_1 + table_size_rs_3 + 3
    /// - state'  == state'' & (table_size - 1)
    ///
    /// where state' is the next row's state.
    state: Column<Advice>,
    /// Denotes the baseline field.
    baseline: Column<Advice>,
    /// Helper gadget to compute whether baseline==0x00.
    baseline_0x00: IsEqualConfig<Fr>,
    /// Helper column to mark the baseline observed at the last state allocated to a symbol.
    last_baseline: Column<Advice>,
    /// The number of bits to be read from bitstream at this state.
    nb: Column<Advice>,
    /// The smaller power of two assigned to this state. The following must hold:
    /// - 2 ^ nb == SPoT.
    spot: Column<Advice>,
    /// An accumulator over SPoT value.
    spot_acc: Column<Advice>,
    /// Helper column to remember the smallest spot for that symbol.
    smallest_spot: Column<Advice>,
    /// Helper boolean column which is set only from baseline == 0x00.
    baseline_mark: Column<Advice>,
    /// ROM table for verifying FSE table kind and block_idx transition.
    rom_fse_transition: RomFseTableTransition,
}

impl FseTable {
    /// Configure the FSE table.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        u8_table: U8Table,
        range8_table: RangeTable<8>,
        pow2_table: Pow2Table<20>,
        bitwise_op_table: BitwiseOpTable,
    ) -> Self {
        // Fixed table to check the transition of table kinds and block idx.
        let rom_fse_transition = RomFseTableTransition::construct(meta);

        let (is_padding, symbol, baseline) = (
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        );
        let config = Self {
            q_first: meta.fixed_column(),
            q_start: meta.fixed_column(),
            is_padding: meta.advice_column(),
            block_idx: meta.advice_column(),
            table_kind: meta.advice_column(),
            table_size: meta.advice_column(),
            table_size_rs_1: meta.advice_column(),
            table_size_rs_3: meta.advice_column(),
            idx: meta.advice_column(),
            symbol,
            is_symbol_change: meta.advice_column(),
            symbol_cmp: ComparatorChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::prev())),
                |meta| meta.query_advice(symbol, Rotation::prev()),
                |meta| meta.query_advice(symbol, Rotation::cur()),
                u8_table.into(),
            ),
            symbol_count: meta.advice_column(),
            symbol_count_acc: meta.advice_column(),
            state: meta.advice_column(),
            baseline,
            baseline_0x00: IsEqualChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(baseline, Rotation::cur()),
                |_| 0.expr(),
            ),
            last_baseline: meta.advice_column(),
            nb: meta.advice_column(),
            spot: meta.advice_column(),
            spot_acc: meta.advice_column(),
            smallest_spot: meta.advice_column(),
            baseline_mark: meta.advice_column(),
            rom_fse_transition,
        };

        meta.lookup_any("FseTable: spot == 1 << nb", |meta| {
            let condition = not::expr(meta.query_advice(config.is_padding, Rotation::cur()));

            [
                meta.query_advice(config.nb, Rotation::cur()),
                meta.query_advice(config.spot, Rotation::cur()),
            ]
            .into_iter()
            .zip_eq(pow2_table.table_exprs(meta))
            .map(|(arg, table)| (condition.expr() * arg, table))
            .collect()
        });

        meta.lookup("FseTable: table_size >> 3", |meta| {
            // We only check on the starting row. We have a custom gate to check that the
            // table_size_rs_3 column's value does not change over the rest of the rows for a
            // particular instance of FSE table.
            let condition = and::expr([
                meta.query_fixed(config.q_start, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let range_value = meta.query_advice(config.table_size, Rotation::cur())
                - (meta.query_advice(config.table_size_rs_3, Rotation::cur()) * 8.expr());

            vec![(condition * range_value, range8_table.into())]
        });

        meta.lookup("FseTable: symbol in [0, 256)", |meta| {
            vec![(
                meta.query_advice(config.symbol, Rotation::cur()),
                u8_table.into(),
            )]
        });

        meta.create_gate("FseTable: first row", |meta| {
            let condition = meta.query_fixed(config.q_first, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            // The first row is all 0s. This is then followed by a q_start==1 fixed column. We want
            // to make sure the first FSE table belongs to block_idx=1.
            cb.require_equal(
                "block_idx == 1 for the first FSE table",
                meta.query_advice(config.block_idx, Rotation::next()),
                1.expr(),
            );

            // The first FSE table described should be the LLT table.
            cb.require_equal(
                "table_kind == LLT for the first FSE table",
                meta.query_advice(config.table_kind, Rotation::next()),
                FseTableKind::LLT.expr(),
            );

            cb.gate(condition)
        });

        meta.lookup_any(
            "FseTable: start row (FSE table kind and block_idx transition)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.q_start, Rotation::cur()),
                    not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
                ]);

                let (block_idx_prev, block_idx_curr, table_kind_prev, table_kind_curr) = (
                    meta.query_advice(config.block_idx, Rotation::prev()),
                    meta.query_advice(config.block_idx, Rotation::cur()),
                    meta.query_advice(config.table_kind, Rotation::prev()),
                    meta.query_advice(config.table_kind, Rotation::cur()),
                );

                [
                    block_idx_prev,
                    block_idx_curr,
                    table_kind_prev,
                    table_kind_curr,
                ]
                .into_iter()
                .zip_eq(config.rom_fse_transition.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        meta.create_gate("FseTable: start row", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_start, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "state inits at 0",
                meta.query_advice(config.state, Rotation::cur()),
            );

            cb.require_equal(
                "idx == 1",
                meta.query_advice(config.idx, Rotation::cur()),
                1.expr(),
            );

            // table_size_rs_1 == table_size >> 1.
            cb.require_boolean(
                "table_size >> 1",
                meta.query_advice(config.table_size, Rotation::cur())
                    - (meta.query_advice(config.table_size_rs_1, Rotation::cur()) * 2.expr()),
            );

            // The start row is a new symbol.
            cb.require_equal(
                "is_symbol_change == 1",
                meta.query_advice(config.is_symbol_change, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        meta.create_gate("FseTable: other rows in the same FSE table", |meta| {
            let condition = not::expr(meta.query_fixed(config.q_start, Rotation::cur()));

            let mut cb = BaseConstraintBuilder::default();

            // FSE table's columns that remain unchanged.
            for column in [
                config.block_idx,
                config.table_kind,
                config.table_size,
                config.table_size_rs_1,
                config.table_size_rs_3,
            ] {
                cb.require_equal(
                    "FseTable: columns that remain unchanged",
                    meta.query_advice(column, Rotation::cur()),
                    meta.query_advice(column, Rotation::prev()),
                );
            }

            // If the symbol comparator says that the current symbol is the same as the previous
            // symbol, then the current row cannot be marked as a is_symbol_change row.
            let (prev_lt_cur, prev_eq_cur) = config.symbol_cmp.expr(meta, Some(Rotation::cur()));
            let is_symbol_change = meta.query_advice(config.is_symbol_change, Rotation::cur());
            cb.condition(prev_eq_cur.expr(), |cb| {
                cb.require_zero("is_symbol_change == 0", is_symbol_change.expr());
            });
            cb.condition(prev_lt_cur.expr(), |cb| {
                cb.require_equal("is_symbol_change == 1", is_symbol_change.expr(), 1.expr());
            });

            // If symbol is changing on the current row, then the symbol has increased from the
            // previous row.
            cb.condition(is_symbol_change.expr(), |cb| {
                cb.require_equal("symbol::prev < symbol::cur", prev_lt_cur, 1.expr());
            });
            cb.condition(not::expr(is_symbol_change.expr()), |cb| {
                cb.require_equal("symbol::prev == symbol::cur", prev_eq_cur, 1.expr());
            });

            // Once we enter padding territory, we stay in padding territory, i.e.
            // is_padding transitions from 0 -> 1 only once.
            let (is_padding_curr, is_padding_prev) = (
                meta.query_advice(config.is_padding, Rotation::cur()),
                meta.query_advice(config.is_padding, Rotation::prev()),
            );
            let is_padding_delta = is_padding_curr.expr() - is_padding_prev.expr();
            cb.require_boolean("is_padding is boolean", is_padding_curr.expr());
            cb.require_boolean("is_padding_delta is boolean", is_padding_delta);

            // While we have not entered the padding region in this table, the idx should
            // increment.
            cb.condition(not::expr(is_padding_curr.expr()), |cb| {
                cb.require_equal(
                    "idx increments",
                    meta.query_advice(config.idx, Rotation::cur()),
                    meta.query_advice(config.idx, Rotation::prev()) + 1.expr(),
                );
            });

            // If we are entering the padding region on this row, the idx on the previous row must
            // equal the table size, i.e. all states must be generated.
            cb.condition(
                and::expr([not::expr(is_padding_prev), is_padding_curr]),
                |cb| {
                    cb.require_equal(
                        "idx == table_size on the last state",
                        meta.query_advice(config.idx, Rotation::prev()),
                        meta.query_advice(config.table_size, Rotation::prev()),
                    );
                },
            );

            cb.gate(condition)
        });

        meta.create_gate("FseTable: symbol changes", |meta| {
            let condition = and::expr([
                meta.query_advice(config.is_symbol_change, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // We first do validations for the previous symbol.
            //
            // - symbol_count_acc accumulated to symbol_count.
            // - spot_acc accumulated to table_size.
            // - the last state has the smallest spot value.
            // - the last state's baseline is in fact last_baseline.
            cb.require_equal(
                "symbol_count == symbol_count_acc",
                meta.query_advice(config.symbol_count, Rotation::prev()),
                meta.query_advice(config.symbol_count_acc, Rotation::prev()),
            );
            cb.require_equal(
                "spot_acc == table_size",
                meta.query_advice(config.spot_acc, Rotation::prev()),
                meta.query_advice(config.table_size, Rotation::prev()),
            );
            cb.require_equal(
                "spot == smallest_spot",
                meta.query_advice(config.spot, Rotation::prev()),
                meta.query_advice(config.smallest_spot, Rotation::prev()),
            );
            cb.require_equal(
                "baseline == last_baseline",
                meta.query_advice(config.baseline, Rotation::prev()),
                meta.query_advice(config.last_baseline, Rotation::prev()),
            );

            // When the symbol changes, we wish to check in case the baseline==0x00 or not. If it
            // is, then the baseline_mark should be turned on from this row onwards (while the
            // symbol continues). If it is not, the baseline_mark should stay turned off until we
            // encounter baseline==0x00.
            let is_baseline_mark = meta.query_advice(config.baseline_mark, Rotation::cur());
            let is_baseline_0x00 = config.baseline_0x00.expr();
            cb.condition(is_baseline_0x00.expr(), |cb| {
                cb.require_equal(
                    "baseline_mark set at baseline==0x00",
                    is_baseline_mark.expr(),
                    1.expr(),
                );
            });
            cb.condition(not::expr(is_baseline_0x00.expr()), |cb| {
                cb.require_zero(
                    "baseline_mark not set at baseline!=0x00",
                    is_baseline_mark.expr(),
                );
            });

            // We repeat the above constraints to make sure witness to baseline mark are set
            // correctly.
            //
            // When a symbol changes and the baseline is not marked, then the baseline is
            // calculated from the baseline and nb at the last state allocated to this symbol.
            cb.condition(is_baseline_mark.expr(), |cb| {
                cb.require_zero(
                    "baseline=0x00 at baseline mark",
                    meta.query_advice(config.baseline, Rotation::cur()),
                );
            });
            cb.condition(not::expr(is_baseline_mark.expr()), |cb| {
                cb.require_equal(
                    "baseline == last_baseline + smallest_spot",
                    meta.query_advice(config.baseline, Rotation::cur()),
                    meta.query_advice(config.last_baseline, Rotation::cur())
                        + meta.query_advice(config.smallest_spot, Rotation::cur()),
                );
            });

            // The spot accumulation inits at spot.
            cb.require_equal(
                "spot_acc == spot",
                meta.query_advice(config.spot_acc, Rotation::cur()),
                meta.query_advice(config.spot, Rotation::cur()),
            );

            // The symbol_count_acc inits at 1.
            cb.require_equal(
                "symbol_count_acc inits at 1",
                meta.query_advice(config.symbol_count_acc, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        meta.create_gate("FseTable: symbol continues", |meta| {
            let condition = and::expr([
                not::expr(meta.query_advice(config.is_symbol_change, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // While we allocate more states to the same symbol:
            //
            // - symbol_count does not change
            // - smallest_spot does not change
            // - last_baseline does not change
            // - symbol_count_acc increments by +1
            // - spot_acc accumlates based on the current spot
            // - baseline_mark can transition from 0 -> 1 only once
            // - baseline==0x00 if baseline_mark is set
            // - baseline==baseline::prev+spot::prev if baseline_mark is not set
            for column in [
                config.symbol_count,
                config.smallest_spot,
                config.last_baseline,
            ] {
                cb.require_equal(
                    "unchanged columns",
                    meta.query_advice(column, Rotation::cur()),
                    meta.query_advice(column, Rotation::prev()),
                );
            }

            cb.require_equal(
                "symbol_count_acc increments",
                meta.query_advice(config.symbol_count_acc, Rotation::cur()),
                meta.query_advice(config.symbol_count_acc, Rotation::prev()) + 1.expr(),
            );

            cb.require_equal(
                "spot_acc accumlates",
                meta.query_advice(config.spot_acc, Rotation::cur()),
                meta.query_advice(config.spot_acc, Rotation::prev())
                    + meta.query_advice(config.spot, Rotation::cur()),
            );

            let (baseline_mark_curr, baseline_mark_prev) = (
                meta.query_advice(config.baseline_mark, Rotation::cur()),
                meta.query_advice(config.baseline_mark, Rotation::prev()),
            );
            let baseline_mark_delta = baseline_mark_curr.expr() - baseline_mark_prev;
            cb.require_boolean("baseline_mark_delta is boolean", baseline_mark_delta);

            // baseline == baseline_mark_curr == 1 ? 0x00 : baseline_prev + spot_prev
            let (baseline_curr, baseline_prev, spot_prev) = (
                meta.query_advice(config.baseline, Rotation::cur()),
                meta.query_advice(config.baseline, Rotation::prev()),
                meta.query_advice(config.spot, Rotation::prev()),
            );
            cb.require_equal(
                "baseline calculation",
                baseline_curr,
                select::expr(baseline_mark_curr, 0x00.expr(), baseline_prev + spot_prev),
            );

            cb.gate(condition)
        });

        // Constraint for state' calculation. We wish to constrain:
        //
        // - state' == state'' & (table_size - 1)
        // - state'' == state + (table_size >> 3) + (table_size >> 1) + 3
        meta.lookup_any("FseTable: state transition", |meta| {
            let condition = and::expr([
                not::expr(meta.query_fixed(config.q_start, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let state_prime = meta.query_advice(config.state, Rotation::cur());
            let state_prime_prime = meta.query_advice(config.state, Rotation::prev())
                + meta.query_advice(config.table_size_rs_3, Rotation::cur())
                + meta.query_advice(config.table_size_rs_1, Rotation::cur())
                + 3.expr();
            let table_size_minus_one =
                meta.query_advice(config.table_size, Rotation::cur()) - 1.expr();

            [
                BitwiseOp::AND.expr(), // op
                state_prime_prime,     // operand1
                table_size_minus_one,  // operand2
                state_prime,           // result
            ]
            .into_iter()
            .zip_eq(bitwise_op_table.table_exprs(meta))
            .map(|(arg, table)| (condition.expr() * arg, table))
            .collect()
        });

        debug_assert!(meta.degree() <= 9);

        config
    }
}

impl FseTable {
    /// Lookup table expressions for (state, symbol, baseline, nb) tuple check.
    ///
    /// This check can be done on any row within the FSE table.
    pub fn table_exprs_by_state(&self, meta: &mut VirtualCells<Fr>) -> Vec<Expression<Fr>> {
        vec![
            meta.query_fixed(self.q_first, Rotation::cur()),
            meta.query_advice(self.block_idx, Rotation::cur()),
            meta.query_advice(self.table_kind, Rotation::cur()),
            meta.query_advice(self.table_size, Rotation::cur()),
            meta.query_advice(self.state, Rotation::cur()),
            meta.query_advice(self.symbol, Rotation::cur()),
            meta.query_advice(self.baseline, Rotation::cur()),
            meta.query_advice(self.nb, Rotation::cur()),
            meta.query_advice(self.is_padding, Rotation::cur()),
        ]
    }

    /// Lookup table expressions for (symbol, symbol_count) tuple check.
    ///
    /// This check is only done on the last occurence of a particular symbol, i.e. where:
    /// - symbol_count == symbol_count_acc
    pub fn table_exprs_by_symbol(&self, meta: &mut VirtualCells<Fr>) -> Vec<Expression<Fr>> {
        vec![
            meta.query_fixed(self.q_first, Rotation::cur()),
            meta.query_advice(self.block_idx, Rotation::cur()),
            meta.query_advice(self.table_kind, Rotation::cur()),
            meta.query_advice(self.table_size, Rotation::cur()),
            meta.query_advice(self.symbol, Rotation::cur()),
            meta.query_advice(self.symbol_count, Rotation::cur()),
            meta.query_advice(self.symbol_count_acc, Rotation::cur()),
            meta.query_advice(self.is_padding, Rotation::cur()),
        ]
    }
}
