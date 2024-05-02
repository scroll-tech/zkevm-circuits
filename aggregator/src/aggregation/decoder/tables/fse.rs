use gadgets::{
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

use crate::aggregation::decoder::{
    tables::{FixedLookupTag, FixedTable},
    witgen::FseTableKind,
};

/// The FSE table verifies that given the symbols and the states allocated to those symbols, the
/// baseline and number of bits (nb) are assigned correctly to them.
///
/// The FSE table's layout is setup in a specific order, so that we cannot specify multiple FSE
/// table's of the same kind at the same block index. Every block has 3 FSE tables, namely for
/// Literal Length (LLT), Match Offset (MOT) and Match Length (MLT). They appear in the below
/// order:
///
/// - block_idx=1, table_kind=LLT
/// - block_idx=1, table_kind=MOT
/// - block_idx=1, table_kind=MLT
/// - block_idx=2, table_kind=LLT
/// - ... and so on
///
/// Each table spans over a maximum of 1024 rows, and the start of an FSE table is marked by the
/// fixed column ``q_start``. Upon finishing the FSE table, remaining rows are marked with the
/// ``is_padding`` column.
///
/// Each table begins with symbols that have a "less than 1" probability, whereby the state
/// allocated to them is at the end of the table (highest state) and retreating. For example, if
/// the symbol=3 has a normalised probability of prob==-1, then it is allocated the state 0x3f (63)
/// in an FSE table of accuracy_log=6. For subsequent symbols that have a prob>1, the state=0x3f is
/// skipped and we continue the same computation for the next successive state:
///
/// - state'  == state'' & (table_size - 1)
/// - state'' == state + (table_size >> 3) + (table_size >> 1) + 3
///
/// where state' signifies the next state.
///
/// We cannot anticipate how many times we end up on such a "skipped" (or pre-allocated) state
/// while computing the states for a symbol, so we mark such rows with the boolean column
/// ``is_skipped_state``. On these rows, the ``state`` should have been taken by a
/// ``is_prob_less_than1`` symbol that reads AL number of bits at a baseline of 0x00.
///
/// | State | Symbol | is_prob_less_than1 |
/// |-------|--------|--------------------|
/// | 0     | 0      | 0                  | <- q_first
/// |-------|--------|--------------------|
/// | 0x3f  | 3      | 1                  | <- q_start
/// | 0x3e  | 4      | 1                  |
/// | 0x00  | 0      | 0                  |
/// | ...   | 0      | 0                  |
/// | 0x1d  | 0      | 0                  |
/// | 0x03  | 1  ->  | 0                  |
/// | 0x0c  | 1  ->  | 0                  |
/// | 0x11  | 1  ->  | 0                  |
/// | 0x15  | 1  ->  | 0                  |
/// | 0x1a  | 1  ->  | 0                  |
/// | 0x1e  | 1  ->  | 0                  |
/// | 0x08  | 2      | 0                  |
/// | ...   | ...    | 0                  |
/// | 0x09  | 6      | 0                  |
/// | 0x00  | 0      | 0                  | <- is_padding
/// | ...   | ...    | 0                  | <- is_padding
/// | 0x00  | 0      | 0                  | <- is_padding
/// |-------|--------|--------------------|
/// | ...   | ...    | ...                | <- q_start
/// |-------|--------|--------------------|
///
/// For more details, refer the [FSE reconstruction][doclink] section.
///
/// [doclink]: https://nigeltao.github.io/blog/2022/zstandard-part-5-fse.html#fse-reconstruction
#[derive(Clone, Debug)]
pub struct FseTable {
    /// The helper table to validate that the (baseline, nb) were assigned correctly to each state.
    sorted_table: FseSortedStatesTable,
    /// A boolean to mark whether this row represents a symbol with probability "less than 1".
    is_prob_less_than1: Column<Advice>,
    /// Boolean column to mark whether the row is a padded row.
    is_padding: Column<Advice>,
    /// Helper column for (table_size >> 1).
    table_size_rs_1: Column<Advice>,
    /// Helper column for (table_size >> 3).
    table_size_rs_3: Column<Advice>,
    /// Incremental index given to a state, idx in 1..=table_size.
    idx: Column<Advice>,
    /// The FSE symbol, starting at symbol=0.
    symbol: Column<Advice>,
    /// Boolean column to tell us when symbol is changing.
    is_new_symbol: Column<Advice>,
    /// Represents the number of times this symbol appears in the FSE table. This value does not
    /// change while the symbol in the table remains the same.
    symbol_count: Column<Advice>,
    /// An accumulator that resets to 1 each time we encounter a new symbol in the FSE table.
    /// It increments while the symbol remains the same if we are not skipping the state. When we
    /// encounter a new symbol, we validate that on the previous row, symbol_count equaled
    /// symbol_count_acc.
    symbol_count_acc: Column<Advice>,
    /// The state in FSE. In the Auxiliary table, it does not increment by 1. Instead, it follows:
    ///
    /// - state'' == state   + table_size_rs_1 + table_size_rs_3 + 3
    /// - state'  == state'' & (table_size - 1)
    ///
    /// where state' is the next row's state.
    state: Column<Advice>,
    /// Boolean column to mark if the computed state must be "skipped" because it was
    /// pre-allocated to one of the symbols with a "less than 1" probability.
    is_skipped_state: Column<Advice>,
    /// The assigned baseline for this state.
    baseline: Column<Advice>,
    /// The number of bits to read from bitstream when at this state.
    nb: Column<Advice>,
    /// Fixed lookup table.
    fixed_table: FixedTable,
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
        let fixed_table = FixedTable::construct(meta);

        // Auxiliary table to validate that (baseline, nb) were assigned correctly to the states
        // allocated to a symbol.
        let sorted_table = FseSortedStatesTable::configure(meta, pow2_table, u8_table);

        let config = Self {
            sorted_table,
            is_prob_less_than1: meta.advice_column(),
            is_padding: meta.advice_column(),
            table_size_rs_1: meta.advice_column(),
            table_size_rs_3: meta.advice_column(),
            idx: meta.advice_column(),
            symbol: meta.advice_column(),
            is_new_symbol: meta.advice_column(),
            symbol_count: meta.advice_column(),
            symbol_count_acc: meta.advice_column(),
            state: meta.advice_column(),
            is_skipped_state: meta.advice_column(),
            baseline: meta.advice_column(),
            nb: meta.advice_column(),
            fixed_table,
        };

        // Check that on the starting row of each FSE table, i.e. q_start=true:
        // - table_size_rs_3 == table_size >> 3.
        meta.lookup("FseTable: table_size >> 3", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.sorted_table.q_start, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let range_value = meta.query_advice(config.sorted_table.table_size, Rotation::cur())
                - (meta.query_advice(config.table_size_rs_3, Rotation::cur()) * 8.expr());

            vec![(condition * range_value, range8_table.into())]
        });

        // Every FSE symbol is a byte.
        meta.lookup("FseTable: symbol in [0, 256)", |meta| {
            vec![(
                meta.query_advice(config.symbol, Rotation::cur()),
                u8_table.into(),
            )]
        });

        // The first row of the FseTable layout, i.e. q_first=true.
        meta.create_gate("FseTable: first row", |meta| {
            let condition = meta.query_fixed(config.sorted_table.q_first, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            // The first row is all 0s. This is then followed by a q_start==1 fixed column. We want
            // to make sure the first FSE table belongs to block_idx=1.
            cb.require_equal(
                "block_idx == 1 for the first FSE table",
                meta.query_advice(config.sorted_table.block_idx, Rotation::next()),
                1.expr(),
            );

            // The first FSE table described should be the LLT table.
            cb.require_equal(
                "table_kind == LLT for the first FSE table",
                meta.query_advice(config.sorted_table.table_kind, Rotation::next()),
                FseTableKind::LLT.expr(),
            );

            cb.gate(condition)
        });

        // Check that on the starting row of every FSE table, i.e. q_start=true:
        //
        // - tuple (block_idx::prev, block_idx::cur, table_kind::prev, table_kind::cur)
        //
        // is in fact a valid transition. All valid transitions are provided in the fixed-table
        // RomFseTableTransition.
        meta.lookup_any(
            "FseSortedStatesTable: start row (ROM block_idx and table_kind transition)",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(config.sorted_table.q_start, Rotation::cur()),
                    not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
                ]);

                let (block_idx_prev, block_idx_curr, table_kind_prev, table_kind_curr) = (
                    meta.query_advice(config.sorted_table.block_idx, Rotation::prev()),
                    meta.query_advice(config.sorted_table.block_idx, Rotation::cur()),
                    meta.query_advice(config.sorted_table.table_kind, Rotation::prev()),
                    meta.query_advice(config.sorted_table.table_kind, Rotation::cur()),
                );

                [
                    FixedLookupTag::FseTableTransition.expr(),
                    block_idx_prev,
                    block_idx_curr,
                    table_kind_prev,
                    table_kind_curr,
                    0.expr(), // unused
                    0.expr(), // unused
                ]
                .into_iter()
                .zip_eq(config.fixed_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        // The starting row of every FSE table, i.e. q_start=true.
        meta.create_gate("FseTable: start row", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.sorted_table.q_start, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let is_prob_less_than1 = meta.query_advice(config.is_prob_less_than1, Rotation::cur());
            cb.require_boolean("prob=-1 is boolean", is_prob_less_than1.expr());

            // 1. If we start with a symbol that has prob "less than 1"
            cb.condition(is_prob_less_than1.expr(), |cb| {
                cb.require_equal(
                    "prob=-1: state inits at table_size - 1",
                    meta.query_advice(config.state, Rotation::cur()),
                    meta.query_advice(config.sorted_table.table_size, Rotation::cur()) - 1.expr(),
                );
            });

            // 2. If no symbol has a prob "less than 1"
            cb.condition(not::expr(is_prob_less_than1), |cb| {
                cb.require_zero(
                    "state inits at 0",
                    meta.query_advice(config.state, Rotation::cur()),
                );
            });

            cb.require_equal(
                "idx == 1",
                meta.query_advice(config.idx, Rotation::cur()),
                1.expr(),
            );

            // table_size_rs_1 == table_size >> 1.
            cb.require_boolean(
                "table_size >> 1",
                meta.query_advice(config.sorted_table.table_size, Rotation::cur())
                    - (meta.query_advice(config.table_size_rs_1, Rotation::cur()) * 2.expr()),
            );

            // The start row is a new symbol.
            cb.require_equal(
                "is_new_symbol==true",
                meta.query_advice(config.is_new_symbol, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        // For every symbol that has a normalised probability prob=-1.
        meta.lookup_any("FseTable: all symbols with prob=-1 (nb==AL)", |meta| {
            let condition = meta.query_advice(config.is_prob_less_than1, Rotation::cur());

            // for a symbol with prob=-1, we do a full state reset, i.e.
            // read nb=AL bits, i.e. 1 << nb == table_size.
            [
                meta.query_advice(config.nb, Rotation::cur()),
                meta.query_advice(config.sorted_table.table_size, Rotation::cur()),
            ]
            .into_iter()
            .zip_eq(pow2_table.table_exprs(meta))
            .map(|(arg, table)| (condition.expr() * arg, table))
            .collect()
        });

        // For every symbol that has a normalised probability prob=-1.
        meta.create_gate("FseTable: all symbols with prob=-1", |meta| {
            let condition = meta.query_advice(config.is_prob_less_than1, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            // Each such row is a new symbol.
            cb.require_equal(
                "prob=-1: is_new_symbol==true",
                meta.query_advice(config.is_new_symbol, Rotation::cur()),
                1.expr(),
            );

            // prob=-1 indicates a baseline==0x00.
            cb.require_zero(
                "prob=-1: baseline==0x00",
                meta.query_advice(config.baseline, Rotation::cur()),
            );

            // prob=-1 symbol cannot be padding.
            cb.require_zero(
                "prob=-1: is_padding==false",
                meta.query_advice(config.is_padding, Rotation::cur()),
            );

            // prob=-1 symbol is not a skipped state.
            cb.require_zero(
                "prob=-1: is_skipped_state=false",
                meta.query_advice(config.is_skipped_state, Rotation::cur()),
            );

            cb.gate(condition)
        });

        // Symbols with prob=-1 are in increasing order.
        meta.lookup(
            "FseTable: subsequent symbols with prob=-1 (symbol increasing)",
            |meta| {
                let condition = and::expr([
                    not::expr(meta.query_fixed(config.sorted_table.q_start, Rotation::cur())),
                    meta.query_advice(config.is_prob_less_than1, Rotation::cur()),
                ]);

                // Symbols with prob=-1 are assigned cells from the end (state==table_size-1) and
                // retreating. However those symbols are processed in natural order, i.e. symbols
                // are in increasing order.
                //
                // - symbol::cur - symbol::prev > 0
                //
                // We check that (symbol - symbol_prev - 1) lies in the [0, 256) range.
                let (symbol_curr, symbol_prev) = (
                    meta.query_advice(config.symbol, Rotation::cur()),
                    meta.query_advice(config.symbol, Rotation::prev()),
                );
                let delta = symbol_curr - symbol_prev - 1.expr();

                vec![(condition * delta, u8_table.into())]
            },
        );

        // Symbols with prob=-1 are assigned states from the end and retreating.
        meta.create_gate(
            "FseTable: subsequent symbols with prob=-1 (state retreating)",
            |meta| {
                let condition = and::expr([
                    not::expr(meta.query_fixed(config.sorted_table.q_start, Rotation::cur())),
                    meta.query_advice(config.is_prob_less_than1, Rotation::cur()),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // While prob=-1, state is retreating, i.e. decrements by 1.
                cb.require_equal(
                    "state == state::prev - 1",
                    meta.query_advice(config.state, Rotation::cur()),
                    meta.query_advice(config.state, Rotation::prev()) - 1.expr(),
                );

                cb.gate(condition)
            },
        );

        // Symbols with prob>=1 are also in increasing order. We skip this check if this is the
        // first symbol with prob>=1.
        meta.lookup(
            "FseTable: symbols with prob>=1 (symbol increasing)",
            |meta| {
                let condition = and::expr([
                    not::expr(meta.query_fixed(config.sorted_table.q_start, Rotation::cur())),
                    not::expr(meta.query_advice(config.is_prob_less_than1, Rotation::prev())),
                    meta.query_advice(config.is_new_symbol, Rotation::cur()),
                ]);

                // Whenever we move to a new symbol (is_new_symbol=true), excluding the first symbol
                // with prob>=1, the symbol is increasing.
                //
                // - symbol::cur - symbol::prev > 0
                //
                // We check that (symbol - symbol_prev - 1) lies in the [0, 256) range.
                let (symbol_curr, symbol_prev) = (
                    meta.query_advice(config.symbol, Rotation::cur()),
                    meta.query_advice(config.symbol, Rotation::prev()),
                );
                let delta = symbol_curr - symbol_prev - 1.expr();

                vec![(condition * delta, u8_table.into())]
            },
        );

        // Symbols with prob>=1 continue the same symbol if not a new symbol.
        meta.create_gate("FseTable: symbols with prob>=1", |meta| {
            let condition = and::expr([
                not::expr(meta.query_fixed(config.sorted_table.q_start, Rotation::cur())),
                not::expr(meta.query_advice(config.is_prob_less_than1, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // When we are not seeing a new symbol, make sure the symbol is equal to the symbol on
            // the previous row.
            let is_not_new_symbol =
                not::expr(meta.query_advice(config.is_new_symbol, Rotation::cur()));
            cb.condition(is_not_new_symbol, |cb| {
                cb.require_equal(
                    "prob>=1: same symbol",
                    meta.query_advice(config.symbol, Rotation::cur()),
                    meta.query_advice(config.symbol, Rotation::prev()),
                );
            });

            cb.gate(condition)
        });

        // All rows in an instance of FSE table, except the starting row (q_start=true).
        meta.create_gate("FseTable: every FSE table (except q_start=1)", |meta| {
            let condition =
                not::expr(meta.query_fixed(config.sorted_table.q_start, Rotation::cur()));

            let mut cb = BaseConstraintBuilder::default();

            // FSE table's columns that remain unchanged.
            for column in [config.table_size_rs_1, config.table_size_rs_3] {
                cb.require_equal(
                    "FseTable: columns that remain unchanged",
                    meta.query_advice(column, Rotation::cur()),
                    meta.query_advice(column, Rotation::prev()),
                );
            }

            // The symbols with prob "less than 1" are assigned at the starting rows of the FSE
            // table with maximum (and retreating) state values.
            let (is_prob_less_than1_prev, is_prob_less_than1_curr) = (
                meta.query_advice(config.is_prob_less_than1, Rotation::prev()),
                meta.query_advice(config.is_prob_less_than1, Rotation::cur()),
            );
            let delta = is_prob_less_than1_prev - is_prob_less_than1_curr.expr();
            cb.require_boolean("prob=-1 is boolean", is_prob_less_than1_curr);
            cb.require_boolean("prob=-1 symbols occur in the start of the layout", delta);

            // Once we enter padding territory, we stay in padding territory, i.e.
            // is_padding transitions from 0 -> 1 only once.
            let (is_padding_curr, is_padding_prev) = (
                meta.query_advice(config.is_padding, Rotation::cur()),
                meta.query_advice(config.is_padding, Rotation::prev()),
            );
            let is_padding_delta = is_padding_curr.expr() - is_padding_prev.expr();
            cb.require_boolean("is_padding is boolean", is_padding_curr.expr());
            cb.require_boolean("is_padding_delta is boolean", is_padding_delta);

            // If we are not in the padding region and don't skip state on this row, then this is a
            // new state in the FSE table, i.e. idx increments.
            let is_skipped_state = meta.query_advice(config.is_skipped_state, Rotation::cur());
            cb.require_equal(
                "idx increments in non-padding region if we don't skip state",
                meta.query_advice(config.idx, Rotation::cur()),
                select::expr(
                    and::expr([
                        not::expr(is_padding_curr.expr()),
                        not::expr(is_skipped_state),
                    ]),
                    meta.query_advice(config.idx, Rotation::prev()) + 1.expr(),
                    meta.query_advice(config.idx, Rotation::prev()),
                ),
            );

            // If we are entering the padding region on this row, the idx on the previous row must
            // equal the table size, i.e. all states must be generated.
            cb.condition(
                and::expr([not::expr(is_padding_prev), is_padding_curr]),
                |cb| {
                    cb.require_equal(
                        "idx == table_size on the last state",
                        meta.query_advice(config.idx, Rotation::prev()),
                        meta.query_advice(config.sorted_table.table_size, Rotation::prev()),
                    );
                },
            );

            cb.gate(condition)
        });

        // A state is skipped only if that state was pre-allocated to a symbol with prob=-1.
        meta.lookup_any("FseTable: skipped state", |meta| {
            let condition = meta.query_advice(config.is_skipped_state, Rotation::cur());

            // A state can be skipped only if it was pre-allocated to a symbol with prob=-1. So we
            // check that there exists a row with the same block_idx, table_kind and the skipped
            // state with a prob=-1.
            let fse_table_exprs = [
                meta.query_advice(config.sorted_table.block_idx, Rotation::cur()),
                meta.query_advice(config.sorted_table.table_kind, Rotation::cur()),
                meta.query_advice(config.state, Rotation::cur()),
                meta.query_advice(config.is_prob_less_than1, Rotation::cur()),
            ];

            [
                meta.query_advice(config.sorted_table.block_idx, Rotation::cur()),
                meta.query_advice(config.sorted_table.table_kind, Rotation::cur()),
                meta.query_advice(config.state, Rotation::cur()),
                1.expr(), // prob=-1
            ]
            .into_iter()
            .zip_eq(fse_table_exprs)
            .map(|(arg, table)| (condition.expr() * arg, table))
            .collect()
        });

        // For every symbol with prob>=1 and a valid state allocated, we check that the baseline
        // and nb fields were assigned correctly.
        meta.lookup_any(
            "FseTable: assigned state (baseline, nb) validation",
            |meta| {
                let condition = and::expr([
                    not::expr(meta.query_advice(config.is_prob_less_than1, Rotation::cur())),
                    not::expr(meta.query_advice(config.is_skipped_state, Rotation::cur())),
                    not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
                ]);

                let (block_idx, table_kind, table_size, state, symbol, symbol_count, baseline, nb) = (
                    meta.query_advice(config.sorted_table.block_idx, Rotation::cur()),
                    meta.query_advice(config.sorted_table.table_kind, Rotation::cur()),
                    meta.query_advice(config.sorted_table.table_size, Rotation::cur()),
                    meta.query_advice(config.state, Rotation::cur()),
                    meta.query_advice(config.symbol, Rotation::cur()),
                    meta.query_advice(config.symbol_count, Rotation::cur()),
                    meta.query_advice(config.baseline, Rotation::cur()),
                    meta.query_advice(config.nb, Rotation::cur()),
                );

                [
                    block_idx,
                    table_kind,
                    table_size,
                    state,
                    symbol,
                    symbol_count,
                    baseline,
                    nb,
                    0.expr(),
                ]
                .into_iter()
                .zip_eq(config.sorted_table.table_exprs(meta))
                .map(|(arg, table)| (condition.expr() * arg, table))
                .collect()
            },
        );

        // For predefined FSE tables, we must validate against the ROM predefined table fields for
        // every state in the FSE table.
        meta.lookup_any("FseTable: predefined table validation", |meta| {
            let condition = and::expr([
                meta.query_advice(config.sorted_table.is_predefined, Rotation::cur()),
                not::expr(meta.query_advice(config.is_skipped_state, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let (table_kind, table_size, state, symbol, baseline, nb) = (
                meta.query_advice(config.sorted_table.table_kind, Rotation::cur()),
                meta.query_advice(config.sorted_table.table_size, Rotation::cur()),
                meta.query_advice(config.state, Rotation::cur()),
                meta.query_advice(config.symbol, Rotation::cur()),
                meta.query_advice(config.baseline, Rotation::cur()),
                meta.query_advice(config.nb, Rotation::cur()),
            );

            [
                FixedLookupTag::PredefinedFse.expr(),
                table_kind,
                table_size,
                state,
                symbol,
                baseline,
                nb,
            ]
            .into_iter()
            .zip_eq(config.fixed_table.table_exprs(meta))
            .map(|(arg, table)| (condition.expr() * arg, table))
            .collect()
        });

        // For every new symbol detected.
        meta.create_gate("FseTable: new symbol", |meta| {
            let condition = and::expr([
                meta.query_advice(config.is_new_symbol, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // We first do validations for the previous symbol.
            //
            // - symbol_count_acc accumulated to symbol_count.
            //
            // This is also expected to pass on the starting row of each FSE table, since the
            // previous row is either q_first=true or is_padding=true, where in both
            // cases we expect:
            // - symbol_count == symbol_count_acc == 0.
            cb.require_equal(
                "symbol_count == symbol_count_acc",
                meta.query_advice(config.symbol_count, Rotation::prev()),
                meta.query_advice(config.symbol_count_acc, Rotation::prev()),
            );

            // The symbol_count_acc inits at 1.
            cb.require_equal(
                "symbol_count_acc inits at 1",
                meta.query_advice(config.symbol_count_acc, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        // Whenever we continue allocating states to the same symbol.
        meta.create_gate("FseTable: same symbol, transitioned state", |meta| {
            let condition = and::expr([
                not::expr(meta.query_advice(config.is_new_symbol, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // While we allocate more states to the same symbol:
            //
            // - symbol_count does not change
            cb.require_equal(
                "if symbol continues: symbol_count unchanged",
                meta.query_advice(config.symbol_count, Rotation::cur()),
                meta.query_advice(config.symbol_count, Rotation::prev()),
            );

            // symbol count accumulator increments if the state is not skipped.
            cb.require_equal(
                "symbol_count_acc increments if state not skipped",
                meta.query_advice(config.symbol_count_acc, Rotation::cur()),
                select::expr(
                    meta.query_advice(config.is_skipped_state, Rotation::cur()),
                    meta.query_advice(config.symbol_count_acc, Rotation::prev()),
                    meta.query_advice(config.symbol_count_acc, Rotation::prev()) + 1.expr(),
                ),
            );

            cb.gate(condition)
        });

        // Constraint for state' calculation. We wish to constrain:
        //
        // - state' == state'' & (table_size - 1)
        // - state'' == state + (table_size >> 3) + (table_size >> 1) + 3
        meta.lookup_any("FseTable: state transition", |meta| {
            let condition = and::expr([
                not::expr(meta.query_fixed(config.sorted_table.q_start, Rotation::cur())),
                not::expr(meta.query_advice(config.is_prob_less_than1, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let state_prime = meta.query_advice(config.state, Rotation::cur());
            let state_prime_prime = meta.query_advice(config.state, Rotation::prev())
                + meta.query_advice(config.table_size_rs_3, Rotation::cur())
                + meta.query_advice(config.table_size_rs_1, Rotation::cur())
                + 3.expr();
            let table_size_minus_one =
                meta.query_advice(config.sorted_table.table_size, Rotation::cur()) - 1.expr();

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
            meta.query_fixed(self.sorted_table.q_first, Rotation::cur()),
            meta.query_advice(self.sorted_table.block_idx, Rotation::cur()),
            meta.query_advice(self.sorted_table.table_kind, Rotation::cur()),
            meta.query_advice(self.sorted_table.table_size, Rotation::cur()),
            meta.query_advice(self.sorted_table.is_predefined, Rotation::cur()),
            meta.query_advice(self.state, Rotation::cur()),
            meta.query_advice(self.symbol, Rotation::cur()),
            meta.query_advice(self.baseline, Rotation::cur()),
            meta.query_advice(self.nb, Rotation::cur()),
            meta.query_advice(self.is_skipped_state, Rotation::cur()),
            meta.query_advice(self.is_padding, Rotation::cur()),
        ]
    }

    /// Lookup table expressions for (symbol, symbol_count) tuple check.
    ///
    /// This check is only done on the last occurence of a particular symbol, i.e. where:
    /// - symbol_count == symbol_count_acc
    pub fn table_exprs_by_symbol(&self, meta: &mut VirtualCells<Fr>) -> Vec<Expression<Fr>> {
        vec![
            meta.query_fixed(self.sorted_table.q_first, Rotation::cur()),
            meta.query_advice(self.sorted_table.block_idx, Rotation::cur()),
            meta.query_advice(self.sorted_table.table_kind, Rotation::cur()),
            meta.query_advice(self.sorted_table.table_size, Rotation::cur()),
            meta.query_advice(self.sorted_table.is_predefined, Rotation::cur()),
            meta.query_advice(self.symbol, Rotation::cur()),
            meta.query_advice(self.symbol_count, Rotation::cur()),
            meta.query_advice(self.symbol_count_acc, Rotation::cur()),
            meta.query_advice(self.is_prob_less_than1, Rotation::cur()),
            meta.query_advice(self.is_padding, Rotation::cur()),
        ]
    }

    /// Lookup table expressions for (table_kind, table_size) to know that the FSE decoder values
    /// were correctly populated even at the "init-state" stage.
    pub fn table_exprs_metadata(&self, meta: &mut VirtualCells<Fr>) -> Vec<Expression<Fr>> {
        vec![
            meta.query_fixed(self.sorted_table.q_first, Rotation::cur()),
            meta.query_fixed(self.sorted_table.q_start, Rotation::cur()),
            meta.query_advice(self.sorted_table.block_idx, Rotation::cur()),
            meta.query_advice(self.sorted_table.table_kind, Rotation::cur()),
            meta.query_advice(self.sorted_table.table_size, Rotation::cur()),
            meta.query_advice(self.sorted_table.is_predefined, Rotation::cur()),
            meta.query_advice(self.is_padding, Rotation::cur()),
        ]
    }
}

/// Contrary to the FSE table where states are allocated as per the state transition rules, in the
/// FseSortedStatesTable, for every symbol with prob>=1 we sort its states in increasing order to
/// appropriately compute the (baseline, nb) fields assigned to those states.
///
/// | State | Symbol | Baseline | Nb  | Baseline Mark |
/// |-------|--------|----------|-----|---------------|
/// | 0     | 0      | 0        | 0   | 0             | <- q_first
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
/// |-------|--------|----------|-----|---------------|
/// | ...   | ...    | ...      | ... | ...           | <- q_start
/// |-------|--------|----------|-----|---------------|
///
/// For more details, refer the [FSE reconstruction][doclink] section.
///
/// [doclink]: https://nigeltao.github.io/blog/2022/zstandard-part-5-fse.html#fse-reconstruction
#[derive(Clone, Debug)]
struct FseSortedStatesTable {
    /// Fixed column to mark the first row of the FSE table layout. We reserve the first row to
    /// populate all 0s. q_start=1 starts from the second row onwards.
    q_first: Column<Fixed>,
    /// Fixed column to mark the start of a new FSE table. FSE tables for LLT, MOT and MLT have a
    /// maximum possible accuracy log of AL=9, i.e. we will have at the most 2^9=256 states in the
    /// FSE table. From the second row onwards, every 256th row will be marked with q_start=1 to
    /// indicate the start of a new FSE table. Within an FSE table, we will only have rows up to
    /// table_size (1 << AL), and the rest of the rows will be marked with is_padding=1.
    q_start: Column<Fixed>,
    /// The block index in which this FSE table is found.
    block_idx: Column<Advice>,
    /// The table kind, i.e. LLT=1, MOT=2 or MLT=3.
    table_kind: Column<Advice>,
    /// The number of states in the FSE table, i.e. 1 << AL.
    table_size: Column<Advice>,
    /// A boolean to indicate whether the FSE table is the one constructed from predefined default
    /// distributions.
    /// For more information, refer the [default distributions][doclink1] and [predefined FSE
    /// tables][doclink2]
    ///
    /// [doclink1]: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#default-distributions
    /// [doclink2]: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#appendix-a---decoding-tables-for-predefined-codes
    is_predefined: Column<Advice>,
    /// The FSE symbol, starting at the first symbol with prob>=1.
    symbol: Column<Advice>,
    /// Boolean column to mark if we are moving to the next symbol.
    is_new_symbol: Column<Advice>,
    /// Represents the number of times this symbol appears in the FSE table. This value does not
    /// change while the symbol in the table remains the same.
    symbol_count: Column<Advice>,
    /// An accumulator that resets to 1 each time we encounter a new symbol in the FSE table.
    /// It increments while the symbol remains the same. When we encounter a new symbol, we
    /// validate that on the previous row, symbol_count equaled symbol_count_acc.
    symbol_count_acc: Column<Advice>,
    /// The state in FSE. In this table the state is in increasing order for each symbol.
    state: Column<Advice>,
    /// Denotes the baseline field.
    baseline: Column<Advice>,
    /// The number of bits to be read from bitstream at this state.
    nb: Column<Advice>,
    /// Boolean column to mark whether the row is a padded row.
    is_padding: Column<Advice>,
    /// Helper gadget to compute whether baseline==0x00.
    baseline_0x00: IsEqualConfig<Fr>,
    /// Helper column to mark the baseline observed at the last state allocated to a symbol.
    last_baseline: Column<Advice>,
    /// The smaller power of two assigned to this state. The following must hold:
    /// - 2 ^ nb == SPoT.
    spot: Column<Advice>,
    /// An accumulator over SPoT value.
    spot_acc: Column<Advice>,
    /// Helper column to remember the smallest spot for that symbol.
    smallest_spot: Column<Advice>,
    /// Helper boolean column which is set only from baseline == 0x00.
    baseline_mark: Column<Advice>,
}

impl FseSortedStatesTable {
    fn configure(
        meta: &mut ConstraintSystem<Fr>,
        pow2_table: Pow2Table<20>,
        u8_table: U8Table,
    ) -> Self {
        let (is_padding, baseline) = (meta.advice_column(), meta.advice_column());

        let config = Self {
            q_first: meta.fixed_column(),
            q_start: meta.fixed_column(),
            block_idx: meta.advice_column(),
            table_kind: meta.advice_column(),
            table_size: meta.advice_column(),
            is_predefined: meta.advice_column(),
            symbol: meta.advice_column(),
            is_new_symbol: meta.advice_column(),
            symbol_count: meta.advice_column(),
            symbol_count_acc: meta.advice_column(),
            state: meta.advice_column(),
            baseline,
            nb: meta.advice_column(),
            is_padding,
            baseline_0x00: IsEqualChip::configure(
                meta,
                |meta| not::expr(meta.query_advice(is_padding, Rotation::cur())),
                |meta| meta.query_advice(baseline, Rotation::cur()),
                |_| 0.expr(),
            ),
            last_baseline: meta.advice_column(),
            spot: meta.advice_column(),
            spot_acc: meta.advice_column(),
            smallest_spot: meta.advice_column(),
            baseline_mark: meta.advice_column(),
        };

        // For every non-padded row, the SPoT is 2^nb.
        meta.lookup_any("FseSortedStatesTable: spot == 1 << nb", |meta| {
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

        // The first row of the FseTable layout, i.e. q_first=true.
        meta.create_gate("FseSortedStatesTable: first row", |meta| {
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

        // The starting row of every FSE table, i.e. q_start=true.
        meta.create_gate("FseSortedStatesTable: start row", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_start, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // The start row is a new symbol.
            cb.require_equal(
                "is_new_symbol==true",
                meta.query_advice(config.is_new_symbol, Rotation::cur()),
                1.expr(),
            );

            cb.require_boolean(
                "is_predefined is boolean",
                meta.query_advice(config.is_predefined, Rotation::cur()),
            );

            cb.gate(condition)
        });

        // Symbols are in increasing order.
        meta.lookup(
            "FseSortedStatesTable: symbols are in increasing order",
            |meta| {
                let condition = and::expr([
                    not::expr(meta.query_fixed(config.q_start, Rotation::cur())),
                    meta.query_advice(config.is_new_symbol, Rotation::cur()),
                ]);

                // Whenever we move to a new symbol (is_new_symbol=true), excluding the first symbol
                // with prob>=1, the symbol is increasing.
                //
                // - symbol::cur - symbol::prev > 0
                //
                // We check that (symbol - symbol_prev - 1) lies in the [0, 256) range.
                let (symbol_curr, symbol_prev) = (
                    meta.query_advice(config.symbol, Rotation::cur()),
                    meta.query_advice(config.symbol, Rotation::prev()),
                );
                let delta = symbol_curr - symbol_prev - 1.expr();

                vec![(condition * delta, u8_table.into())]
            },
        );

        // We continue the same symbol if not a new symbol.
        meta.create_gate("FseSortedStatesTable: same symbol", |meta| {
            let condition = and::expr([
                not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                not::expr(meta.query_fixed(config.q_start, Rotation::cur())),
                not::expr(meta.query_advice(config.is_new_symbol, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // When we are not seeing a new symbol, make sure the symbol is equal to the symbol on
            // the previous row.
            cb.require_equal(
                "prob>=1: same symbol",
                meta.query_advice(config.symbol, Rotation::cur()),
                meta.query_advice(config.symbol, Rotation::prev()),
            );

            cb.gate(condition)
        });

        // While continuing the same symbol, states are in increasing order.
        meta.lookup(
            "FseSortedStatesTable: states are in increasing order",
            |meta| {
                let condition = and::expr([
                    not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                    not::expr(meta.query_fixed(config.q_start, Rotation::cur())),
                    not::expr(meta.query_advice(config.is_new_symbol, Rotation::cur())),
                    not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
                ]);

                // While traversing the same symbol (is_new_symbol=false), the states allocated to
                // it in the FseSortedStatesTable are in increasing order. So we check that:
                //
                // - state::cur - state::prev > 0
                //
                // We check that (state::cur - state::prev - 1) lies in the [0, 256) range.
                let (state_curr, state_prev) = (
                    meta.query_advice(config.state, Rotation::cur()),
                    meta.query_advice(config.state, Rotation::prev()),
                );
                let delta = state_curr - state_prev - 1.expr();

                vec![(condition * delta, u8_table.into())]
            },
        );

        // All rows in an instance of FSE table, except the starting row (q_start=true).
        meta.create_gate(
            "FseSortedStatesTable: every FSE table (except q_start=1)",
            |meta| {
                let condition = not::expr(meta.query_fixed(config.q_start, Rotation::cur()));

                let mut cb = BaseConstraintBuilder::default();

                // FSE table's columns that remain unchanged.
                for column in [
                    config.block_idx,
                    config.table_kind,
                    config.table_size,
                    config.is_predefined,
                ] {
                    cb.require_equal(
                        "FseSortedStatesTable: columns that remain unchanged",
                        meta.query_advice(column, Rotation::cur()),
                        meta.query_advice(column, Rotation::prev()),
                    );
                }

                // Once we enter padding territory, we stay in padding territory, i.e.
                // is_padding transitions from 0 -> 1 only once.
                let (is_padding_curr, is_padding_prev) = (
                    meta.query_advice(config.is_padding, Rotation::cur()),
                    meta.query_advice(config.is_padding, Rotation::prev()),
                );
                let is_padding_delta = is_padding_curr.expr() - is_padding_prev.expr();
                cb.require_boolean("is_padding is boolean", is_padding_curr.expr());
                cb.require_boolean("is_padding_delta is boolean", is_padding_delta);

                cb.gate(condition)
            },
        );

        // For every new symbol detected.
        meta.create_gate("FseSortedStatesTable: new symbol", |meta| {
            let condition = and::expr([
                meta.query_advice(config.is_new_symbol, Rotation::cur()),
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

            cb.require_boolean("is_baseline_mark is boolean", is_baseline_mark.expr());
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

        // Whenever we continue allocating states to the same symbol.
        meta.create_gate("FseSortedStatesTable: same symbol, new state", |meta| {
            let condition = and::expr([
                not::expr(meta.query_advice(config.is_new_symbol, Rotation::cur())),
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
                    "FseSortedStatesTable: unchanged columns (same symbol)",
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
                "spot_acc accumulates",
                meta.query_advice(config.spot_acc, Rotation::cur()),
                meta.query_advice(config.spot_acc, Rotation::prev())
                    + meta.query_advice(config.spot, Rotation::cur()),
            );

            let (baseline_mark_curr, baseline_mark_prev) = (
                meta.query_advice(config.baseline_mark, Rotation::cur()),
                meta.query_advice(config.baseline_mark, Rotation::prev()),
            );
            let baseline_mark_delta = baseline_mark_curr.expr() - baseline_mark_prev;
            cb.require_boolean("baseline_mark is boolean", baseline_mark_curr);
            cb.require_boolean("baseline_mark_delta is boolean", baseline_mark_delta.expr());

            // baseline == baseline_mark_delta == 1 ? 0x00 : baseline_prev + spot_prev
            let (baseline_curr, baseline_prev, spot_prev) = (
                meta.query_advice(config.baseline, Rotation::cur()),
                meta.query_advice(config.baseline, Rotation::prev()),
                meta.query_advice(config.spot, Rotation::prev()),
            );
            cb.require_equal(
                "baseline calculation",
                baseline_curr,
                select::expr(baseline_mark_delta, 0x00.expr(), baseline_prev + spot_prev),
            );

            cb.gate(condition)
        });

        config
    }
}

impl LookupTable<Fr> for FseSortedStatesTable {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![
            self.block_idx.into(),
            self.table_kind.into(),
            self.table_size.into(),
            self.symbol.into(),
            self.symbol_count.into(),
            self.state.into(),
            self.baseline.into(),
            self.nb.into(),
            self.is_padding.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("block_idx"),
            String::from("table_kind"),
            String::from("table_size"),
            String::from("symbol"),
            String::from("symbol_count"),
            String::from("state"),
            String::from("baseline"),
            String::from("nb"),
            String::from("is_padding"),
        ]
    }
}
