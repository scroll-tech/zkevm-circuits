use gadgets::{
    is_equal::*,
    is_zero::*,
    util::{and, not, select, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::LookupTable,
    util::Field,
};

use crate::aggregation::{decoder::witgen::AddressTableRow, util::BooleanAdvice};

/// Table used carry the raw sequence instructions parsed from sequence section
/// and would be later transformed as the back-reference instructions
///
/// For every block, one row in the table represent a single sequence instruction
/// in the sequence section, and handle all data parsed from the same sequence.
/// The 'block_index' is a 1-index for each block with n sequences in its
/// sequence section, the parsed value from bitstream for current sequence is put
/// in the 'input cols' section (`literal_len`, `match_offset` and `match_len`)
/// The transformed sequence instructions is put in 'output cols' section (
/// `acc_literal_len`, `offset` and `match_len`),
/// notice we can use `match_len` without transformation.
///
/// | enabled |block_index| n_seq |seq_index|s_beginning|<input cols>|<output cols>|
/// |---------|-----------|-------|---------|-----------|------------|-------------|
/// |     1   |    1      |   30  |    0    |     1     |            |             |
/// |     1   |    1      |   30  |    1    |     0     |  (4,2,4)   |  (4,4,4)    |
/// |     1   |    1      |   30  |    2    |     0     |  (1,5,2)   |  (5,5,2)    |
/// |     1   |    1      |   30  |    3    |     0     |  (0,2,1)   |  (5,1,1)    |
/// |     1   |   ...     |   30  |   ...   |     0     |    ...     |             |
/// |     1   |    1      |   30  |   30    |     0     | (1,50,11)  |             |
/// |     1   |    2      |   20  |    0    |     1     |            |             |
/// |     1   |    2      |   20  |    1    |     0     | (3,52,13)  |             |
/// |     1   |   ...     |   20  |   ...   |     0     |            |             |
/// |     1   |    2      |   20  |   20    |     0     |            |             |
/// |     1   |    3      |   4   |    0    |     1     |            |             |
/// |    ...  |   ...     |  ...  |   ...   |    ...    |            |             |
/// |     1   |   998     |   0   |    0    |     1     |            |             |
/// |     1   |   999     |   0   |    0    |     1     |            |             |
///
/// When all sequences from compressed data has been handled, the rest rows being enabled
/// (q_enabled is true) has to be padded with increased block index, with `n_seq` is 0
/// and `s_beginning` is true
///
/// The transform from 'input cols' to 'output cols' according to zstd's spec
/// include following steps:
/// 1. accumulate the copied literal bytes in one section
/// 2. for match offset > 3, set the actual offset val is -=3, else we refer it
/// from the reference tables represented by 'repeated_offset_1/2/3' cols
/// 3. After each sequence, the reference tables is updated according to the
/// value of cooked offset and whether `literal_len` is zero
///  
/// |literal_len|match_offset|acc_lit_len| offset |match_len|rep_offset_1|rep_offset_2|rep_offset_3|s_beginning|
/// |-----------|------------|-----------|--------|---------|------------|------------|------------|-----------|
/// |           |            |           |        |         |     1      |     4      |      8     |     1     |
/// |    4      |     2      |    4      |   4    |    4    |     4      |     1      |      8     |     0     |
/// |    1      |     5      |    5      |   5    |    2    |     5      |     4      |      1     |     0     |
/// |    0      |     2      |    5      |   1    |    1    |     1      |     5      |      4     |     0     |
/// |           |            |           |        |         |            |            |            |     0     |

#[derive(Clone, Debug)]
pub struct SeqInstTable<F: Field> {
    // active flag, one active row parse
    q_enabled: Column<Fixed>,

    // 1-index for each block, keep the same for each row
    // until all sequenced has been handled
    block_index: Column<Advice>,
    // the count of sequences in one block, keey the same
    // for each row when block index is not changed
    n_seq: Column<Advice>,
    // the 1-indexed seq number (1..=n_seq) for each
    // sequence. We have extra row at the beginning of
    // each block with seq_index is 0
    seq_index: Column<Advice>,
    // the flag for the first row in each block (i.e. seq_index is 0)
    s_beginning: BooleanAdvice,

    // the value directly decoded from bitstream, one row
    // for one sequence
    literal_len: Column<Advice>,
    match_offset: Column<Advice>,
    match_len: Column<Advice>,

    // exported instructions for one sequence,
    // note the match_len would be exported as-is
    // updated offset
    offset: Column<Advice>,
    // updated (acc) literal len
    acc_literal_len: Column<Advice>,

    // the reference table for repeated offset
    rep_offset_1: Column<Advice>,
    rep_offset_2: Column<Advice>,
    rep_offset_3: Column<Advice>,

    // 3 mode on update ref table, corresponding to
    // 1: offset = 1 (if lt_len != 0)
    ref_update_mode_1: BooleanAdvice,
    // 2: offset = 2 or offset = 1 (if lt_len == 0)
    ref_update_mode_2: BooleanAdvice,
    // 3: offset = 3 or offset = 2 (if lt_len == 0)
    ref_update_mode_3: BooleanAdvice,
    // 4: special case of offset = 3 (if lt_len == 0)
    ref_update_mode_4: BooleanAdvice,

    // detect if literal_len is zero
    literal_is_zero: IsZeroConfig<F>,
    // detect if seq_index in current row equal
    // to n_seq (i.e. n_seq - seq_index is zero)
    seq_index_is_n_seq: IsEqualConfig<F>,
    // detect if current match_offset is 1, 2 or 3
    offset_is_1: IsEqualConfig<F>,
    offset_is_2: IsEqualConfig<F>,
    offset_is_3: IsEqualConfig<F>,

    // detect if rep_offset_1 is 0 (indicate the data
    // is corrupt)
    ref_offset_1_is_zero: IsZeroConfig<F>,
}

impl<F: Field> LookupTable<F> for SeqInstTable<F> {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enabled.into(),
            self.block_index.into(),
            self.n_seq.into(),
            self.s_beginning.column.into(),
            self.seq_index.into(),
            self.literal_len.into(),
            self.match_offset.into(),
            self.match_len.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enabled"),
            String::from("n_seq"),
            String::from("block_index"),
            String::from("s_beginning"),
            String::from("seq_index"),
            String::from("literal_len"),
            String::from("match_offset"),
            String::from("match_len"),
        ]
    }
}

#[derive(Clone, Debug)]
struct ChipContext<F: Field> {
    literal_is_zero_chip: IsZeroChip<F>,
    ref_offset_1_is_zero_chip: IsZeroChip<F>,
    seq_index_chip: IsEqualChip<F>,
    offset_is_1_chip: IsEqualChip<F>,
    offset_is_2_chip: IsEqualChip<F>,
    offset_is_3_chip: IsEqualChip<F>,
}

impl<F: Field> ChipContext<F> {
    fn construct(config: &SeqInstTable<F>) -> Self {
        let literal_is_zero_chip = IsZeroChip::construct(config.literal_is_zero.clone());
        let ref_offset_1_is_zero_chip = IsZeroChip::construct(config.ref_offset_1_is_zero.clone());
        let seq_index_chip = IsEqualChip::construct(config.seq_index_is_n_seq.clone());
        let offset_is_1_chip = IsEqualChip::construct(config.offset_is_1.clone());
        let offset_is_2_chip = IsEqualChip::construct(config.offset_is_2.clone());
        let offset_is_3_chip = IsEqualChip::construct(config.offset_is_3.clone());

        Self {
            literal_is_zero_chip,
            ref_offset_1_is_zero_chip,
            seq_index_chip,
            offset_is_1_chip,
            offset_is_2_chip,
            offset_is_3_chip,
        }
    }
}

impl<F: Field> SeqInstTable<F> {
    /// The sequence count should be lookuped by parsed bitstream,
    /// used the block index and value for sequence count tag to
    /// lookup (`true`, `block_index`, 1, `value`)
    /// The table would be padded by increased block index to
    /// fill all rows being enabled
    ///
    /// | enabled |block_index| flag  | n_seq |
    /// |---------|-----------|-------|-------|
    /// |     1   |    1      |   1   |   30  |
    /// |     1   |   ...     |  ...  |   30  |
    /// |     1   |    2      |   1   |   20  |
    /// |     1   |   ...     |  ...  |   20  |
    /// |     1   |    3      |   1   |   4   |
    /// |    ...  |   ...     |   ... |  ...  |
    /// |     1   |   999     |   1   |   0   |
    pub fn seq_count_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_fixed(self.q_enabled, Rotation::cur()),
            meta.query_advice(self.block_index, Rotation::cur()),
            self.s_beginning.expr_at(meta, Rotation::cur()),
            meta.query_advice(self.n_seq, Rotation::cur()),
        ]
    }

    /// The sequence values should be lookuped by parsed bitstream,
    /// used the block index and value with each sequence tag for
    /// multiple lookup (`true`, `block_index`, 0, `seq_index`, `value`) on
    /// corresponding value column (literal len, offset, match len)
    /// , or a lookup with suitable rotations
    /// | enabled |block_index|s_beginning|seq_index| literal | offset | match |
    /// |---------|-----------|-----------|---------|---------|--------|-------|
    /// |     1   |    1      |     0     |    1    |   4     |   2    |   4   |
    /// |     1   |    1      |     0     |    2    |   1     |   5    |   2   |
    /// |     1   |    1      |     0     |    3    |   0     |   2    |   3   |
    /// |     1   |   ...     |     0     |   ...   |  ...    |  ...   |  ...  |
    /// |     1   |    1      |     0     |   30    |   1     |  50    |  11   |
    /// |     1   |    2      |     0     |    1    |   3     |  52    |  13   |
    /// |     1   |   ...     |     0     |   ...   |  ...    |  ...   |  ...  |
    pub fn seq_values_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_fixed(self.q_enabled, Rotation::cur()),
            meta.query_advice(self.block_index, Rotation::cur()),
            self.s_beginning.expr_at(meta, Rotation::cur()),
            meta.query_advice(self.seq_index, Rotation::cur()),
            meta.query_advice(self.literal_len, Rotation::cur()),
            meta.query_advice(self.match_offset, Rotation::cur()),
            meta.query_advice(self.match_len, Rotation::cur()),
        ]
    }

    /// Obtian the instruction table cols
    pub fn instructions(&self) -> [Column<Advice>; 5] {
        [
            self.block_index,
            self.seq_index,
            self.offset,
            self.acc_literal_len,
            self.match_len,
        ]
    }

    /// Construct the sequence instruction table
    /// the maximum rotation is prev(1), next(1)
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let q_enabled = meta.fixed_column();
        let block_index = meta.advice_column();
        let n_seq = meta.advice_column();
        let literal_len = meta.advice_column();
        let match_offset = meta.advice_column();
        let match_len = meta.advice_column();
        let offset = meta.advice_column();
        let acc_literal_len = meta.advice_column();
        let s_beginning =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enabled, Rotation::cur()));
        let seq_index = meta.advice_column();
        let rep_offset_1 = meta.advice_column();
        let rep_offset_2 = meta.advice_column();
        let rep_offset_3 = meta.advice_column();
        let ref_update_mode_1 =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enabled, Rotation::cur()));
        let ref_update_mode_2 =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enabled, Rotation::cur()));
        let ref_update_mode_3 =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enabled, Rotation::cur()));
        let ref_update_mode_4 =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enabled, Rotation::cur()));

        let [literal_is_zero, ref_offset_1_is_zero] = [literal_len, rep_offset_1].map(|col| {
            let inv_col = meta.advice_column();
            IsZeroChip::configure(
                meta,
                |meta| meta.query_fixed(q_enabled, Rotation::cur()),
                |meta| meta.query_advice(col, Rotation::cur()),
                inv_col,
            )
        });
        let [offset_is_1, offset_is_2, offset_is_3] = [1, 2, 3].map(|val| {
            IsEqualChip::configure(
                meta,
                |meta| meta.query_fixed(q_enabled, Rotation::cur()),
                |meta| meta.query_advice(match_offset, Rotation::cur()),
                |_| val.expr(),
            )
        });
        let seq_index_is_n_seq = IsEqualChip::configure(
            meta,
            |meta| meta.query_fixed(q_enabled, Rotation::cur()),
            |meta| meta.query_advice(seq_index, Rotation::cur()),
            |meta| meta.query_advice(n_seq, Rotation::cur()),
        );

        // seq_index must increment and compare with n_seq for seq border
        meta.create_gate("seq index and section borders", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let seq_index_next = meta.query_advice(seq_index, Rotation::next());
            let seq_index = meta.query_advice(seq_index, Rotation::cur());
            let is_seq_border = &seq_index_is_n_seq;

            cb.require_equal(
                "seq index must increment or 0 in s_beginning",
                select::expr(is_seq_border.expr(), 0.expr(), seq_index.expr() + 1.expr()),
                seq_index_next.expr(),
            );

            let s_beginning = s_beginning.expr_at(meta, Rotation::next());

            cb.condition(not::expr(is_seq_border.expr()), |cb| {
                cb.require_zero(
                    "s_beginning on enabled after seq border",
                    s_beginning.expr(),
                )
            });

            cb.gate(meta.query_fixed(q_enabled, Rotation::next()))
        });

        // block index must be increment at seq border, so section for each
        // block index can occur once
        // and the lookup from seq_table enforce valid block / seq / s_beginning
        // must be put
        meta.create_gate("block index", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let block_index_next = meta.query_advice(block_index, Rotation::next());
            let block_index = meta.query_advice(block_index, Rotation::cur());

            let is_seq_border = &seq_index_is_n_seq;

            cb.require_equal(
                "block can only increase in seq border",
                select::expr(
                    is_seq_border.expr(),
                    block_index.expr() + 1.expr(),
                    block_index.expr(),
                ),
                block_index_next,
            );
            cb.gate(meta.query_fixed(q_enabled, Rotation::next()))
        });

        // so, we enforce s_beginning enabled for valid block index
        meta.create_gate("border constraints", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            let s_beginning = s_beginning.expr_at(meta, Rotation::cur());

            let repeated_offset_pairs = [rep_offset_1, rep_offset_2, rep_offset_3].map(|col| {
                (
                    meta.query_advice(col, Rotation::cur()),
                    meta.query_advice(col, Rotation::prev()),
                )
            });

            for (repeated_offset, repeated_offset_prev) in repeated_offset_pairs {
                cb.condition(s_beginning.expr(), |cb| {
                    cb.require_equal(
                        "offset must be inherited in border",
                        repeated_offset,
                        repeated_offset_prev,
                    )
                });
            }

            let literal_len = meta.query_advice(literal_len, Rotation::cur());
            cb.require_equal(
                "literal len accumulation",
                select::expr(
                    s_beginning.expr(),
                    literal_len.expr(),
                    literal_len.expr() + meta.query_advice(acc_literal_len, Rotation::prev()),
                ),
                meta.query_advice(acc_literal_len, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        meta.create_gate("offset update mode", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "ref update mode 1",
                and::expr([not::expr(literal_is_zero.expr()), offset_is_1.expr()]),
                ref_update_mode_1.expr_at(meta, Rotation::cur()),
            );

            cb.require_equal(
                "ref update mode 2",
                select::expr(
                    literal_is_zero.expr(),
                    offset_is_1.expr(),
                    offset_is_2.expr(),
                ),
                ref_update_mode_2.expr_at(meta, Rotation::cur()),
            );

            cb.require_equal(
                "ref update mode 3",
                select::expr(
                    literal_is_zero.expr(),
                    offset_is_2.expr(),
                    offset_is_3.expr(),
                ),
                ref_update_mode_3.expr_at(meta, Rotation::cur()),
            );

            cb.require_equal(
                "ref update mode 4",
                and::expr([literal_is_zero.expr(), offset_is_3.expr()]),
                ref_update_mode_4.expr_at(meta, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        // offset is in-section (not s_beginning)
        meta.create_gate("offset reference", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let offset_val = meta.query_advice(offset, Rotation::cur());
            let offset = meta.query_advice(match_offset, Rotation::cur());

            let [rep_offset_1_prev, rep_offset_2_prev, rep_offset_3_prev] =
                [rep_offset_1, rep_offset_2, rep_offset_3]
                    .map(|col| meta.query_advice(col, Rotation::prev()));

            let [rep_offset_1, rep_offset_2, rep_offset_3] =
                [rep_offset_1, rep_offset_2, rep_offset_3]
                    .map(|col| meta.query_advice(col, Rotation::cur()));

            let ref_update_mode_1 = ref_update_mode_1.expr_at(meta, Rotation::cur());
            let ref_update_mode_2 = ref_update_mode_2.expr_at(meta, Rotation::cur());
            let ref_update_mode_3 = ref_update_mode_3.expr_at(meta, Rotation::cur());
            let ref_update_mode_4 = ref_update_mode_4.expr_at(meta, Rotation::cur());
            let s_is_offset_ref = ref_update_mode_1.expr()
                + ref_update_mode_2.expr()
                + ref_update_mode_3.expr()
                + ref_update_mode_4.expr();

            // and ref in offset_1 is updated by current value
            cb.require_equal(
                "set offset 0 to offset val",
                offset_val.expr(),
                rep_offset_1.expr(),
            );

            // following we ref updated table

            // for no-ref ref offset table 2/3 is
            // updated with a "shift" nature, and 1 is cooked_offset - 3
            cb.condition(not::expr(s_is_offset_ref.expr()), |cb| {
                cb.require_equal(
                    "offset is cooked_val - 3",
                    offset.expr() - 3.expr(),
                    rep_offset_1.expr(),
                );

                cb.require_equal(
                    "shift 1 -> 2",
                    rep_offset_1_prev.expr(),
                    rep_offset_2.expr(),
                );
                cb.require_equal(
                    "shift 2 -> 3",
                    rep_offset_2_prev.expr(),
                    rep_offset_3.expr(),
                );
            });

            // update mode 1 (offset == 1 and lit_len != 0)
            cb.condition(ref_update_mode_1.expr(), |cb| {
                cb.require_equal(
                    "copy offset 1 for ref 1",
                    rep_offset_1_prev.expr(),
                    rep_offset_1.expr(),
                );
                cb.require_equal(
                    "copy offset 2 for ref 1",
                    rep_offset_2_prev.expr(),
                    rep_offset_2.expr(),
                );
                cb.require_equal(
                    "copy offset 3 for ref 1",
                    rep_offset_3_prev.expr(),
                    rep_offset_3.expr(),
                );
            });
            // update mode 2 (offset == 2 / offset == 1 while lit_len != 0)
            cb.condition(ref_update_mode_2.expr(), |cb| {
                cb.require_equal(
                    "swap 1&2 for ref 2",
                    rep_offset_2_prev.expr(),
                    rep_offset_1.expr(),
                );
                cb.require_equal(
                    "swap 1&2 for ref 2",
                    rep_offset_1_prev.expr(),
                    rep_offset_2.expr(),
                );
                cb.require_equal(
                    "copy offset 3 for ref 2",
                    rep_offset_3_prev.expr(),
                    rep_offset_3.expr(),
                );
            });
            // update mode 3 (offset == 3 / offset == 2 while lit_len != 0)
            cb.condition(ref_update_mode_3.expr(), |cb| {
                cb.require_equal(
                    "rotate 3-1 for ref 3",
                    rep_offset_3_prev.expr(),
                    rep_offset_1.expr(),
                );
                cb.require_equal(
                    "rotate 3-1 for ref 3",
                    rep_offset_1_prev.expr(),
                    rep_offset_2.expr(),
                );
                cb.require_equal(
                    "rotate 3-1 for ref 3",
                    rep_offset_2_prev.expr(),
                    rep_offset_3.expr(),
                );
            });
            // update mode 4 (offset == 3 while lit_len == 0)
            cb.condition(ref_update_mode_4.expr(), |cb| {
                cb.require_zero("data must not corrupt", ref_offset_1_is_zero.expr());
                cb.require_equal(
                    "take ref 1 and minus 1 for ref 4",
                    rep_offset_1_prev.expr() - 1.expr(),
                    rep_offset_1.expr(),
                );
                cb.require_equal(
                    "rotate 3-1 for ref 4",
                    rep_offset_1_prev.expr(),
                    rep_offset_2.expr(),
                );
                cb.require_equal(
                    "rotate 3-1 for ref 4",
                    rep_offset_2_prev.expr(),
                    rep_offset_3.expr(),
                );
            });

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::cur())
                    * not::expr(s_beginning.expr_at(meta, Rotation::cur())),
            )
        });

        // the beginning of following rows must be constrained
        meta.enable_equality(block_index);
        meta.enable_equality(seq_index);
        meta.enable_equality(rep_offset_1);
        meta.enable_equality(rep_offset_2);
        meta.enable_equality(rep_offset_3);

        debug_assert!(meta.degree() <= 9);
        debug_assert!(meta.clone().chunk_lookups().degree() <= 9);

        Self {
            q_enabled,
            block_index,
            n_seq,
            literal_len,
            match_offset,
            match_len,
            offset,
            acc_literal_len,
            s_beginning,
            seq_index,
            rep_offset_1,
            rep_offset_2,
            rep_offset_3,
            offset_is_1,
            offset_is_2,
            offset_is_3,
            literal_is_zero,
            seq_index_is_n_seq,
            ref_offset_1_is_zero,
            ref_update_mode_1,
            ref_update_mode_2,
            ref_update_mode_3,
            ref_update_mode_4,
        }
    }

    // assign a heading / padding row before a each block
    fn assign_heading_row(
        &self,
        region: &mut Region<F>,
        offset: usize,
        block_ind: u64,
        n_seq: usize,
        chip_ctx: &ChipContext<F>,
        offset_table: &[u64; 3],
    ) -> Result<usize, Error> {
        region.assign_fixed(
            || "enable row",
            self.q_enabled,
            offset,
            || Value::known(F::one()),
        )?;

        for col in [
            self.rep_offset_1,
            self.rep_offset_2,
            self.rep_offset_3,
            self.match_len,
            self.match_offset,
            self.literal_len,
            self.acc_literal_len,
            self.offset,
            self.seq_index,
            self.ref_update_mode_1.column,
            self.ref_update_mode_2.column,
            self.ref_update_mode_3.column,
            self.ref_update_mode_4.column,
        ] {
            region.assign_advice(|| "padding values", col, offset, || Value::known(F::zero()))?;
        }

        for (col, val) in [
            (self.rep_offset_1, offset_table[0]),
            (self.rep_offset_2, offset_table[1]),
            (self.rep_offset_3, offset_table[2]),
            (self.block_index, block_ind),
            (self.n_seq, n_seq as u64),
        ] {
            region.assign_advice(
                || "header block fill",
                col,
                offset,
                || Value::known(F::from(val)),
            )?;
        }

        chip_ctx
            .literal_is_zero_chip
            .assign(region, offset, Value::known(F::zero()))?;
        chip_ctx.ref_offset_1_is_zero_chip.assign(
            region,
            offset,
            Value::known(F::from(offset_table[0])),
        )?;

        for (chip, val) in [
            (&chip_ctx.offset_is_1_chip, F::from(1u64)),
            (&chip_ctx.offset_is_2_chip, F::from(2u64)),
            (&chip_ctx.offset_is_3_chip, F::from(3u64)),
            (&chip_ctx.seq_index_chip, F::from(n_seq as u64)),
        ] {
            chip.assign(region, offset, Value::known(F::zero()), Value::known(val))?;
        }

        region.assign_advice(
            || "set beginning flag",
            self.s_beginning.column,
            offset,
            || Value::known(F::one()),
        )?;

        Ok(offset + 1)
    }

    // padding for the rest row
    fn padding_rows(
        &self,
        region: &mut Region<F>,
        mut offset: usize,
        till_offset: usize,
        mut blk_index: u64,
        chip_ctx: &ChipContext<F>,
        offset_table: &[u64; 3],
    ) -> Result<(), Error> {
        // pad the rest rows until final row
        while offset < till_offset {
            offset =
                self.assign_heading_row(region, offset, blk_index, 0, chip_ctx, offset_table)?;

            blk_index += 1;
        }

        Ok(())
    }

    // assign a single block from current offset
    // and return the offset below the last used row
    #[allow(clippy::too_many_arguments)]
    fn assign_block<'a>(
        &self,
        region: &mut Region<F>,
        mut offset: usize,
        block_ind: u64,
        n_seq: usize,
        table_rows: impl Iterator<Item = &'a AddressTableRow>,
        chip_ctx: &ChipContext<F>,
        offset_table: &mut [u64; 3],
    ) -> Result<usize, Error> {
        let mut seq_index = 0u64;
        let mut acc_literal_len = 0u64;

        for table_row in table_rows {
            seq_index += 1;

            region.assign_fixed(
                || "enable row",
                self.q_enabled,
                offset,
                || Value::known(F::one()),
            )?;

            let ref_update_mode = match table_row.cooked_match_offset {
                0 => panic!("invalid cooked offset"),
                1 => {
                    if table_row.literal_length == 0 {
                        2
                    } else {
                        1
                    }
                }
                2 => {
                    if table_row.literal_length == 0 {
                        3
                    } else {
                        2
                    }
                }
                3 => {
                    if table_row.literal_length == 0 {
                        4
                    } else {
                        3
                    }
                }
                _ => 0,
            };

            acc_literal_len += table_row.literal_length;
            // sanity check
            assert_eq!(acc_literal_len, table_row.literal_length_acc);

            offset_table[0] = table_row.repeated_offset1;
            offset_table[1] = table_row.repeated_offset2;
            offset_table[2] = table_row.repeated_offset3;

            for (name, col, val) in [
                ("beginning flag", self.s_beginning.column, F::zero()),
                (
                    "offset table 1",
                    self.rep_offset_1,
                    F::from(offset_table[0]),
                ),
                (
                    "offset table 2",
                    self.rep_offset_2,
                    F::from(offset_table[1]),
                ),
                (
                    "offset table 3",
                    self.rep_offset_3,
                    F::from(offset_table[2]),
                ),
                ("mlen", self.match_len, F::from(table_row.match_length)),
                (
                    "moff",
                    self.match_offset,
                    F::from(table_row.cooked_match_offset),
                ),
                ("llen", self.literal_len, F::from(table_row.literal_length)),
                ("llen_acc", self.acc_literal_len, F::from(acc_literal_len)),
                ("offset", self.offset, F::from(table_row.actual_offset)),
                ("seq ind", self.seq_index, F::from(seq_index)),
                ("block ind", self.block_index, F::from(block_ind)),
                ("n_seq", self.n_seq, F::from(n_seq as u64)),
                (
                    "ref update mode",
                    self.ref_update_mode_1.column,
                    if ref_update_mode == 1 {
                        F::one()
                    } else {
                        F::zero()
                    },
                ),
                (
                    "ref update mode",
                    self.ref_update_mode_2.column,
                    if ref_update_mode == 2 {
                        F::one()
                    } else {
                        F::zero()
                    },
                ),
                (
                    "ref update mode",
                    self.ref_update_mode_3.column,
                    if ref_update_mode == 3 {
                        F::one()
                    } else {
                        F::zero()
                    },
                ),
                (
                    "ref update mode",
                    self.ref_update_mode_4.column,
                    if ref_update_mode == 4 {
                        F::one()
                    } else {
                        F::zero()
                    },
                ),
            ] {
                region.assign_advice(|| name, col, offset, || Value::known(val))?;
            }

            for (chip, val) in [
                (
                    &chip_ctx.literal_is_zero_chip,
                    F::from(table_row.literal_length),
                ),
                (
                    &chip_ctx.ref_offset_1_is_zero_chip,
                    F::from(offset_table[0]),
                ),
            ] {
                chip.assign(region, offset, Value::known(val))?;
            }

            for (chip, val_l, val_r) in [
                (
                    &chip_ctx.offset_is_1_chip,
                    F::from(table_row.cooked_match_offset),
                    F::from(1u64),
                ),
                (
                    &chip_ctx.offset_is_2_chip,
                    F::from(table_row.cooked_match_offset),
                    F::from(2u64),
                ),
                (
                    &chip_ctx.offset_is_3_chip,
                    F::from(table_row.cooked_match_offset),
                    F::from(3u64),
                ),
                (
                    &chip_ctx.seq_index_chip,
                    F::from(seq_index),
                    F::from(n_seq as u64),
                ),
            ] {
                chip.assign(region, offset, Value::known(val_l), Value::known(val_r))?;
            }
            offset += 1;
        }

        assert_eq!(n_seq as u64, seq_index);

        Ok(offset)
    }

    // assign the top row
    fn init_top_row(
        &self,
        region: &mut Region<F>,
        from_offset: Option<usize>,
    ) -> Result<usize, Error> {
        let offset = from_offset.unwrap_or_default();
        // top row constraint
        for (col, val) in [
            (self.rep_offset_1, F::from(1u64)),
            (self.rep_offset_2, F::from(4u64)),
            (self.rep_offset_3, F::from(8u64)),
        ] {
            region.assign_advice_from_constant(|| "top row", col, offset, val)?;
        }

        for col in [self.block_index, self.seq_index, self.acc_literal_len] {
            region.assign_advice(|| "top row flush", col, offset, || Value::known(F::zero()))?;
        }

        for (col, val) in [(self.block_index, F::one()), (self.seq_index, F::zero())] {
            region.assign_advice_from_constant(|| "begin row constraint", col, offset + 1, val)?;
        }

        Ok(offset + 1)
    }

    /// assign with multiple blocks, known the number of
    /// sequences in advance
    pub fn assign<'a, R: ExactSizeIterator<Item = &'a AddressTableRow>>(
        &self,
        layouter: &mut impl Layouter<F>,
        table_rows: impl IntoIterator<Item = R> + Clone,
        enabled_rows: usize,
    ) -> Result<(), Error> {
        let chip_ctx = ChipContext::construct(self);
        layouter.assign_region(
            || "addr table",
            |mut region| {
                let mut offset_table: [u64; 3] = [1, 4, 8];
                let mut blk_id = 0u64;
                let mut offset = self.init_top_row(&mut region, None)?;
                for (i, rows_in_blk) in table_rows.clone().into_iter().enumerate() {
                    blk_id = (i + 1) as u64;
                    let n_seqs = rows_in_blk.len();
                    offset = self.assign_heading_row(
                        &mut region,
                        offset,
                        blk_id,
                        n_seqs,
                        &chip_ctx,
                        &offset_table,
                    )?;
                    offset = self.assign_block(
                        &mut region,
                        offset,
                        blk_id,
                        n_seqs,
                        rows_in_blk,
                        &chip_ctx,
                        &mut offset_table,
                    )?;
                    assert!(offset < enabled_rows);
                }

                self.padding_rows(
                    &mut region,
                    offset,
                    enabled_rows,
                    blk_id + 1,
                    &chip_ctx,
                    &offset_table,
                )?;

                Ok(())
            },
        )
    }

    #[cfg(test)]
    pub fn mock_assign(
        &self,
        layouter: &mut impl Layouter<F>,
        table_rows: &[AddressTableRow],
        enabled_rows: usize,
    ) -> Result<(), Error> {
        let chip_ctx = ChipContext::construct(self);
        layouter.assign_region(
            || "addr table",
            |mut region| {
                let mut offset_table: [u64; 3] = [1, 4, 8];
                let offset = self.init_top_row(&mut region, None)?;
                let offset = self.assign_heading_row(
                    &mut region,
                    offset,
                    1,
                    table_rows.len(),
                    &chip_ctx,
                    &offset_table,
                )?;
                let offset = self.assign_block(
                    &mut region,
                    offset,
                    1,
                    table_rows.len(),
                    table_rows.iter(),
                    &chip_ctx,
                    &mut offset_table,
                )?;
                assert!(offset < enabled_rows);

                self.padding_rows(
                    &mut region,
                    offset,
                    enabled_rows,
                    2,
                    &chip_ctx,
                    &offset_table,
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };

    #[derive(Clone, Debug)]
    struct SeqTable(Vec<AddressTableRow>);

    impl Circuit<Fr> for SeqTable {
        type Config = SeqInstTable<Fr>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let const_col = meta.fixed_column();
            meta.enable_constant(const_col);

            Self::Config::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            config.mock_assign(&mut layouter, &self.0, 15)?;

            Ok(())
        }
    }

    #[test]
    fn seqinst_table_gates() {
        // example comes from zstd's spec
        let circuit = SeqTable(AddressTableRow::mock_samples(&[
            [1114, 11, 1111, 1, 4],
            [1, 22, 1111, 1, 4],
            [2225, 22, 2222, 1111, 1],
            [1114, 111, 1111, 2222, 1111],
            [3336, 33, 3333, 1111, 2222],
            [2, 22, 1111, 3333, 2222],
            [3, 33, 2222, 1111, 3333],
            [3, 0, 2221, 2222, 1111],
            [1, 0, 2222, 2221, 1111],
        ]));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }
}
