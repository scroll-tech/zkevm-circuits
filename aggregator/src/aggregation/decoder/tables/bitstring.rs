use gadgets::util::{and, not, select, Expr};
use halo2_proofs::{
    circuit::Layouter,
    halo2curves::bn256::Fr,
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, RangeTable, U8Table},
};

use crate::aggregation::decoder::witgen::ZstdWitnessRow;

/// In the process of decoding zstd encoded data, there are several scenarios in which we process
/// bits instead of bytes, for instance:
/// - decoding FSE table
/// - applying the FSE table to decode sequences
///
/// For the above scenarios we wish to know the binary value of the "bits" that we are reading, as
/// well as the start/end indices of those "bitstrings" of interest.
///
/// The below table performs the very task and exposes a lookup table for the bitstream decoder
/// config, which is a part of the decoder config. For illustration purposes:
///
/// Consider a bit chunk from bit_index == 4 to bit_index == 9. We will have:
///
/// | bit index | from start | until end | bitstring len | bit | bit value acc |
/// |-----------|------------|-----------|---------------|-----|---------------|
/// | 0         | 1          | 0         | 0             | 0   | 0             |
/// | 1         | 1          | 0         | 0             | 0   | 0             |
/// | 2         | 1          | 0         | 0             | 1   | 0             |
/// | 3         | 1          | 0         | 0             | 0   | 0             |
/// | 4      -> | 1          | 1         | 1             | 1   | 1             |
/// | 5      -> | 1          | 1         | 2             | 0   | 1             |
/// | 6      -> | 1          | 1         | 3             | 1   | 5             |
/// | 7      -> | 1          | 1         | 4             | 1   | 13            |
/// | 8      -> | 1          | 1         | 5             | 0   | 13            |
/// | 9      -> | 1          | 1         | 6             | 1   | 45            |
/// | 10        | 0          | 1         | 6             | 0   | 45            |
/// | 11        | 0          | 1         | 6             | 0   | 45            |
/// | 12        | 0          | 1         | 6             | 0   | 45            |
/// | 13        | 0          | 1         | 6             | 1   | 45            |
/// | 14        | 0          | 1         | 6             | 1   | 45            |
/// | 15        | 0          | 1         | 6             | 0   | 45            |
/// | 16        | 0          | 1         | 6             | 0   | 45            |
/// | 17        | 0          | 1         | 6             | 0   | 45            |
/// | 18        | 0          | 1         | 6             | 0   | 45            |
/// | 19        | 0          | 1         | 6             | 0   | 45            |
/// | 20        | 0          | 1         | 6             | 0   | 45            |
/// | 21        | 0          | 1         | 6             | 0   | 45            |
/// | 22        | 0          | 1         | 6             | 0   | 45            |
/// | 23        | 0          | 1         | 6             | 0   | 45            |
///
/// The above table illustrates 3 contiguous bytes b0, b1 and b2 where the bit index increments
/// from 0 to 23. We are interested in reading a bitstring of length 6 that starts at bit index 4
/// and ends at bit index 9. The supporting columns "from start" and "until end" help us to mark
/// the bits of interest where "from_start == until_end == 1". Over these rows, we accumulate the
/// binary value and the bitstring's length.
#[derive(Clone, Debug)]
pub struct BitstringTable {
    /// Fixed column that is enabled only for the first row.
    pub q_first: Column<Fixed>,
    /// The byte offset of byte_1.
    pub byte_idx_1: Column<Advice>,
    /// The byte offset of byte_2.
    pub byte_idx_2: Column<Advice>,
    /// The byte offset of byte_3.
    pub byte_idx_3: Column<Advice>,
    /// The byte value at byte_idx_1, i.e. the first byte in the contiguous chunk of 3 bytes.
    pub byte_1: Column<Advice>,
    /// The byte value at byte_idx_2, i.e. the second byte in the contiguous chunk of 3 bytes.
    pub byte_2: Column<Advice>,
    /// The byte value at byte_idx_3, i.e. the third byte in the contiguous chunk of 3 bytes.
    pub byte_3: Column<Advice>,
    /// The index within these 2 bytes, i.e. 0 <= bit_index <= 23. bit_index increments until its
    /// 23 and then is reset to 0.
    pub bit_index: Column<Fixed>,
    /// Helper column to know the start of a new chunk of 3 contiguous bytes, this is a fixed
    /// column as well as it is set only on bit_index == 0.
    pub q_start: Column<Fixed>,
    /// The bit at bit_index.
    /// - Accumulation of bits from 0 <= bit_index <= 7 denotes byte_1.
    /// - Accumulation of bits from 8 <= bit_index <= 15 denotes byte_2.
    /// - Accumulation of bits from 16 <= bit_index <= 23 denotes byte_3.
    pub bit: Column<Advice>,
    /// The binary value of the bits in the current bitstring.
    pub bitstring_value: Column<Advice>,
    /// The accumulator over bits from is_start to is_end, i.e. while is_set == 1.
    pub bitstring_value_acc: Column<Advice>,
    /// The length of the bitstring, i.e. the number of bits in the bitstring.
    pub bitstring_len: Column<Advice>,
    /// Boolean that is set from start of bit chunk to bit_index == 15.
    pub from_start: Column<Advice>,
    /// Boolean that is set from bit_index == 0 to end of bit chunk.
    pub until_end: Column<Advice>,
    /// Boolean to mark if the bitstring is a part of bytes that are read from front-to-back or
    /// back-to-front. For the back-to-front case, the is_reverse boolean is set.
    pub is_reverse: Column<Advice>,
    /// After all rows of meaningful bytes are done, we mark the remaining rows by a padding
    /// boolean where our constraints are skipped.
    pub is_padding: Column<Advice>,
}

impl BitstringTable {
    /// Construct the bitstring accumulation table.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, u8_table: U8Table) -> Self {
        let config = Self {
            q_first: meta.fixed_column(),
            byte_idx_1: meta.advice_column(),
            byte_idx_2: meta.advice_column(),
            byte_idx_3: meta.advice_column(),
            byte_1: meta.advice_column(),
            byte_2: meta.advice_column(),
            byte_3: meta.advice_column(),
            bit_index: meta.fixed_column(),
            q_start: meta.fixed_column(),
            bit: meta.advice_column(),
            bitstring_value: meta.advice_column(),
            bitstring_value_acc: meta.advice_column(),
            bitstring_len: meta.advice_column(),
            from_start: meta.advice_column(),
            until_end: meta.advice_column(),
            is_reverse: meta.advice_column(),
            is_padding: meta.advice_column(),
        };

        meta.create_gate("BitstringTable: bit_index == 0", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_start, Rotation::cur()),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let bits = (0..24)
                .map(|i| meta.query_advice(config.bit, Rotation(i)))
                .collect::<Vec<Expression<Fr>>>();

            let (byte_idx_1, byte_idx_2, byte_idx_3) = (
                meta.query_advice(config.byte_idx_1, Rotation::cur()),
                meta.query_advice(config.byte_idx_2, Rotation::cur()),
                meta.query_advice(config.byte_idx_3, Rotation::cur()),
            );
            let (byte_1, byte_2, byte_3) = (
                meta.query_advice(config.byte_1, Rotation::cur()),
                meta.query_advice(config.byte_2, Rotation::cur()),
                meta.query_advice(config.byte_3, Rotation::cur()),
            );

            cb.require_equal(
                "byte1 is the binary accumulation of 0 <= bit_index <= 7",
                byte_1,
                select::expr(
                    meta.query_advice(config.is_reverse, Rotation::cur()),
                    bits[7].expr()
                        + bits[6].expr() * 2.expr()
                        + bits[5].expr() * 4.expr()
                        + bits[4].expr() * 8.expr()
                        + bits[3].expr() * 16.expr()
                        + bits[2].expr() * 32.expr()
                        + bits[1].expr() * 64.expr()
                        + bits[0].expr() * 128.expr(),
                    bits[0].expr()
                        + bits[1].expr() * 2.expr()
                        + bits[2].expr() * 4.expr()
                        + bits[3].expr() * 8.expr()
                        + bits[4].expr() * 16.expr()
                        + bits[5].expr() * 32.expr()
                        + bits[6].expr() * 64.expr()
                        + bits[7].expr() * 128.expr(),
                ),
            );

            cb.require_equal(
                "byte2 is the binary accumulation of 8 <= bit_index <= 15",
                byte_2,
                select::expr(
                    meta.query_advice(config.is_reverse, Rotation::cur()),
                    bits[15].expr()
                        + bits[14].expr() * 2.expr()
                        + bits[13].expr() * 4.expr()
                        + bits[12].expr() * 8.expr()
                        + bits[11].expr() * 16.expr()
                        + bits[10].expr() * 32.expr()
                        + bits[9].expr() * 64.expr()
                        + bits[8].expr() * 128.expr(),
                    bits[8].expr()
                        + bits[9].expr() * 2.expr()
                        + bits[10].expr() * 4.expr()
                        + bits[11].expr() * 8.expr()
                        + bits[12].expr() * 16.expr()
                        + bits[13].expr() * 32.expr()
                        + bits[14].expr() * 64.expr()
                        + bits[15].expr() * 128.expr(),
                ),
            );

            cb.require_equal(
                "byte3 is the binary accumulation of 16 <= bit_index <= 23",
                byte_3,
                select::expr(
                    meta.query_advice(config.is_reverse, Rotation::cur()),
                    bits[23].expr()
                        + bits[22].expr() * 2.expr()
                        + bits[21].expr() * 4.expr()
                        + bits[20].expr() * 8.expr()
                        + bits[19].expr() * 16.expr()
                        + bits[18].expr() * 32.expr()
                        + bits[17].expr() * 64.expr()
                        + bits[16].expr() * 128.expr(),
                    bits[16].expr()
                        + bits[17].expr() * 2.expr()
                        + bits[18].expr() * 4.expr()
                        + bits[19].expr() * 8.expr()
                        + bits[20].expr() * 16.expr()
                        + bits[21].expr() * 32.expr()
                        + bits[22].expr() * 64.expr()
                        + bits[23].expr() * 128.expr(),
                ),
            );

            cb.require_boolean(
                "is_reverse is boolean",
                meta.query_advice(config.is_reverse, Rotation::cur()),
            );

            // from_start initialises at 1
            cb.require_equal(
                "if bit_index == 0: from_start == 1",
                meta.query_advice(config.from_start, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        meta.create_gate("BitstringTable: bit_index > 0", |meta| {
            let condition = and::expr([
                not::expr(meta.query_fixed(config.q_start, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // Columns that do not change in the chunk of 3 contigious bytes.
            for col in [
                config.byte_idx_1,
                config.byte_idx_2,
                config.byte_idx_3,
                config.byte_1,
                config.byte_2,
                config.byte_3,
                config.bitstring_value,
                config.is_reverse,
                config.is_padding,
            ] {
                cb.require_equal(
                    "unchanged columns from 0 < bit_idx <= 23",
                    meta.query_advice(col, Rotation::cur()),
                    meta.query_advice(col, Rotation::prev()),
                );
            }

            // from_start transitions from 1 to 0 only once, i.e. delta is boolean
            let delta = meta.query_advice(config.from_start, Rotation::prev())
                - meta.query_advice(config.from_start, Rotation::cur());
            cb.require_boolean("from_start delta is boolean", delta);

            cb.gate(condition)
        });

        meta.create_gate("BitstringTable: bitstring_value accumulation", |meta| {
            let condition = not::expr(meta.query_advice(config.is_padding, Rotation::cur()));

            let mut cb = BaseConstraintBuilder::default();

            let is_start = meta.query_fixed(config.q_start, Rotation::cur());
            let is_end = meta.query_fixed(config.q_start, Rotation::next());

            // bit value is boolean.
            cb.require_boolean(
                "bit is boolean",
                meta.query_advice(config.bit, Rotation::cur()),
            );

            // Columns from_start and until_end are boolean.
            cb.require_boolean(
                "from_start is boolean",
                meta.query_advice(config.from_start, Rotation::cur()),
            );
            cb.require_boolean(
                "until_end is boolean",
                meta.query_advice(config.until_end, Rotation::cur()),
            );

            // until_end transitions from 0 to 1 only once, i.e. delta is boolean
            let delta = meta.query_advice(config.until_end, Rotation::next())
                - meta.query_advice(config.until_end, Rotation::cur());

            cb.condition(is_end.expr(), |cb| {
                cb.require_equal(
                    "if bit_index == 23: until_end == 1",
                    meta.query_advice(config.until_end, Rotation::cur()),
                    1.expr(),
                );
            });
            cb.condition(not::expr(is_end.expr()), |cb| {
                cb.require_boolean("until_end delta is boolean", delta);
            });

            // Constraints at meaningful bits.
            let is_set = and::expr([
                meta.query_advice(config.from_start, Rotation::cur()),
                meta.query_advice(config.until_end, Rotation::cur()),
            ]);
            cb.condition(is_start.expr() * is_set.expr(), |cb| {
                cb.require_equal(
                    "if is_start && is_set: bit == bitstring_value_acc",
                    meta.query_advice(config.bit, Rotation::cur()),
                    meta.query_advice(config.bitstring_value_acc, Rotation::cur()),
                );
                cb.require_equal(
                    "if is_start && is_set: bitstring_len == 1",
                    meta.query_advice(config.bitstring_len, Rotation::cur()),
                    1.expr(),
                );
            });
            cb.condition(not::expr(is_start) * is_set, |cb| {
                cb.require_equal(
                    "is_set: bitstring_value_acc == bitstring_value_acc::prev * 2 + bit",
                    meta.query_advice(config.bitstring_value_acc, Rotation::cur()),
                    meta.query_advice(config.bitstring_value_acc, Rotation::prev()) * 2.expr()
                        + meta.query_advice(config.bit, Rotation::cur()),
                );
                cb.require_equal(
                    "is_set: bitstring_len == bitstring_len::prev + 1",
                    meta.query_advice(config.bitstring_len, Rotation::cur()),
                    meta.query_advice(config.bitstring_len, Rotation::prev()) + 1.expr(),
                );
            });

            // Constraints at bits to be ignored (at the start).
            let is_ignored_start = not::expr(meta.query_advice(config.until_end, Rotation::cur()));
            cb.condition(is_ignored_start, |cb| {
                cb.require_zero(
                    "while until_end == 0: bitstring_len == 0",
                    meta.query_advice(config.bitstring_len, Rotation::cur()),
                );
                cb.require_zero(
                    "while until_end == 0: bitstring_value_acc == 0",
                    meta.query_advice(config.bitstring_value_acc, Rotation::cur()),
                );
            });

            // Constraints at bits to be ignored (towards the end).
            let is_ignored_end = not::expr(meta.query_advice(config.from_start, Rotation::cur()));
            cb.condition(is_ignored_end, |cb| {
                cb.require_equal(
                    "bitstring_len unchanged at the last ignored bits",
                    meta.query_advice(config.bitstring_len, Rotation::cur()),
                    meta.query_advice(config.bitstring_len, Rotation::prev()),
                );
                cb.require_equal(
                    "bitstring_value_acc unchanged at the last ignored bits",
                    meta.query_advice(config.bitstring_value_acc, Rotation::cur()),
                    meta.query_advice(config.bitstring_value_acc, Rotation::prev()),
                );
            });

            cb.gate(condition)
        });

        meta.create_gate("BitstringTable: first row", |meta| {
            let condition = meta.query_fixed(config.q_first, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "cannot start with padding",
                meta.query_advice(config.is_padding, Rotation::cur()),
            );

            cb.gate(condition)
        });

        meta.create_gate("BitstringTable: padding", |meta| {
            let condition = not::expr(meta.query_fixed(config.q_first, Rotation::cur()));

            let mut cb = BaseConstraintBuilder::default();

            let (is_padding_curr, is_padding_prev) = (
                meta.query_advice(config.is_padding, Rotation::cur()),
                meta.query_advice(config.is_padding, Rotation::prev()),
            );

            // padding is boolean
            cb.require_boolean("is_padding is boolean", is_padding_curr.expr());

            // padding transitions from 0 to 1 only once.
            let delta = is_padding_curr - is_padding_prev;
            cb.require_boolean("is_padding delta is boolean", delta);

            cb.gate(condition)
        });

        // For every bitstring accumulation, the byte indices must be in the order in which
        // they appear in the rows assigned to the DecoderConfig. Which means:
        // - byte_idx_2 at the most increments by 1 compared to byte_idx_1.
        // - byte_idx_3 at the most increments by 1 compared to byte_idx_2.
        //
        // We indirectly validate this part through the lookup from DecoderConfig to the
        // BitstringTable, that includes the byte indices.
        //
        // However, we still want to make sure subsequent bitstring accumulation happens in
        // increasing order of byte indices, to avoid malicious assignments for an older byte
        // index. We need this check only for subsequent bitstrings after q_first=true.
        //
        // TODO: for a multi-block setup, the difference may be greater than 255.
        meta.lookup("BitstringTable: byte_idx_1 is increasing", |meta| {
            let condition = and::expr([
                meta.query_fixed(config.q_start, Rotation::cur()),
                not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                not::expr(meta.query_advice(config.is_padding, Rotation::cur())),
            ]);

            let (byte_idx_1_curr, byte_idx_1_prev) = (
                meta.query_advice(config.byte_idx_1, Rotation::cur()),
                meta.query_advice(config.byte_idx_1, Rotation::prev()),
            );
            let byte_idx_delta = byte_idx_1_curr - byte_idx_1_prev;

            vec![(condition * byte_idx_delta, u8_table.into())]
        });

        debug_assert!(meta.degree() <= 9);

        config
    }

    /// Load witness to the table: dev mode.
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        witness_rows: &[ZstdWitnessRow<Fr>],
    ) -> Result<(), Error> {
        unimplemented!();

        Ok(())
    }
}

impl LookupTable<Fr> for BitstringTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.byte_idx_1.into(),
            self.byte_idx_2.into(),
            self.byte_idx_3.into(),
            self.byte_1.into(),
            self.byte_2.into(),
            self.byte_3.into(),
            self.bitstring_value.into(),
            self.bitstring_len.into(),
            self.bit_index.into(),
            self.from_start.into(),
            self.until_end.into(),
            self.is_reverse.into(),
            self.is_padding.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("byte_idx_1"),
            String::from("byte_idx_2"),
            String::from("byte_idx_3"),
            String::from("byte_1"),
            String::from("byte_2"),
            String::from("byte_3"),
            String::from("bitstring_value"),
            String::from("bitstring_len"),
            String::from("bit_index"),
            String::from("from_start"),
            String::from("until_end"),
            String::from("is_reverse"),
            String::from("is_padding"),
        ]
    }
}
