use gadgets::util::{and, not, select, Expr};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, RangeTable},
};

use crate::{
    aggregation::{
        decoder::{
            witgen::{util::value_bits_le, ZstdTag, ZstdWitnessRow},
            BlockInfo,
        },
        util::BooleanAdvice,
    },
    witgen::{N_BITS_PER_BYTE, N_BLOCK_SIZE_TARGET},
};

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
pub struct BitstringTable<const N_BYTES: usize> {
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
    pub bit: BooleanAdvice,
    /// The binary value of the bits in the current bitstring.
    pub bitstring_value: Column<Advice>,
    /// The accumulator over bits from is_start to is_end, i.e. while is_set == 1.
    pub bitstring_value_acc: Column<Advice>,
    /// The length of the bitstring, i.e. the number of bits in the bitstring.
    pub bitstring_len: Column<Advice>,
    /// Boolean that is set from start of bit chunk to bit_index == 15.
    pub from_start: BooleanAdvice,
    /// Boolean that is set from bit_index == 0 to end of bit chunk.
    pub until_end: BooleanAdvice,
    /// Boolean to mark if the bitstring is a part of bytes that are read from front-to-back or
    /// back-to-front. For the back-to-front case, the is_reverse boolean is set.
    pub is_reverse: BooleanAdvice,
    /// After all rows of meaningful bytes are done, we mark the remaining rows by a padding
    /// boolean where our constraints are skipped.
    pub is_padding: BooleanAdvice,
}

impl<const N_BYTES: usize> BitstringTable<N_BYTES> {
    /// Construct the bitstring accumulation table.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        q_enable: Column<Fixed>,
        range_block_len: RangeTable<{ N_BLOCK_SIZE_TARGET as usize }>,
    ) -> Self {
        assert!(
            (1..=3).contains(&N_BYTES),
            "unexpected byte-group={:?} expected=range({:?}..={:?})",
            N_BYTES,
            1,
            3,
        );

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
            bit: BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enable, Rotation::cur())),
            bitstring_value: meta.advice_column(),
            bitstring_value_acc: meta.advice_column(),
            bitstring_len: meta.advice_column(),
            from_start: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            until_end: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            is_reverse: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
            is_padding: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
        };

        meta.create_gate("BitstringTable: bit_index == 0", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_fixed(config.q_start, Rotation::cur()),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let bits = (0..(3 * N_BITS_PER_BYTE))
                .map(|i| config.bit.expr_at(meta, Rotation(i as i32)))
                .collect::<Vec<Expression<Fr>>>();

            let (byte_1, byte_2, byte_3) = (
                meta.query_advice(config.byte_1, Rotation::cur()),
                meta.query_advice(config.byte_2, Rotation::cur()),
                meta.query_advice(config.byte_3, Rotation::cur()),
            );

            cb.require_equal(
                "byte1 is the binary accumulation of 0 <= bit_index <= 7",
                byte_1,
                select::expr(
                    config.is_reverse.expr_at(meta, Rotation::cur()),
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

            if N_BYTES > 1 {
                cb.require_equal(
                    "byte2 is the binary accumulation of 8 <= bit_index <= 15",
                    byte_2,
                    select::expr(
                        config.is_reverse.expr_at(meta, Rotation::cur()),
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
            }

            if N_BYTES > 2 {
                cb.require_equal(
                    "byte3 is the binary accumulation of 16 <= bit_index <= 23",
                    byte_3,
                    select::expr(
                        config.is_reverse.expr_at(meta, Rotation::cur()),
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
            }

            // from_start initialises at 1
            cb.require_equal(
                "if bit_index == 0: from_start == 1",
                config.from_start.expr_at(meta, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        meta.create_gate("BitstringTable: bit_index > 0", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(config.q_start, Rotation::cur())),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            // Columns that do not change in the chunk of 3 contiguous bytes.
            for col in [
                config.byte_idx_1,
                config.byte_idx_2,
                config.byte_idx_3,
                config.byte_1,
                config.byte_2,
                config.byte_3,
                config.bitstring_value,
                config.is_reverse.column,
                config.is_padding.column,
            ] {
                cb.require_equal(
                    "unchanged columns from 0 < bit_idx <= 23",
                    meta.query_advice(col, Rotation::cur()),
                    meta.query_advice(col, Rotation::prev()),
                );
            }

            // from_start transitions from 1 to 0 only once, i.e. delta is boolean
            let delta = config.from_start.expr_at(meta, Rotation::prev())
                - config.from_start.expr_at(meta, Rotation::cur());
            cb.require_boolean("from_start delta is boolean", delta);

            cb.gate(condition)
        });

        meta.create_gate("BitstringTable: bitstring_value accumulation", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let is_start = meta.query_fixed(config.q_start, Rotation::cur());
            let is_end = meta.query_fixed(config.q_start, Rotation::next());

            // until_end transitions from 0 to 1 only once, i.e. delta is boolean
            let delta = config.until_end.expr_at(meta, Rotation::next())
                - config.until_end.expr_at(meta, Rotation::cur());

            cb.condition(is_end.expr(), |cb| {
                cb.require_equal(
                    "if bit_index == 23: until_end == 1",
                    config.until_end.expr_at(meta, Rotation::cur()),
                    1.expr(),
                );
            });
            cb.condition(not::expr(is_end.expr()), |cb| {
                cb.require_boolean("until_end delta is boolean", delta);
            });

            // Constraints at meaningful bits.
            let is_set = and::expr([
                config.from_start.expr_at(meta, Rotation::cur()),
                config.until_end.expr_at(meta, Rotation::cur()),
            ]);
            cb.condition(is_start.expr() * is_set.expr(), |cb| {
                cb.require_equal(
                    "if is_start && is_set: bit == bitstring_value_acc",
                    config.bit.expr_at(meta, Rotation::cur()),
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
                        + config.bit.expr_at(meta, Rotation::cur()),
                );
                cb.require_equal(
                    "is_set: bitstring_len == bitstring_len::prev + 1",
                    meta.query_advice(config.bitstring_len, Rotation::cur()),
                    meta.query_advice(config.bitstring_len, Rotation::prev()) + 1.expr(),
                );
            });

            // Constraints at bits to be ignored (at the start).
            let is_ignored_start = not::expr(config.until_end.expr_at(meta, Rotation::cur()));
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
            let is_ignored_end = not::expr(config.from_start.expr_at(meta, Rotation::cur()));
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

        meta.create_gate("BitstringTable: padding", |meta| {
            let condition = and::expr([
                not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                meta.query_fixed(q_enable, Rotation::cur()),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let (is_padding_curr, is_padding_prev) = (
                config.is_padding.expr_at(meta, Rotation::cur()),
                config.is_padding.expr_at(meta, Rotation::prev()),
            );

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
        meta.lookup("BitstringTable: byte_idx_1 is increasing", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_fixed(config.q_start, Rotation::cur()),
                not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let (byte_idx_1_curr, byte_idx_1_prev) = (
                meta.query_advice(config.byte_idx_1, Rotation::cur()),
                meta.query_advice(config.byte_idx_1, Rotation::prev()),
            );
            let byte_idx_delta = byte_idx_1_curr - byte_idx_1_prev;

            vec![(condition * byte_idx_delta, range_block_len.into())]
        });

        debug_assert!(meta.degree() <= 9);
        debug_assert!(meta.clone().chunk_lookups().degree() <= 9);

        config
    }

    /// Load witness to the table: dev mode.
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        block_info_arr: &Vec<BlockInfo>,
        witness_rows: &[ZstdWitnessRow<Fr>],
        n_enabled: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Bitstring Table",
            |mut region| {
                let mut offset: usize = 0;
                region.assign_fixed(|| "q_first", self.q_first, 0, || Value::known(Fr::one()))?;

                // assign fixed columns.
                for i in 0..n_enabled {
                    let bit_index = i % (N_BYTES * N_BITS_PER_BYTE);
                    if bit_index == 0 {
                        region.assign_fixed(
                            || "q_start",
                            self.q_start,
                            i,
                            || Value::known(Fr::one()),
                        )?;
                    }
                    region.assign_fixed(
                        || "bit_index",
                        self.bit_index,
                        i,
                        || Value::known(Fr::from(bit_index as u64)),
                    )?;
                }

                let n_witness_rows = witness_rows.len();
                let filler_row = (
                    witness_rows
                        .last()
                        .expect("at least 1 row")
                        .encoded_data
                        .byte_idx
                        + 1,
                    0u64,
                    0u64,
                    0u64,
                    0u64,
                    0u64,
                );

                let mut rows = Vec::with_capacity(n_enabled);
                for block_info in block_info_arr {
                    for i in 0..n_witness_rows {
                        // prechecks.
                        let witness_row = &witness_rows[i];
                        if witness_row.state.block_idx > (block_info.block_idx as u64) {
                            break;
                        }
                        if witness_row.state.block_idx != (block_info.block_idx as u64)
                            || witness_row.bitstream_read_data.is_nil
                            || witness_row.bitstream_read_data.is_zero_bit_read
                        {
                            continue;
                        }

                        let is_tag_ok = matches!(
                            witness_row.state.tag,
                            ZstdTag::ZstdBlockSequenceFseCode | ZstdTag::ZstdBlockSequenceData
                        );
                        let bit_end_idx = witness_row.bitstream_read_data.bit_end_idx;
                        let is_bitstring_ok = (bit_end_idx >= ((N_BYTES - 1) * N_BITS_PER_BYTE))
                            && (bit_end_idx < N_BYTES * N_BITS_PER_BYTE);
                        if is_tag_ok && is_bitstring_ok {
                            rows.push((
                                witness_row.encoded_data.byte_idx,
                                witness_row.encoded_data.value_byte as u64,
                                witness_row.bitstream_read_data.bit_start_idx as u64,
                                witness_row.bitstream_read_data.bit_end_idx as u64,
                                witness_row.bitstream_read_data.bit_value,
                                witness_row.state.tag.is_reverse() as u64,
                            ));
                            if N_BYTES > 1 {
                                let next_row = if i + 1 < n_witness_rows {
                                    (
                                        witness_rows[i + 1].encoded_data.byte_idx,
                                        witness_rows[i + 1].encoded_data.value_byte as u64,
                                        witness_rows[i + 1].bitstream_read_data.bit_start_idx
                                            as u64,
                                        witness_rows[i + 1].bitstream_read_data.bit_end_idx as u64,
                                        witness_rows[i + 1].bitstream_read_data.bit_value,
                                        witness_rows[i + 1].state.tag.is_reverse() as u64,
                                    )
                                } else {
                                    filler_row
                                };
                                rows.push(next_row);
                            }
                            if N_BYTES > 2 {
                                let next_next_row = if i + 2 < n_witness_rows {
                                    (
                                        witness_rows[i + 2].encoded_data.byte_idx,
                                        witness_rows[i + 2].encoded_data.value_byte as u64,
                                        witness_rows[i + 2].bitstream_read_data.bit_start_idx
                                            as u64,
                                        witness_rows[i + 2].bitstream_read_data.bit_end_idx as u64,
                                        witness_rows[i + 2].bitstream_read_data.bit_value,
                                        witness_rows[i + 2].state.tag.is_reverse() as u64,
                                    )
                                } else {
                                    filler_row
                                };
                                rows.push(next_next_row);
                            }
                        }
                    }
                }

                for grouped_rows in rows.chunks_exact(N_BYTES) {
                    let curr_row = grouped_rows[0];

                    let (byte_idx_1, byte_idx_2, byte_idx_3) = match N_BYTES {
                        1 => (grouped_rows[0].0, 0, 0),
                        2 => (grouped_rows[0].0, grouped_rows[1].0, 0),
                        3 => (grouped_rows[0].0, grouped_rows[1].0, grouped_rows[2].0),
                        v => unreachable!("unexpected N_BYTES={:?}", v),
                    };
                    let (byte_1, byte_2, byte_3) = match N_BYTES {
                        1 => (grouped_rows[0].1, 0, 0),
                        2 => (grouped_rows[0].1, grouped_rows[1].1, 0),
                        3 => (grouped_rows[0].1, grouped_rows[1].1, grouped_rows[2].1),
                        v => unreachable!("unexpected N_BYTES={:?}", v),
                    };

                    let byte_1_bits = value_bits_le(byte_1 as u8);
                    let byte_2_bits = value_bits_le(byte_2 as u8);
                    let byte_3_bits = value_bits_le(byte_3 as u8);

                    let bits = if curr_row.5 > 0 {
                        // reversed
                        [
                            byte_1_bits.into_iter().rev().collect::<Vec<u8>>(),
                            byte_2_bits.into_iter().rev().collect::<Vec<u8>>(),
                            byte_3_bits.into_iter().rev().collect::<Vec<u8>>(),
                        ]
                        .concat()
                    } else {
                        // not reversed
                        [byte_1_bits, byte_2_bits, byte_3_bits].concat()
                    };

                    let mut acc: u64 = 0;
                    let mut bitstring_len: u64 = 0;

                    for (bit_idx, bit) in
                        bits.into_iter().enumerate().take(N_BYTES * N_BITS_PER_BYTE)
                    {
                        region.assign_advice(
                            || "byte_idx_1",
                            self.byte_idx_1,
                            offset + bit_idx,
                            || Value::known(Fr::from(byte_idx_1)),
                        )?;
                        region.assign_advice(
                            || "byte_idx_2",
                            self.byte_idx_2,
                            offset + bit_idx,
                            || Value::known(Fr::from(byte_idx_2)),
                        )?;
                        region.assign_advice(
                            || "byte_idx_3",
                            self.byte_idx_3,
                            offset + bit_idx,
                            || Value::known(Fr::from(byte_idx_3)),
                        )?;
                        region.assign_advice(
                            || "byte_1",
                            self.byte_1,
                            offset + bit_idx,
                            || Value::known(Fr::from(byte_1)),
                        )?;
                        region.assign_advice(
                            || "byte_2",
                            self.byte_2,
                            offset + bit_idx,
                            || Value::known(Fr::from(byte_2)),
                        )?;
                        region.assign_advice(
                            || "byte_3",
                            self.byte_3,
                            offset + bit_idx,
                            || Value::known(Fr::from(byte_3)),
                        )?;

                        if bit_idx >= (curr_row.2 as usize) && bit_idx <= (curr_row.3 as usize) {
                            acc = acc * 2 + (bit as u64);
                            bitstring_len += 1;
                        }
                        region.assign_advice(
                            || "bit",
                            self.bit.column,
                            offset + bit_idx,
                            || Value::known(Fr::from(bit as u64)),
                        )?;
                        region.assign_advice(
                            || "bitstring_value",
                            self.bitstring_value,
                            offset + bit_idx,
                            || Value::known(Fr::from(curr_row.4)),
                        )?;
                        region.assign_advice(
                            || "bitstring_value_acc",
                            self.bitstring_value_acc,
                            offset + bit_idx,
                            || Value::known(Fr::from(acc)),
                        )?;
                        region.assign_advice(
                            || "bitstring_len",
                            self.bitstring_len,
                            offset + bit_idx,
                            || Value::known(Fr::from(bitstring_len)),
                        )?;
                        region.assign_advice(
                            || "from_start",
                            self.from_start.column,
                            offset + bit_idx,
                            || Value::known(Fr::from((bit_idx <= (curr_row.3 as usize)) as u64)),
                        )?;
                        region.assign_advice(
                            || "until_end",
                            self.until_end.column,
                            offset + bit_idx,
                            || Value::known(Fr::from((bit_idx >= (curr_row.2 as usize)) as u64)),
                        )?;
                        region.assign_advice(
                            || "is_reverse",
                            self.is_reverse.column,
                            offset + bit_idx,
                            || Value::known(Fr::from(curr_row.5)),
                        )?;
                    }

                    offset += N_BYTES * N_BITS_PER_BYTE;
                }

                for idx in 0..offset {
                    region.assign_advice(
                        || "is_padding",
                        self.is_padding.column,
                        idx,
                        || Value::known(Fr::zero()),
                    )?;
                }
                for idx in offset..n_enabled {
                    region.assign_advice(
                        || "is_padding",
                        self.is_padding.column,
                        idx,
                        || Value::known(Fr::one()),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<const N_BYTES: usize> LookupTable<Fr> for BitstringTable<N_BYTES> {
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
            self.from_start.column.into(),
            self.until_end.column.into(),
            self.is_reverse.column.into(),
            self.is_padding.column.into(),
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
