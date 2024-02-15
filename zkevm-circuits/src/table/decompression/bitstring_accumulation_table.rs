use eth_types::Field;
use gadgets::util::{and, not, select, Expr};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::LookupTable,
    witness::{value_bits_le, ZstdTag, ZstdWitnessRow},
};

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
pub struct BitstringAccumulationTable {
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
    /// The bit at bit_index. Accumulation of bits from 0 <= bit_index <= 7 denotes byte_1.
    /// Accumulation of 8 <= bit_index <= 15 denotes byte_2.
    pub bit: Column<Advice>,
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
    /// Boolean to mark if the bitstring is a part of bytes that are read from front-to-back or
    /// back-to-front. For the back-to-front case, the is_reverse boolean is set.
    pub is_reverse: Column<Advice>,
}

impl BitstringAccumulationTable {
    /// Construct the bitstring accumulation table.
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
            bit: meta.advice_column(),
            bit_value: meta.advice_column(),
            bitstring_len: meta.advice_column(),
            bit_value_acc: meta.advice_column(),
            from_start: meta.advice_column(),
            until_end: meta.advice_column(),
            is_reverse: meta.advice_column(),
        };

        meta.create_gate("BitstringAccumulationTable: bit_index == 0", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let bits = (0..16)
                .map(|i| meta.query_advice(table.bit, Rotation(i)))
                .collect::<Vec<Expression<F>>>();

            cb.require_equal(
                "byte1 is the binary accumulation of 0 <= bit_index <= 7",
                meta.query_advice(table.byte_1, Rotation::cur()),
                select::expr(
                    meta.query_advice(table.is_reverse, Rotation::cur()),
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
                meta.query_advice(table.byte_2, Rotation::cur()),
                select::expr(
                    meta.query_advice(table.is_reverse, Rotation::cur()),
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

            cb.require_boolean(
                "is_reverse is boolean",
                meta.query_advice(table.is_reverse, Rotation::cur()),
            );

            // TODO: Possibly exclude jump table bytes as they create a gap in byte_idx between
            // huffman code and lstreams
            cb.require_boolean(
                "byte2 == byte1 or byte2 == byte1 + 1",
                meta.query_advice(table.byte_idx_2, Rotation::cur())
                    - meta.query_advice(table.byte_idx_1, Rotation::cur()),
            );

            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                meta.query_fixed(table.q_first, Rotation::cur()),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("BitstringAccumulationTable: bit_index > 0", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Constrain columns that are unchanged from 0 < bit_idx < 16.
            for col in [
                table.byte_offset,
                table.byte_idx_1,
                table.byte_idx_2,
                table.byte_1,
                table.byte_2,
                table.bit_value,
                table.is_reverse,
            ] {
                cb.require_equal(
                    "unchanged columns from 0 < bit_idx < 16",
                    meta.query_advice(col, Rotation::cur()),
                    meta.query_advice(col, Rotation::prev()),
                );
            }

            let is_last = meta.query_fixed(table.q_first, Rotation::next());
            cb.condition(is_last, |cb| {
                cb.require_equal(
                    "byte_idx_1' == byte_idx_2",
                    meta.query_advice(table.byte_idx_1, Rotation::next()),
                    meta.query_advice(table.byte_idx_2, Rotation::cur()),
                );
            });

            cb.gate(and::expr([
                meta.query_fixed(table.q_enabled, Rotation::cur()),
                not::expr(meta.query_fixed(table.q_first, Rotation::cur())),
            ]))
        });

        debug_assert!(meta.degree() <= 9);

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
        meta.create_gate("BitstringAccumulationTable: bit value", |meta| {
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
        });

        debug_assert!(meta.degree() <= 9);

        table
    }

    /// Load witness to the table: dev mode.
    pub fn assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        witness_rows: &[ZstdWitnessRow<F>],
    ) -> Result<(), Error> {
        assert!(!witness_rows.is_empty());

        // Get the byte at which FSE is described
        // TODO: Determining huffman offset in a multi-block scenario.
        let huffman_offset = witness_rows
            .iter()
            .find(|&r| r.state.tag == ZstdTag::ZstdBlockFseCode)
            .unwrap()
            .encoded_data
            .byte_idx;

        // Extract bit accumulation-related info from the rows
        let accumulation_rows = witness_rows
            .iter()
            .filter(|&r| {
                r.state.tag == ZstdTag::ZstdBlockFseCode
                    || r.state.tag == ZstdTag::ZstdBlockHuffmanCode
                    || r.state.tag == ZstdTag::ZstdBlockJumpTable
                    || r.state.tag == ZstdTag::ZstdBlockLstream
            })
            .map(|r| {
                (
                    r.encoded_data.byte_idx as usize,
                    r.encoded_data.value_byte as u64,
                    r.bitstream_read_data.bit_start_idx,
                    r.bitstream_read_data.bit_end_idx,
                    r.bitstream_read_data.bit_value,
                    r.state.tag.is_reverse() as u64, // is_reverse
                )
            })
            .collect::<Vec<(usize, u64, usize, usize, u64, u64)>>();

        layouter.assign_region(
            || "Bitstring Accumulation Table",
            |mut region| {
                let mut offset: usize = 0;
                let mut last_byte_idx: usize = 0;
                for rows in accumulation_rows.windows(2) {
                    let row = rows[0];
                    let next_row = rows[1];
                    let byte_1_bits = value_bits_le(row.1 as u8);
                    let byte_2_bits = value_bits_le(next_row.1 as u8);
                    let bits = if row.5 > 0 {
                        // reversed
                        [
                            byte_1_bits.into_iter().rev().collect::<Vec<u8>>(),
                            byte_2_bits.into_iter().rev().collect::<Vec<u8>>(),
                        ]
                        .concat()
                    } else {
                        // not reversed
                        [byte_1_bits, byte_2_bits].concat()
                    };

                    let mut acc: u64 = 0;
                    let mut bitstring_len: u64 = 0;

                    for (bit_idx, bit) in bits.into_iter().enumerate().take(16) {
                        region.assign_fixed(
                            || "q_enable",
                            self.q_enabled,
                            offset + bit_idx,
                            || Value::known(F::one()),
                        )?;
                        region.assign_advice(
                            || "byte_offset",
                            self.byte_offset,
                            offset + bit_idx,
                            || Value::known(F::from(huffman_offset)),
                        )?;
                        region.assign_advice(
                            || "byte_idx_1",
                            self.byte_idx_1,
                            offset + bit_idx,
                            || Value::known(F::from(row.0 as u64)),
                        )?;
                        region.assign_advice(
                            || "byte_idx_2",
                            self.byte_idx_2,
                            offset + bit_idx,
                            || Value::known(F::from(next_row.0 as u64)),
                        )?;
                        region.assign_advice(
                            || "byte_1",
                            self.byte_1,
                            offset + bit_idx,
                            || Value::known(F::from(row.1)),
                        )?;
                        region.assign_advice(
                            || "byte_2",
                            self.byte_2,
                            offset + bit_idx,
                            || Value::known(F::from(next_row.1)),
                        )?;
                        region.assign_fixed(
                            || "bit_index",
                            self.bit_index,
                            offset + bit_idx,
                            || Value::known(F::from(bit_idx as u64)),
                        )?;
                        region.assign_fixed(
                            || "q_first",
                            self.q_first,
                            offset + bit_idx,
                            || Value::known(F::from((bit_idx == 0) as u64)),
                        )?;

                        if bit_idx >= row.2 && bit_idx <= row.3 {
                            acc = acc * 2 + (bit as u64);
                            bitstring_len += 1;
                        }
                        region.assign_advice(
                            || "bit",
                            self.bit,
                            offset + bit_idx,
                            || Value::known(F::from(bit as u64)),
                        )?;
                        region.assign_advice(
                            || "bit_value_acc",
                            self.bit_value_acc,
                            offset + bit_idx,
                            || Value::known(F::from(acc)),
                        )?;
                        region.assign_advice(
                            || "bit_value",
                            self.bit_value,
                            offset + bit_idx,
                            || Value::known(F::from(row.4)),
                        )?;
                        region.assign_advice(
                            || "bitstring_len",
                            self.bitstring_len,
                            offset + bit_idx,
                            || Value::known(F::from(bitstring_len)),
                        )?;
                        region.assign_advice(
                            || "from_start",
                            self.from_start,
                            offset + bit_idx,
                            || Value::known(F::from((bit_idx <= row.3) as u64)),
                        )?;
                        region.assign_advice(
                            || "until_end",
                            self.until_end,
                            offset + bit_idx,
                            || Value::known(F::from((bit_idx >= row.2) as u64)),
                        )?;
                        region.assign_advice(
                            || "is_reverse",
                            self.is_reverse,
                            offset + bit_idx,
                            || Value::known(F::from(row.5)),
                        )?;
                    }

                    offset += 16;
                    last_byte_idx = next_row.0;
                }

                region.assign_fixed(
                    || "q_first",
                    self.q_first,
                    offset,
                    || Value::known(F::one()),
                )?;
                region.assign_advice(
                    || "byte_idx_1",
                    self.byte_idx_1,
                    offset,
                    || Value::known(F::from(last_byte_idx as u64)),
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

impl<F: Field> LookupTable<F> for BitstringAccumulationTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.byte_offset.into(),
            self.byte_idx_1.into(),
            self.byte_idx_2.into(),
            self.byte_1.into(),
            self.byte_2.into(),
            self.bit_value.into(),
            self.bitstring_len.into(),
            self.bit_index.into(),
            self.from_start.into(),
            self.until_end.into(),
            self.is_reverse.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("byte_offset"),
            String::from("byte_idx_1"),
            String::from("byte_idx_2"),
            String::from("byte_1"),
            String::from("byte_2"),
            String::from("bit_value"),
            String::from("bitstring_len"),
            String::from("bit_index"),
            String::from("from_start"),
            String::from("until_end"),
            String::from("is_reverse"),
        ]
    }
}
