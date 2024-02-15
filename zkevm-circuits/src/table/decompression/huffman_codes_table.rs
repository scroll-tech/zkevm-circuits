use array_init::array_init;
use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    comparator::{ComparatorChip, ComparatorConfig, ComparatorInstruction},
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use strum::IntoEnumIterator;

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, Pow2Table, RangeTable},
    witness::{FseSymbol, HuffmanCodesData, N_BITS_SYMBOL, N_MAX_SYMBOLS},
};

/// The Huffman codes table maps the canonical weights (symbols as per FseTable) to the Huffman
/// codes.
#[derive(Clone, Debug)]
pub struct HuffmanCodesTable<F> {
    /// Fixed column to denote whether the constraints will be enabled or not.
    pub q_enabled: Column<Fixed>,
    /// Fixed column to mark the first row in the table.
    pub q_first: Column<Fixed>,
    /// Set when this is the start of a new huffman code.
    pub is_start: Column<Advice>,
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
    /// Construct the huffman codes table.
    pub fn construct(
        meta: &mut ConstraintSystem<F>,
        pow2_table: Pow2Table,
        range256: RangeTable<256>,
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
                range256.into(),
            ),
            is_start: meta.advice_column(),
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

        // TODO: constrain is_start

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
                let is_start = meta.query_advice(table.is_start, Rotation::cur());
                cb.condition(not::expr(is_start.expr()), |cb| {
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
            for i in [
                FseSymbol::S1,
                FseSymbol::S2,
                FseSymbol::S3,
                FseSymbol::S4,
                FseSymbol::S5,
                FseSymbol::S6,
            ] {
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

            // Marks the start of a new huffman code.
            cb.require_equal(
                "is_start == 1",
                meta.query_advice(table.is_start, Rotation::next()),
                1.expr(),
            );

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

    /// Load witness to the huffman codes table: dev mode.
    pub fn assign(
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

impl<F: Field> HuffmanCodesTable<F> {
    /// Lookup the canonical weight assigned to a symbol in the Huffman code with the header at
    /// the given byte_offset.
    pub fn table_exprs_canonical_weight(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.byte_offset, Rotation::cur()),
            meta.query_advice(self.symbol, Rotation::cur()),
            meta.query_advice(self.weight, Rotation::cur()),
        ]
    }

    /// Lookup the number of symbols that are present in the canonical representation of the
    /// Huffman code.
    pub fn table_exprs_weights_count(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.byte_offset, Rotation::cur()),
            meta.query_advice(self.symbol, Rotation::cur()),
            // TODO: add is_last to mark the last row of a specific Huffman code.
        ]
    }
}
