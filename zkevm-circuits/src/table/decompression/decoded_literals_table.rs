use eth_types::Field;
use gadgets::{
    comparator::{ComparatorChip, ComparatorConfig},
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase},
    poly::Rotation,
};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, RangeTable},
    util::Challenges,
};

/// Table that consists of every decoded literal byte. Depending on the literals length from
/// sequences execution, we also accumulate RLC over contiguous bytes.
#[derive(Clone, Debug)]
pub struct DecodedLiteralsTable<F> {
    q_enable: Column<Fixed>,
    q_first: Column<Fixed>,
    huffman_byte_offset: Column<Advice>,
    huffman_byte_offset_cmp: ComparatorConfig<F, 3>,
    byte_offset: Column<Advice>,
    is_boundary: Column<Advice>,
    decoded_byte: Column<Advice>,
    decoded_literals_length: Column<Advice>,
    decoded_literals_rlc: Column<Advice>,
}

impl<F: Field> DecodedLiteralsTable<F> {
    /// Construct and constrain the decoded literals table.
    pub fn construct(
        meta: &mut ConstraintSystem<F>,
        challenges: Challenges<Expression<F>>,
        range256: RangeTable<256>,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let huffman_byte_offset = meta.advice_column();
        let table = Self {
            q_enable,
            q_first: meta.fixed_column(),
            huffman_byte_offset,
            huffman_byte_offset_cmp: ComparatorChip::configure(
                meta,
                |meta| meta.query_fixed(q_enable, Rotation::cur()),
                |meta| meta.query_advice(huffman_byte_offset, Rotation::prev()),
                |meta| meta.query_advice(huffman_byte_offset, Rotation::cur()),
                range256.into(),
            ),
            byte_offset: meta.advice_column(),
            is_boundary: meta.advice_column(),
            decoded_byte: meta.advice_column(),
            decoded_literals_length: meta.advice_column(),
            decoded_literals_rlc: meta.advice_column_in(SecondPhase),
        };

        meta.create_gate("DecodedLiteralsTable: first row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "init decoded literals RLC",
                meta.query_advice(table.decoded_literals_rlc, Rotation::cur()),
                meta.query_advice(table.decoded_byte, Rotation::cur()),
            );
            cb.require_equal(
                "init decoded literals length",
                meta.query_advice(table.decoded_literals_length, Rotation::cur()),
                1.expr(),
            );

            cb.gate(and::expr([
                meta.query_fixed(table.q_enable, Rotation::cur()),
                meta.query_fixed(table.q_first, Rotation::cur()),
            ]))
        });

        meta.create_gate("DecodedLiteralsTable: all rows", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_boundary is boolean",
                meta.query_advice(table.is_boundary, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(table.q_enable, Rotation::cur()))
        });

        meta.create_gate("DecodedLiteralsTable: instance of huffman code", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "byte_offset is increasing",
                meta.query_advice(table.byte_offset, Rotation::cur())
                    - meta.query_advice(table.byte_offset, Rotation::prev()),
            );

            let crossed_boundary = meta.query_advice(table.is_boundary, Rotation::prev());

            // if not boundary, continue RLC.
            cb.condition(not::expr(crossed_boundary.expr()), |cb| {
                cb.require_equal(
                    "no boundary: continue decoded literals RLC",
                    meta.query_advice(table.decoded_literals_rlc, Rotation::cur()),
                    meta.query_advice(table.decoded_literals_rlc, Rotation::prev())
                        * challenges.keccak_input()
                        + meta.query_advice(table.decoded_byte, Rotation::cur()),
                );
                cb.require_equal(
                    "no boundary: continue decoded literals length",
                    meta.query_advice(table.decoded_literals_length, Rotation::cur()),
                    meta.query_advice(table.decoded_literals_length, Rotation::prev()) + 1.expr(),
                );
            });

            // if boundary, reset RLC.
            cb.condition(crossed_boundary.expr(), |cb| {
                cb.require_equal(
                    "crossed boundary: reset decoded literals RLC",
                    meta.query_advice(table.decoded_literals_rlc, Rotation::cur()),
                    meta.query_advice(table.decoded_byte, Rotation::cur()),
                );
                cb.require_equal(
                    "crossed boundary: reset decoded literals length",
                    meta.query_advice(table.decoded_literals_length, Rotation::cur()),
                    1.expr(),
                );
            });

            let (_lt, huffman_code_unchanged) = table.huffman_byte_offset_cmp.expr(meta, None);
            cb.gate(and::expr([
                meta.query_fixed(table.q_enable, Rotation::cur()),
                huffman_code_unchanged,
            ]))
        });

        meta.lookup("DecodedLiteralsTable: decoded byte", |meta| {
            let condition = meta.query_fixed(table.q_enable, Rotation::cur());
            vec![(
                condition * meta.query_advice(table.decoded_byte, Rotation::cur()),
                range256.into(),
            )]
        });

        table
    }

    /// Load witness to the table: dev mode.
    pub fn assign(&self, _layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        unimplemented!()
    }
}

impl<F: Field> LookupTable<F> for DecodedLiteralsTable<F> {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![
            self.huffman_byte_offset.into(),
            self.byte_offset.into(),
            self.decoded_byte.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("huffman_byte_offset"),
            String::from("byte_offset"),
            String::from("decoded_byte"),
        ]
    }
}
