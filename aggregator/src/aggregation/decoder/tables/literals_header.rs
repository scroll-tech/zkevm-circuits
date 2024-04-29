use gadgets::util::{not, select, Expr};
use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Any, Column, ConstraintSystem, Fixed},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, RangeTable},
};

/// Helper table to decode the regenerated size from the Literals Header.
#[derive(Clone, Debug)]
pub struct LiteralsHeaderTable {
    /// Fixed column to mark the first row of the table.
    q_first: Column<Fixed>,
    /// The block index in which we find this literals header. Since every block will have a
    /// literals header, and block_idx in 1..=n, we know that on the first row block_idx=1 and on
    /// subsequent rows, block_idx increments by 1.
    pub block_idx: Column<Advice>,
    /// The first byte of the literals header.
    pub byte0: Column<Advice>,
    /// The second byte.
    pub byte1: Column<Advice>,
    /// The third byte.
    pub byte2: Column<Advice>,
    /// The bit0 of size format.
    pub size_format_bit0: Column<Advice>,
    /// The bit1 of size format.
    pub size_format_bit1: Column<Advice>,
    /// byte0 >> 3.
    pub byte0_rs_3: Column<Advice>,
    /// byte0 >> 4.
    pub byte0_rs_4: Column<Advice>,
    /// Regenerated size.
    pub regen_size: Column<Advice>,
    /// Set if padded row
    pub is_padding: Column<Advice>,
}

impl LiteralsHeaderTable {
    /// Construct and constrain the literals header table.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        range8: RangeTable<8>,
        range16: RangeTable<16>,
    ) -> Self {
        let config = Self {
            q_first: meta.fixed_column(),
            block_idx: meta.advice_column(),
            byte0: meta.advice_column(),
            byte1: meta.advice_column(),
            byte2: meta.advice_column(),
            size_format_bit0: meta.advice_column(),
            size_format_bit1: meta.advice_column(),
            byte0_rs_3: meta.advice_column(),
            byte0_rs_4: meta.advice_column(),
            regen_size: meta.advice_column(),
            is_padding: meta.advice_column(),
        };

        meta.create_gate("LiteralsHeaderTable: first row", |meta| {
            let condition = meta.query_fixed(config.q_first, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "is_padding=0 on first row",
                meta.query_advice(config.is_padding, Rotation::cur()),
            );

            cb.require_equal(
                "block_idx=1 on first row",
                meta.query_advice(config.block_idx, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        meta.create_gate("LiteralsHeaderTable: main gate", |meta| {
            let condition = not::expr(meta.query_advice(config.is_padding, Rotation::cur()));

            let mut cb = BaseConstraintBuilder::default();

            let sf0 = meta.query_advice(config.size_format_bit0, Rotation::cur());
            let sf1 = meta.query_advice(config.size_format_bit1, Rotation::cur());
            let byte0_rs_3 = meta.query_advice(config.byte0_rs_3, Rotation::cur());
            let byte0_rs_4 = meta.query_advice(config.byte0_rs_4, Rotation::cur());
            let byte1_ls_4 = meta.query_advice(config.byte1, Rotation::cur()) * 16.expr();
            let byte2_ls_12 = meta.query_advice(config.byte2, Rotation::cur()) * 4096.expr();

            // - branch0: Size_Format is 00 or 10
            // - branch1: Size_Format is 01
            // - branch2: Size_Format is 10
            let branch1 = sf0.expr() * not::expr(sf1.expr());
            let branch2 = sf1.expr() * not::expr(sf0.expr());

            let branch0_regen_size = byte0_rs_3;
            let branch1_regen_size = byte0_rs_4.expr() + byte1_ls_4.expr();
            let branch2_regen_size = byte0_rs_4.expr() + byte1_ls_4.expr() + byte2_ls_12;

            let regen_size = select::expr(
                branch1,
                branch1_regen_size,
                select::expr(branch2, branch2_regen_size, branch0_regen_size),
            );

            cb.require_equal(
                "regen_size computation",
                regen_size,
                meta.query_advice(config.regen_size, Rotation::cur()),
            );

            // TODO: byte_offset should be strictly increasing.

            cb.gate(condition)
        });

        meta.create_gate("LiteralsHeaderTable: padding check", |meta| {
            let condition = not::expr(meta.query_fixed(config.q_first, Rotation::cur()));

            let mut cb = BaseConstraintBuilder::default();

            // padding transitions from 0 -> 1 only once.
            let is_padding_cur = meta.query_advice(config.is_padding, Rotation::cur());
            let is_padding_prev = meta.query_advice(config.is_padding, Rotation::prev());
            let is_padding_delta = is_padding_cur.expr() - is_padding_prev;

            cb.require_boolean("is_padding is boolean", is_padding_cur.expr());
            cb.require_boolean("is_padding delta is boolean", is_padding_delta);

            // if this is not a padding row, then block_idx has incremented.
            cb.condition(not::expr(is_padding_cur), |cb| {
                cb.require_equal(
                    "block_idx increments by 1",
                    meta.query_advice(config.block_idx, Rotation::cur()),
                    meta.query_advice(config.block_idx, Rotation::prev()) + 1.expr(),
                );
            });

            cb.gate(condition)
        });

        meta.lookup("LiteralsHeaderTable: byte0 >> 3", |meta| {
            let condition = 1.expr();

            let range_value = meta.query_advice(config.byte0, Rotation::cur())
                - (meta.query_advice(config.byte0_rs_3, Rotation::cur()) * 8.expr());

            vec![(condition * range_value, range8.into())]
        });

        meta.lookup("LiteralsHeaderTable: byte0 >> 4", |meta| {
            let condition = 1.expr();

            let range_value = meta.query_advice(config.byte0, Rotation::cur())
                - (meta.query_advice(config.byte0_rs_4, Rotation::cur()) * 16.expr());

            vec![(condition * range_value, range16.into())]
        });

        debug_assert!(meta.degree() <= 9);

        config
    }
}

impl LookupTable<Fr> for LiteralsHeaderTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.block_idx.into(),
            self.byte0.into(),
            self.byte1.into(),
            self.byte2.into(),
            self.size_format_bit0.into(),
            self.size_format_bit1.into(),
            self.regen_size.into(),
            self.is_padding.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("block_idx"),
            String::from("byte_offset"),
            String::from("byte0"),
            String::from("byte1"),
            String::from("byte2"),
            String::from("size_format_bit0"),
            String::from("size_format_bit1"),
            String::from("regen_size"),
            String::from("is_padding"),
        ]
    }
}
