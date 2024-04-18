use gadgets::util::{not, select, Expr};
use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Any, Column, ConstraintSystem},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, RangeTable},
};

/// Helper table to decode the regenerated size from the Literals Header.
#[derive(Clone, Debug)]
pub struct LiteralsHeaderTable {
    /// The byte_idx at which this literals header is located.
    pub byte_offset: Column<Advice>,
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
            byte_offset: meta.advice_column(),
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

        config
    }
}

impl LookupTable<Fr> for LiteralsHeaderTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.byte_offset.into(),
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
