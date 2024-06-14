use gadgets::util::{and, not, select, Expr};
use gadgets::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{LookupTable, RangeTable},
};

use crate::aggregation::{
    decoder::witgen::{
        util::{le_bits_to_value, value_bits_le},
        BlockType,
    },
    util::BooleanAdvice,
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
    pub is_padding: BooleanAdvice,
}

impl LiteralsHeaderTable {
    /// Construct and constrain the literals header table.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        q_enable: Column<Fixed>,
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
            is_padding: BooleanAdvice::construct(meta, |meta| {
                meta.query_fixed(q_enable, Rotation::cur())
            }),
        };

        meta.create_gate("LiteralsHeaderTable: first row", |meta| {
            let condition = meta.query_fixed(config.q_first, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "is_padding=0 on first row",
                config.is_padding.expr_at(meta, Rotation::cur()),
            );

            cb.require_equal(
                "block_idx=1 on first row",
                meta.query_advice(config.block_idx, Rotation::cur()),
                1.expr(),
            );

            cb.gate(condition)
        });

        meta.create_gate("LiteralsHeaderTable: main gate", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let mut cb = BaseConstraintBuilder::default();

            let sf0 = meta.query_advice(config.size_format_bit0, Rotation::cur());
            let sf1 = meta.query_advice(config.size_format_bit1, Rotation::cur());
            let byte0_rs_3 = meta.query_advice(config.byte0_rs_3, Rotation::cur());
            let byte0_rs_4 = meta.query_advice(config.byte0_rs_4, Rotation::cur());
            let byte1_ls_4 = meta.query_advice(config.byte1, Rotation::cur()) * 16.expr();
            let byte2_ls_12 = meta.query_advice(config.byte2, Rotation::cur()) * 4096.expr();

            // - branch0: Size_Format is 00 or 10
            // - branch1: Size_Format is 01
            // - branch2: Size_Format is 11
            let branch1 = sf0.expr() * not::expr(sf1.expr());
            let branch2 = sf1.expr() * sf0.expr();

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

            cb.gate(condition)
        });

        meta.create_gate(
            "LiteralsHeaderTable: subsequent rows after q_first=true",
            |meta| {
                let condition = and::expr([
                    meta.query_fixed(q_enable, Rotation::cur()),
                    not::expr(meta.query_fixed(config.q_first, Rotation::cur())),
                ]);

                let mut cb = BaseConstraintBuilder::default();

                // padding transitions from 0 -> 1 only once.
                let is_padding_cur = config.is_padding.expr_at(meta, Rotation::cur());
                let is_padding_prev = config.is_padding.expr_at(meta, Rotation::prev());
                let is_padding_delta = is_padding_cur.expr() - is_padding_prev;

                cb.require_boolean("is_padding delta is boolean", is_padding_delta);

                // block_idx increments.
                //
                // This also ensures that we are not populating conflicting literal headers for the
                // same block_idx in this layout.
                cb.condition(not::expr(is_padding_cur), |cb| {
                    cb.require_equal(
                        "block_idx increments",
                        meta.query_advice(config.block_idx, Rotation::cur()),
                        meta.query_advice(config.block_idx, Rotation::prev()) + 1.expr(),
                    );
                });

                cb.gate(condition)
            },
        );

        meta.lookup("LiteralsHeaderTable: byte0 >> 3", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let range_value = meta.query_advice(config.byte0, Rotation::cur())
                - (meta.query_advice(config.byte0_rs_3, Rotation::cur()) * 8.expr());

            vec![(condition * range_value, range8.into())]
        });

        meta.lookup("LiteralsHeaderTable: byte0 >> 4", |meta| {
            let condition = and::expr([
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(config.is_padding.expr_at(meta, Rotation::cur())),
            ]);

            let range_value = meta.query_advice(config.byte0, Rotation::cur())
                - (meta.query_advice(config.byte0_rs_4, Rotation::cur()) * 16.expr());

            vec![(condition * range_value, range16.into())]
        });

        debug_assert!(meta.degree() <= 9);
        debug_assert!(meta.clone().chunk_lookups().degree() <= 9);

        config
    }

    /// Assign witness to the literals header table.
    pub fn assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        literals_headers: Vec<(u64, u64, (u64, u64, u64))>,
        n_enabled: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "LiteralsHeaderTable",
            |mut region| {
                region.assign_fixed(|| "q_first", self.q_first, 0, || Value::known(F::one()))?;

                for (offset, (block_idx, _byte_offset, (byte0, byte1, byte2))) in
                    literals_headers.clone().into_iter().enumerate()
                {
                    let lh_bytes = [byte0 as u8, byte1 as u8, byte2 as u8];
                    let literals_block_type = BlockType::from(lh_bytes[0] & 0x3);
                    let size_format = (lh_bytes[0] >> 2) & 3;

                    let [n_bits_fmt, n_bits_regen, n_bytes_header]: [usize; 3] =
                        match literals_block_type {
                            BlockType::RawBlock => match size_format {
                                0b00 | 0b10 => [1, 5, 1],
                                0b01 => [2, 12, 2],
                                0b11 => [2, 20, 3],
                                _ => unreachable!("size_format out of bound"),
                            },
                            _ => unreachable!(
                                "BlockType::* unexpected. Must be raw bytes for literals."
                            ),
                        };

                    // Bits for representing regenerated_size and compressed_size
                    let sizing_bits = &lh_bytes.into_iter().fold(vec![], |mut acc, b| {
                        acc.extend(value_bits_le(b));
                        acc
                    })[(2 + n_bits_fmt)..(n_bytes_header * 8)];

                    let regen_size = le_bits_to_value(&sizing_bits[0..n_bits_regen]);

                    for (col, value, annotation) in [
                        (self.block_idx, block_idx, "block_idx"),
                        (self.byte0, byte0, "byte0"),
                        (self.byte1, byte1, "byte1"),
                        (self.byte2, byte2, "byte2"),
                        (self.regen_size, regen_size, "regen_size"),
                        (
                            self.size_format_bit0,
                            (size_format & 1) as u64,
                            "size_format_bit0",
                        ),
                        (
                            self.size_format_bit1,
                            ((size_format & 2) >> 1) as u64,
                            "size_format_bit1",
                        ),
                        (self.byte0_rs_3, byte0 >> 3, "byte0_rs_3"),
                        (self.byte0_rs_4, byte0 >> 4, "byte0_rs_4"),
                    ] {
                        region.assign_advice(
                            || annotation,
                            col,
                            offset,
                            || Value::known(F::from(value)),
                        )?;
                    }
                }

                for offset in literals_headers.len()..n_enabled {
                    region.assign_advice(
                        || "is_padding",
                        self.is_padding.column,
                        offset,
                        || Value::known(F::one()),
                    )?;
                }

                Ok(())
            },
        )
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
            self.is_padding.column.into(),
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
