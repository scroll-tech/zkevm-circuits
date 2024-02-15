use eth_types::Field;
use gadgets::{
    binary_number::{BinaryNumberChip, BinaryNumberConfig},
    impl_expr,
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use strum_macros::EnumIter;

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::{BitwiseOp, BitwiseOpTable, LookupTable, RangeTable},
};

/// Different branches that can be taken while calculating regenerated size and compressed size in
/// the Literals Header.
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum LiteralsHeaderBranch {
    /// Raw/RLE block type with size_format 00 or 10.
    RawRle0 = 0,
    /// Raw/RLE block type with size format 10.
    RawRle1,
    /// Raw/RLE block type with size format 11.
    RawRle2,
    /// Compressed block type with size format 00 or 01.
    Compressed0,
    /// Compressed block type with size format 10.
    Compressed1,
    /// Compressed block type with size format 11.
    Compressed2,
}

impl_expr!(LiteralsHeaderBranch);

impl From<u64> for LiteralsHeaderBranch {
    fn from(value: u64) -> Self {
        match value {
            0 => Self::RawRle0,
            1 => Self::RawRle1,
            2 => Self::RawRle2,
            3 => Self::Compressed0,
            4 => Self::Compressed1,
            5 => Self::Compressed2,
            _ => unreachable!("LiteralsHeaderBranch only from 0..=5"),
        }
    }
}

impl From<LiteralsHeaderBranch> for usize {
    fn from(value: LiteralsHeaderBranch) -> Self {
        value as usize
    }
}

/// Helper table to calculate regenerated and compressed size from the Literals Header.
#[derive(Clone, Debug)]
pub struct LiteralsHeaderTable {
    /// Whether to enable.
    pub q_enable: Column<Fixed>,
    /// Byte offset at which this literals header is located.
    pub byte_offset: Column<Advice>,
    /// The branch taken for this literals header.
    pub branch: Column<Advice>,
    /// To identify the branch.
    pub branch_bits: BinaryNumberConfig<LiteralsHeaderBranch, 3>,
    /// The first byte of the literals header.
    pub byte0: Column<Advice>,
    /// The second byte.
    pub byte1: Column<Advice>,
    /// The third byte.
    pub byte2: Column<Advice>,
    /// The fourth byte.
    pub byte3: Column<Advice>,
    /// The fifth byte.
    pub byte4: Column<Advice>,
    /// byte0 >> 3.
    pub byte0_rs_3: Column<Advice>,
    /// byte0 >> 4.
    pub byte0_rs_4: Column<Advice>,
    /// byte1 >> 6.
    pub byte1_rs_6: Column<Advice>,
    /// byte1 & 0b111111.
    pub byte1_and_63: Column<Advice>,
    /// byte2 >> 2.
    pub byte2_rs_2: Column<Advice>,
    /// byte2 >> 6.
    pub byte2_rs_6: Column<Advice>,
    /// byte2 & 0b11.
    pub byte2_and_3: Column<Advice>,
    /// byte2 & 0b111111.
    pub byte2_and_63: Column<Advice>,
    /// Regenerated size.
    pub regen_size: Column<Advice>,
    /// Compressed size.
    pub compr_size: Column<Advice>,
}

impl LiteralsHeaderTable {
    /// Construct and constrain the literals header table.
    pub fn construct<F: Field>(
        meta: &mut ConstraintSystem<F>,
        bitwise_op_table: BitwiseOpTable,
        range4: RangeTable<4>,
        range8: RangeTable<8>,
        range16: RangeTable<16>,
        range64: RangeTable<64>,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let branch = meta.advice_column();
        let table = Self {
            q_enable,
            byte_offset: meta.advice_column(),
            branch,
            branch_bits: BinaryNumberChip::configure(meta, q_enable, Some(branch.into())),
            byte0: meta.advice_column(),
            byte1: meta.advice_column(),
            byte2: meta.advice_column(),
            byte3: meta.advice_column(),
            byte4: meta.advice_column(),
            byte0_rs_3: meta.advice_column(),
            byte0_rs_4: meta.advice_column(),
            byte1_rs_6: meta.advice_column(),
            byte1_and_63: meta.advice_column(),
            byte2_rs_2: meta.advice_column(),
            byte2_rs_6: meta.advice_column(),
            byte2_and_3: meta.advice_column(),
            byte2_and_63: meta.advice_column(),
            regen_size: meta.advice_column(),
            compr_size: meta.advice_column(),
        };

        macro_rules! is_branch {
            ($var:ident, $branch_variant:ident) => {
                let $var = |meta: &mut VirtualCells<F>| {
                    table
                        .branch_bits
                        .value_equals(LiteralsHeaderBranch::$branch_variant, Rotation::cur())(
                        meta
                    )
                };
            };
        }

        is_branch!(branch0, RawRle0);
        is_branch!(branch1, RawRle1);
        is_branch!(branch2, RawRle2);
        is_branch!(branch3, Compressed0);
        is_branch!(branch4, Compressed1);
        is_branch!(branch5, Compressed2);

        meta.create_gate("LiteralsHeaderTable", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let byte0_rs_3 = meta.query_advice(table.byte0_rs_3, Rotation::cur());
            let byte0_rs_4 = meta.query_advice(table.byte0_rs_4, Rotation::cur());
            let byte1_ls_4 = meta.query_advice(table.byte1, Rotation::cur()) * 16.expr();
            let byte1_and_63_ls_4 =
                meta.query_advice(table.byte1_and_63, Rotation::cur()) * 16.expr();
            let byte1_rs_6 = meta.query_advice(table.byte1_rs_6, Rotation::cur());
            let byte2_rs_2 = meta.query_advice(table.byte2_rs_2, Rotation::cur());
            let byte2_rs_6 = meta.query_advice(table.byte2_rs_6, Rotation::cur());
            let byte2_ls_2 = meta.query_advice(table.byte2, Rotation::cur()) * 4.expr();
            let byte2_ls_12 = meta.query_advice(table.byte2, Rotation::cur()) * 4096.expr();
            let byte2_and_3_ls_12 =
                meta.query_advice(table.byte2_and_3, Rotation::cur()) * 4096.expr();
            let byte2_and_63_ls_12 =
                meta.query_advice(table.byte2_and_63, Rotation::cur()) * 4096.expr();
            let byte3_ls_6 = meta.query_advice(table.byte3, Rotation::cur()) * 64.expr();
            let byte3_ls_2 = meta.query_advice(table.byte3, Rotation::cur()) * 4.expr();
            let byte4_ls_10 = meta.query_advice(table.byte4, Rotation::cur()) * 1024.expr();

            // regen_size == lh_byte[0] >> 3.
            // compr_size == 0.
            cb.condition(branch0(meta), |cb| {
                cb.require_equal(
                    "branch0: regenerated size",
                    meta.query_advice(table.regen_size, Rotation::cur()),
                    byte0_rs_3,
                );
                cb.require_zero(
                    "branch0: compressed size",
                    meta.query_advice(table.compr_size, Rotation::cur()),
                );
                for col in [table.byte1, table.byte2, table.byte3, table.byte4] {
                    cb.require_zero("byte[i] == 0", meta.query_advice(col, Rotation::cur()));
                }
            });

            // regen_size == (lh_byte[0] >> 4) + (lh_byte[1] << 4).
            // compr_size == 0.
            cb.condition(branch1(meta), |cb| {
                cb.require_equal(
                    "branch1: regenerated size",
                    meta.query_advice(table.regen_size, Rotation::cur()),
                    byte0_rs_4.expr() + byte1_ls_4.expr(),
                );
                cb.require_zero(
                    "branch1: compressed size",
                    meta.query_advice(table.compr_size, Rotation::cur()),
                );
                for col in [table.byte2, table.byte3, table.byte4] {
                    cb.require_zero("byte[i] == 0", meta.query_advice(col, Rotation::cur()));
                }
            });

            // regen_size == (lh_byte[0] >> 4) + (lh_byte[1] << 4) + (lh_byte[2] << 12).
            // compr_size == 0.
            cb.condition(branch2(meta), |cb| {
                cb.require_equal(
                    "branch2: regenerated size",
                    meta.query_advice(table.regen_size, Rotation::cur()),
                    byte0_rs_4.expr() + byte1_ls_4.expr() + byte2_ls_12,
                );
                cb.require_zero(
                    "branch2: compressed size",
                    meta.query_advice(table.compr_size, Rotation::cur()),
                );
                for col in [table.byte3, table.byte4] {
                    cb.require_zero("byte[i] == 0", meta.query_advice(col, Rotation::cur()));
                }
            });

            // regen_size == (lh_byte[0] >> 4) + ((lh_byte[1] & 0b111111) << 4).
            // compr_size == (lh_byte[1] >> 6) + (lh_byte[2] << 2).
            cb.condition(branch3(meta), |cb| {
                cb.require_equal(
                    "branch3: regenerated size",
                    meta.query_advice(table.regen_size, Rotation::cur()),
                    byte0_rs_4.expr() + byte1_and_63_ls_4,
                );
                cb.require_equal(
                    "branch3: compressed size",
                    meta.query_advice(table.compr_size, Rotation::cur()),
                    byte1_rs_6 + byte2_ls_2.expr(),
                );
                for col in [table.byte3, table.byte4] {
                    cb.require_zero("byte[i] == 0", meta.query_advice(col, Rotation::cur()));
                }
            });

            // regen_size == (lh_byte[0] >> 4) + (lh_byte[1] << 4) + ((lh_byte[2] & 0b11) << 12).
            // compr_size == (lh_byte[2] >> 2) + (lh_byte[3] << 6).
            cb.condition(branch4(meta), |cb| {
                cb.require_equal(
                    "branch4: regenerated size",
                    meta.query_advice(table.regen_size, Rotation::cur()),
                    byte0_rs_4.expr() + byte1_ls_4.expr() + byte2_and_3_ls_12,
                );
                cb.require_equal(
                    "branch4: compressed size",
                    meta.query_advice(table.compr_size, Rotation::cur()),
                    byte2_rs_2 + byte3_ls_6,
                );
                cb.require_zero(
                    "byte[i] == 0",
                    meta.query_advice(table.byte4, Rotation::cur()),
                );
            });

            // regen_size == (lh_byte[0] >> 4) + (lh_byte[1] << 4) + ((lh_byte[2] & 0b111111) <<
            // 12). compr_size == (lh_byte[2] >> 6) + (lh_byte[3] << 2) + (lh_byte[4] <<
            // 10).
            cb.condition(branch5(meta), |cb| {
                cb.require_equal(
                    "branch5: regenerated size",
                    meta.query_advice(table.regen_size, Rotation::cur()),
                    byte0_rs_4 + byte1_ls_4 + byte2_and_63_ls_12,
                );
                cb.require_equal(
                    "branch5: compressed size",
                    meta.query_advice(table.compr_size, Rotation::cur()),
                    byte2_rs_6 + byte3_ls_2 + byte4_ls_10,
                );
            });

            cb.gate(meta.query_fixed(table.q_enable, Rotation::cur()))
        });
        meta.lookup("LiteralsHeaderTable: byte0 >> 3", |meta| {
            let condition = meta.query_fixed(table.q_enable, Rotation::cur());
            let range_value = meta.query_advice(table.byte0, Rotation::cur())
                - (meta.query_advice(table.byte0_rs_3, Rotation::cur()) * 8.expr());

            vec![(condition * range_value, range8.into())]
        });
        meta.lookup("LiteralsHeaderTable: byte0 >> 4", |meta| {
            let condition = meta.query_fixed(table.q_enable, Rotation::cur());
            let range_value = meta.query_advice(table.byte0, Rotation::cur())
                - (meta.query_advice(table.byte0_rs_4, Rotation::cur()) * 16.expr());

            vec![(condition * range_value, range16.into())]
        });
        meta.lookup("LiteralsHeaderTable: byte1 >> 6", |meta| {
            let condition = meta.query_fixed(table.q_enable, Rotation::cur());
            let range_value = meta.query_advice(table.byte1, Rotation::cur())
                - (meta.query_advice(table.byte1_rs_6, Rotation::cur()) * 64.expr());

            vec![(condition * range_value, range64.into())]
        });
        meta.lookup("LiteralsHeaderTable: byte2 >> 2", |meta| {
            let condition = meta.query_fixed(table.q_enable, Rotation::cur());
            let range_value = meta.query_advice(table.byte2, Rotation::cur())
                - (meta.query_advice(table.byte2_rs_2, Rotation::cur()) * 4.expr());

            vec![(condition * range_value, range4.into())]
        });
        meta.lookup("LiteralsHeaderTable: byte2 >> 6", |meta| {
            let condition = meta.query_fixed(table.q_enable, Rotation::cur());
            let range_value = meta.query_advice(table.byte2, Rotation::cur())
                - (meta.query_advice(table.byte2_rs_6, Rotation::cur()) * 64.expr());

            vec![(condition * range_value, range64.into())]
        });
        meta.lookup_any("LiteralsHeaderTable: byte1 & 63", |meta| {
            let condition = and::expr([
                meta.query_fixed(table.q_enable, Rotation::cur()),
                not::expr(branch0(meta)),
            ]);
            [
                BitwiseOp::AND.expr(),
                meta.query_advice(table.byte1, Rotation::cur()),
                63.expr(),
                meta.query_advice(table.byte1_and_63, Rotation::cur()),
            ]
            .into_iter()
            .zip(bitwise_op_table.table_exprs(meta))
            .map(|(input, table)| (input * condition.clone(), table))
            .collect::<Vec<_>>()
        });
        meta.lookup_any("LiteralsHeaderTable: byte2 & 3", |meta| {
            let condition = meta.query_fixed(table.q_enable, Rotation::cur());
            [
                BitwiseOp::AND.expr(),
                meta.query_advice(table.byte2, Rotation::cur()),
                3.expr(),
                meta.query_advice(table.byte2_and_3, Rotation::cur()),
            ]
            .into_iter()
            .zip(bitwise_op_table.table_exprs(meta))
            .map(|(input, table)| (input * condition.clone(), table))
            .collect::<Vec<_>>()
        });
        meta.lookup_any("LiteralsHeaderTable: byte2 & 63", |meta| {
            let condition = meta.query_fixed(table.q_enable, Rotation::cur());
            [
                BitwiseOp::AND.expr(),
                meta.query_advice(table.byte2, Rotation::cur()),
                63.expr(),
                meta.query_advice(table.byte2_and_63, Rotation::cur()),
            ]
            .into_iter()
            .zip(bitwise_op_table.table_exprs(meta))
            .map(|(input, table)| (input * condition.clone(), table))
            .collect::<Vec<_>>()
        });

        debug_assert!(meta.degree() <= 9);

        table
    }

    /// Assign witness to the literals header table.
    pub fn assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        literals_headers: &[(u64, &[u8], u64, u64, u64)], /* (byte_offset, bytes, branch,
                                                           * regen_size, compr_size) */
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "LiteralsHeaderTable",
            |mut region| {
                for (offset, &(byte_offset, header, branch, regen_size, compr_size)) in
                    literals_headers.iter().enumerate()
                {
                    assert!(header.len() <= 5);
                    let [byte0, byte1, byte2, byte3, byte4] = [0, 1, 2, 3, 4]
                        .map(|i| header.get(i).cloned().map_or(0u64, |byte| byte as u64));
                    region.assign_fixed(
                        || "q_enable",
                        self.q_enable,
                        offset,
                        || Value::known(F::one()),
                    )?;
                    for (col, value, annotation) in [
                        (self.byte_offset, byte_offset, "byte_offset"),
                        (self.branch, branch, "branch"),
                        (self.byte0, byte0, "byte0"),
                        (self.byte1, byte1, "byte1"),
                        (self.byte2, byte2, "byte2"),
                        (self.byte3, byte3, "byte3"),
                        (self.byte4, byte4, "byte4"),
                        (self.byte0_rs_3, byte0 >> 3, "byte0_rs_3"),
                        (self.byte0_rs_4, byte0 >> 4, "byte0_rs_4"),
                        (self.byte1_rs_6, byte1 >> 6, "byte1_rs_6"),
                        (self.byte1_and_63, byte1 & 63, "byte1_and_63"),
                        (self.byte2_rs_2, byte2 >> 2, "byte2_rs_2"),
                        (self.byte2_rs_6, byte2 >> 6, "byte2_rs_6"),
                        (self.byte2_and_3, byte2 & 3, "byte2_and_3"),
                        (self.byte2_and_63, byte2 & 63, "byte2_and_63"),
                        (self.regen_size, regen_size, "regen_size"),
                        (self.compr_size, compr_size, "compr_size"),
                    ] {
                        region.assign_advice(
                            || annotation,
                            col,
                            offset,
                            || Value::known(F::from(value)),
                        )?;
                    }
                    let branch_chip = BinaryNumberChip::construct(self.branch_bits);
                    branch_chip.assign(&mut region, offset, &LiteralsHeaderBranch::from(branch))?;
                }

                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for LiteralsHeaderTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.byte_offset.into(),
            self.branch.into(),
            self.byte0.into(),
            self.byte1.into(),
            self.byte2.into(),
            self.byte3.into(),
            self.byte4.into(),
            self.regen_size.into(),
            self.compr_size.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("byte_offset"),
            String::from("branch"),
            String::from("byte0"),
            String::from("byte1"),
            String::from("byte2"),
            String::from("byte3"),
            String::from("byte4"),
            String::from("regen_size"),
            String::from("compr_size"),
        ]
    }
}
