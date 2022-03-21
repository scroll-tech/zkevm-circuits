use crate::impl_expr;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::{Column, ConstraintSystem, Error, Expression, Fixed};
use halo2_proofs::poly::Rotation;
use halo2_proofs::plonk::VirtualCells;
use strum_macros::EnumIter;
use pairing::arithmetic::FieldExt;

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum FixedTableTag {
    U8,
    U10,
    U16,
}

impl_expr!(FixedTableTag);

#[derive(Clone, Copy, Debug)]
pub struct FixedTable {
    u8: Column<Fixed>,
    u10: Column<Fixed>,
    u16: Column<Fixed>,
}

impl FixedTable {
    pub(crate) fn configure<F: FieldExt> (meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            u8: meta.fixed_column(),
            u10: meta.fixed_column(),
            u16: meta.fixed_column(),
        }
    }

    pub(crate) fn u8<F: FieldExt>(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.u8, Rotation::cur())
    }

    pub(crate) fn u10<F: FieldExt>(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.u10, Rotation::cur())
    }

    pub(crate) fn u16<F: FieldExt>(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        meta.query_fixed(self.u16, Rotation::cur())
    }

    pub(crate) fn load<F: FieldExt> (&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (column, tag, limit) in [
            (self.u8, FixedTableTag::U8, 1 << 8),
            (self.u10, FixedTableTag::U10, 1 << 10),
            // (self.u16, FixedTableTag::U16, 1 << 16),
        ] {
            layouter.assign_region(
                || format!("assign {:?} fixed column", tag),
                |mut region| {
                    for i in 0..limit {
                        region.assign_fixed(
                            || format!("assign {} in {:?} fixed column", i, tag),
                            column,
                            i,
                            || Ok(F::from(i as u64)),
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }
}
