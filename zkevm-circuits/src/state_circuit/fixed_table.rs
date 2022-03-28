use halo2_proofs::{
    circuit::Layouter,
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use pairing::arithmetic::FieldExt;

#[derive(Clone, Copy, Debug)]
pub struct FixedTable {
    u8: Column<Fixed>,
    u10: Column<Fixed>,
    u16: Column<Fixed>,
}

impl FixedTable {
    pub(crate) fn configure<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
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

    pub(crate) fn load<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (column, exponent) in [(self.u8, 8), (self.u10, 10), (self.u16, 16)] {
            layouter.assign_region(
                || format!("assign u{} fixed column", exponent),
                |mut region| {
                    for i in 0..(1 << exponent) {
                        region.assign_fixed(
                            || format!("assign {} in u{} fixed column", i, exponent),
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
