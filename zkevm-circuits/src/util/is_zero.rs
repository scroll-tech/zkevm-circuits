use eth_types::Field;
use gadgets::{
    is_zero::{IsZeroChip as IsZeroGadgetChip, IsZeroConfig as IsZeroGadgetConfig},
    util::Expr,
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub(crate) struct IsZeroConfig<F> {
    value: Column<Advice>,
    config: IsZeroGadgetConfig<F>,
}

impl<F: Field> IsZeroConfig<F> {
    /// Returns is_zero expression
    pub(crate) fn expr(
        &self,
        rotation: Rotation,
    ) -> impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F> {
        let (value, value_inv) = (self.value, self.config.value_inv);
        move |meta: &mut VirtualCells<'_, F>| {
            1.expr() - meta.query_advice(value, rotation) * meta.query_advice(value_inv, rotation)
        }
    }
}

/// This chip is a wrapper of IsZeroChip in gadgets.
/// It gives us the ability to access is_zero expression at any Rotation.
#[derive(Clone, Debug)]
pub(crate) struct IsZeroChip<F> {
    config: IsZeroConfig<F>,
}

#[rustfmt::skip]
impl<F: Field> IsZeroChip<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: Column<Advice>,
        value_inv: impl FnOnce(&mut ConstraintSystem<F>) -> Column<Advice>,
    ) -> IsZeroConfig<F> {
        let value_inv = value_inv(meta);
        let config = IsZeroGadgetChip::configure(
            meta,
            q_enable,
            |meta| meta.query_advice(value, Rotation::cur()),
            value_inv,
        );

        IsZeroConfig::<F> {
            value,
            config,
        }
    }

    /// Given an `IsZeroConfig`, construct the chip.
    pub(crate) fn construct(config: IsZeroConfig<F>) -> Self {
        IsZeroChip { config }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<(), Error> {
        let config = &self.config.config;
        // postpone the invert to prover which has batch_invert function to
        // amortize among all is_zero_chip assignments.
        let value_invert = value.into_field().invert();
        region.assign_advice(
            || "witness inverse of value",
            config.value_inv,
            offset,
            || value_invert,
        )?;

        Ok(())
    }
}
