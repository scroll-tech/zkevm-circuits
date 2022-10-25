//! Comparison chip can be used to compare LHS and RHS.

use eth_types::Field;
use halo2_proofs::{
    circuit::{Chip, Region, Value},
    plonk::{ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use crate::{
    is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction},
    less_than::{LtChip, LtConfig, LtInstruction},
};

#[derive(Clone, Debug)]
/// Config for the comparison gadget.
pub struct ComparisonConfig<F, const N_BYTES: usize> {
    lt: LtConfig<F, N_BYTES>,
    eq: IsZeroConfig<F>,
}

impl<F: Field, const N_BYTES: usize> ComparisonConfig<F, N_BYTES> {
    /// Returns a tuple of (lt, eq) expressions which is sufficient to compare
    /// LHS and RHS.
    pub fn expr(
        &self,
        meta: &mut VirtualCells<F>,
        rotation: Option<Rotation>,
    ) -> (Expression<F>, Expression<F>) {
        (
            self.lt.is_lt(meta, rotation),
            self.eq.is_zero_expression.clone(),
        )
    }
}

#[derive(Clone, Debug)]
/// Comparison gadget chip.
pub struct ComparisonChip<F, const N_BYTES: usize> {
    config: ComparisonConfig<F, N_BYTES>,
}

impl<F: Field, const N_BYTES: usize> ComparisonChip<F, N_BYTES> {
    /// Configure the comparison gadget to get its config.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl Fn(&mut VirtualCells<'_, F>) -> Expression<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> ComparisonConfig<F, N_BYTES> {
        let diff_inv = meta.advice_column();
        let lt = LtChip::configure(meta, &q_enable, |_| lhs, |_| rhs);
        let eq = IsZeroChip::configure(meta, &q_enable, |meta| lt.diff(meta, None), diff_inv);

        ComparisonConfig { lt, eq }
    }

    /// Construct a comparison chip given its config.
    pub fn construct(config: ComparisonConfig<F, N_BYTES>) -> Self {
        Self { config }
    }

    /// Assign witness data to the comparison gadget.
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(), Error> {
        let lt_chip = LtChip::construct(self.config.lt);
        let eq_chip = IsZeroChip::construct(self.config.eq.clone());
        lt_chip.assign(region, offset, lhs, rhs)?;
        eq_chip.assign(region, offset, Value::known(lhs - rhs))?;

        Ok(())
    }
}

impl<F: Field, const N_BYTES: usize> Chip<F> for ComparisonChip<F, N_BYTES> {
    type Config = ComparisonConfig<F, N_BYTES>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
