//! IsEqual chip can be used to check equality of two expressions.

use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Region, Value},
    plonk::{ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use crate::util::Expr;

use super::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};

/// Instruction that the IsEqual chip needs to implement.
pub trait IsEqualInstruction<F: FieldExt> {
    /// Assign lhs and rhs witnesses to the IsEqual chip's region.
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: Value<F>,
        rhs: Value<F>,
    ) -> Result<(), Error>;
}

/// Config for the IsEqual chip.
#[derive(Clone, Debug)]
pub struct IsEqualConfig<F> {
    /// Stores an IsZero chip.
    is_zero_config: IsZeroConfig<F>,
    /// Expression that denotes whether the chip evaluated to equal or not.
    pub is_equal_expression: Expression<F>,
}

impl<F: Field> IsEqualConfig<F> {
    /// Returns the is_equal expression.
    pub fn expr(&self) -> Expression<F> {
        self.is_equal_expression.expr()
    }

    /// Returns the is_equal expression from inputs, at any rotation where q_enable=1.
    pub fn expr_at(
        &self,
        meta: &mut VirtualCells<'_, F>,
        at: Rotation,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Expression<F> {
        self.is_zero_config.expr_at(meta, at, lhs - rhs)
    }
}

/// Chip that compares equality between two expressions.
#[derive(Clone, Debug)]
pub struct IsEqualChip<F> {
    /// Config for the IsEqual chip.
    pub(crate) config: IsEqualConfig<F>,
}

impl<F: Field> IsEqualChip<F> {
    /// Configure the IsEqual chip.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        lhs: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        rhs: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) -> IsEqualConfig<F> {
        let value = |meta: &mut VirtualCells<F>| lhs(meta) - rhs(meta);
        let value_inv = meta.advice_column();

        let is_zero_config = IsZeroChip::configure(meta, q_enable, value, value_inv);
        let is_equal_expression = is_zero_config.expr();

        IsEqualConfig {
            is_zero_config,
            is_equal_expression,
        }
    }

    /// Construct an IsEqual chip given a config.
    pub fn construct(config: IsEqualConfig<F>) -> Self {
        Self { config }
    }
}

impl<F: Field> IsEqualInstruction<F> for IsEqualChip<F> {
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: Value<F>,
        rhs: Value<F>,
    ) -> Result<(), Error> {
        IsZeroChip::construct(self.config.is_zero_config.clone()).assign(
            region,
            offset,
            lhs - rhs,
        )?;

        Ok(())
    }
}

impl<F: Field> Chip<F> for IsEqualChip<F> {
    type Config = IsEqualConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use eth_types::Field;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector, VirtualCells},
        poly::Rotation,
    };
    use rand::Rng;

    use super::{IsEqualChip, IsEqualConfig, IsEqualInstruction};
    use crate::util::Expr;

    #[derive(Clone, Debug)]
    struct TestCircuitConfig<F, const RHS: u64> {
        q_enable: Selector,
        value: Column<Advice>,
        check: Column<Advice>,
        is_equal: IsEqualConfig<F>,
    }

    #[derive(Default)]
    struct TestCircuit<F: FieldExt, const RHS: u64> {
        values: Vec<u64>,
        checks: Vec<bool>,
        _marker: PhantomData<F>,
    }

    impl<F: Field, const RHS: u64> Circuit<F> for TestCircuit<F, RHS> {
        type Config = TestCircuitConfig<F, RHS>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable = meta.complex_selector();
            let value = meta.advice_column();
            let check = meta.advice_column();

            let lhs = |meta: &mut VirtualCells<F>| meta.query_advice(value, Rotation::cur());
            let rhs = |_meta: &mut VirtualCells<F>| RHS.expr();

            let is_equal =
                IsEqualChip::configure(meta, |meta| meta.query_selector(q_enable), lhs, rhs);

            let config = Self::Config {
                q_enable,
                value,
                check,
                is_equal,
            };

            meta.create_gate("check is_equal", |meta| {
                let q_enable = meta.query_selector(q_enable);

                let check = meta.query_advice(check, Rotation::cur());

                vec![q_enable * (config.is_equal.is_equal_expression.clone() - check)]
            });

            config
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = IsEqualChip::construct(config.is_equal.clone());

            layouter.assign_region(
                || "witness",
                |mut region| {
                    let checks = self.checks.clone();

                    for (idx, (value, check)) in self.values.iter().cloned().zip(checks).enumerate()
                    {
                        region.assign_advice(
                            || "value",
                            config.value,
                            idx + 1,
                            || Value::known(F::from(value)),
                        )?;
                        region.assign_advice(
                            || "check",
                            config.check,
                            idx + 1,
                            || Value::known(F::from(check as u64)),
                        )?;
                        config.q_enable.enable(&mut region, idx + 1)?;
                        chip.assign(
                            &mut region,
                            idx + 1,
                            Value::known(F::from(value)),
                            Value::known(F::from(RHS)),
                        )?;
                    }

                    Ok(())
                },
            )
        }
    }

    macro_rules! try_test {
        ($values:expr, $checks:expr, $rhs:expr, $is_ok_or_err:ident) => {
            let k = usize::BITS - $values.len().leading_zeros() + 2;
            let circuit = TestCircuit::<Fp, $rhs> {
                values: $values,
                checks: $checks,
                _marker: PhantomData,
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().$is_ok_or_err());
        };
    }

    fn random() -> u64 {
        rand::thread_rng().gen::<u64>()
    }

    #[test]
    fn is_equal_gadget() {
        try_test!(
            vec![random(), 123, random(), 123, 123, random()],
            vec![false, true, false, true, true, false],
            123,
            is_ok
        );
        try_test!(
            vec![random(), 321321, 321321, random()],
            vec![false, true, true, false],
            321321,
            is_ok
        );
        try_test!(
            vec![random(), random(), random(), 1846123],
            vec![false, false, false, true],
            1846123,
            is_ok
        );
        try_test!(
            vec![123, 234, 345, 456],
            vec![true, true, false, false],
            234,
            is_err
        );
    }
}
