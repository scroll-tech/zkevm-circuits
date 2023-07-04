//! Lt chip can be used to compare LT for two expressions LHS and RHS.

use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use crate::util::sum;

use super::{
    bool_check,
    util::{expr_from_bytes, pow_of_two},
};

/// Instruction that the Lt chip needs to implement.
pub trait LtInstruction<F: FieldExt> {
    /// Assign the lhs and rhs witnesses to the Lt chip's region.
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(), Error>;
}

/// Config for the Lt chip.
#[derive(Clone, Copy, Debug)]
pub struct LtConfig<F, const N_BYTES: usize> {
    /// Denotes the lt outcome. If lhs < rhs then lt == 1, otherwise lt == 0.
    pub lt: Column<Advice>,
    /// Denotes the bytes representation of the difference between lhs and rhs.
    /// Note that the range of each byte is not checked by this config.
    pub diff: [Column<Advice>; N_BYTES],
    /// Denotes the range within which both lhs and rhs lie.
    pub range: F,
}

impl<F: Field, const N_BYTES: usize> LtConfig<F, N_BYTES> {
    /// Returns an expression that denotes whether lhs < rhs, or not.
    pub fn is_lt(&self, meta: &mut VirtualCells<F>, rotation: Option<Rotation>) -> Expression<F> {
        meta.query_advice(self.lt, rotation.unwrap_or_else(Rotation::cur))
    }

    /// Returns an expression representing the difference between LHS and RHS.
    pub fn diff(&self, meta: &mut VirtualCells<F>, rotation: Option<Rotation>) -> Expression<F> {
        let rotation = rotation.unwrap_or_else(Rotation::cur);
        sum::expr(self.diff.iter().map(|c| meta.query_advice(*c, rotation)))
    }
}

/// Chip that compares lhs < rhs.
#[derive(Clone, Debug)]
pub struct LtChip<F, const N_BYTES: usize> {
    pub(crate) config: LtConfig<F, N_BYTES>,
}

impl<F: Field, const N_BYTES: usize> LtChip<F, N_BYTES> {
    /// Configures the Lt chip.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        lhs: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
        rhs: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
    ) -> LtConfig<F, N_BYTES> {
        let lt = meta.advice_column();
        let diff = [(); N_BYTES].map(|_| meta.advice_column());
        let range = pow_of_two(N_BYTES * 8);

        meta.create_gate("lt gate", |meta| {
            let q_enable = q_enable(meta);
            let lt = meta.query_advice(lt, Rotation::cur());

            let diff_bytes = diff
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect::<Vec<Expression<F>>>();

            let check_a =
                lhs(meta) - rhs(meta) - expr_from_bytes(&diff_bytes) + (lt.clone() * range);

            let check_b = bool_check(lt);

            [check_a, check_b]
                .into_iter()
                .map(move |poly| q_enable.clone() * poly)
        });

        LtConfig { lt, diff, range }
    }

    /// Constructs a Lt chip given a config.
    pub fn construct(config: LtConfig<F, N_BYTES>) -> LtChip<F, N_BYTES> {
        LtChip { config }
    }
}

impl<F: Field, const N_BYTES: usize> LtInstruction<F> for LtChip<F, N_BYTES> {
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(), Error> {
        let config = self.config();

        let lt = lhs < rhs;
        region.assign_advice(
            || "lt chip: lt",
            config.lt,
            offset,
            || Value::known(F::from(lt as u64)),
        )?;

        let diff = (lhs - rhs) + (if lt { config.range } else { F::zero() });
        let diff_bytes = diff.to_repr();
        for (idx, diff_column) in config.diff.iter().enumerate() {
            region.assign_advice(
                || format!("lt chip: diff byte {idx}"),
                *diff_column,
                offset,
                || Value::known(F::from(diff_bytes[idx] as u64)),
            )?;
        }

        Ok(())
    }
}

impl<F: Field, const N_BYTES: usize> Chip<F> for LtChip<F, N_BYTES> {
    type Config = LtConfig<F, N_BYTES>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[cfg(test)]
mod test {
    use super::{LtChip, LtConfig, LtInstruction};
    use eth_types::Field;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
        poly::Rotation,
    };
    use std::marker::PhantomData;

    macro_rules! try_test_circuit {
        ($values:expr, $checks:expr, $result:expr) => {{
            // let k = usize::BITS - $values.len().leading_zeros();

            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = usize::BITS - $values.len().leading_zeros() + 2;
            let circuit = TestCircuit::<Fp> {
                values: Some($values),
                checks: Some($checks),
                _marker: PhantomData,
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }

    macro_rules! try_test_circuit_error {
        ($values:expr, $checks:expr) => {{
            // let k = usize::BITS - $values.len().leading_zeros();

            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = usize::BITS - $values.len().leading_zeros() + 2;
            let circuit = TestCircuit::<Fp> {
                values: Some($values),
                checks: Some($checks),
                _marker: PhantomData,
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    #[test]
    fn row_diff_is_lt() {
        #[derive(Clone, Debug)]
        struct TestCircuitConfig<F> {
            q_enable: Selector,
            value: Column<Advice>,
            check: Column<Advice>,
            lt: LtConfig<F, 8>,
        }

        #[derive(Default)]
        struct TestCircuit<F: FieldExt> {
            values: Option<Vec<u64>>,
            // checks[i] = lt(values[i + 1], values[i])
            checks: Option<Vec<bool>>,
            _marker: PhantomData<F>,
        }

        impl<F: Field> Circuit<F> for TestCircuit<F> {
            type Config = TestCircuitConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let q_enable = meta.complex_selector();
                let value = meta.advice_column();
                let check = meta.advice_column();

                let lt = LtChip::configure(
                    meta,
                    |meta| meta.query_selector(q_enable),
                    |meta| meta.query_advice(value, Rotation::prev()),
                    |meta| meta.query_advice(value, Rotation::cur()),
                );

                let config = Self::Config {
                    q_enable,
                    value,
                    check,
                    lt,
                };

                meta.create_gate("check is_lt between adjacent rows", |meta| {
                    let q_enable = meta.query_selector(q_enable);

                    // This verifies lt(value::cur, value::next) is calculated correctly
                    let check = meta.query_advice(config.check, Rotation::cur());

                    vec![q_enable * (config.lt.is_lt(meta, None) - check)]
                });

                config
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let chip = LtChip::construct(config.lt);

                let values: Vec<_> = self
                    .values
                    .as_ref()
                    .map(|values| values.iter().map(|value| F::from(*value)).collect())
                    .ok_or(Error::Synthesis)?;
                let checks = self.checks.as_ref().ok_or(Error::Synthesis)?;
                let (first_value, values) = values.split_at(1);
                let first_value = first_value[0];

                layouter.assign_region(
                    || "witness",
                    |mut region| {
                        region.assign_advice(
                            || "first row value",
                            config.value,
                            0,
                            || Value::known(first_value),
                        )?;

                        let mut value_prev = first_value;
                        for (idx, (value, check)) in values.iter().zip(checks).enumerate() {
                            config.q_enable.enable(&mut region, idx + 1)?;
                            region.assign_advice(
                                || "check",
                                config.check,
                                idx + 1,
                                || Value::known(F::from(*check as u64)),
                            )?;
                            region.assign_advice(
                                || "value",
                                config.value,
                                idx + 1,
                                || Value::known(*value),
                            )?;
                            chip.assign(&mut region, idx + 1, value_prev, *value)?;

                            value_prev = *value;
                        }

                        Ok(())
                    },
                )
            }
        }

        // ok
        try_test_circuit!(vec![1, 2, 3, 4, 5], vec![true, true, true, true], Ok(()));
        try_test_circuit!(vec![1, 2, 1, 3, 2], vec![true, false, true, false], Ok(()));
        // error
        try_test_circuit_error!(vec![5, 4, 3, 2, 1], vec![true, true, true, true]);
        try_test_circuit_error!(vec![1, 2, 1, 3, 2], vec![false, true, false, true]);
    }

    #[test]
    fn column_diff_is_lt() {
        #[derive(Clone, Debug)]
        struct TestCircuitConfig<F> {
            q_enable: Selector,
            value_a: Column<Advice>,
            value_b: Column<Advice>,
            check: Column<Advice>,
            lt: LtConfig<F, 8>,
        }

        #[derive(Default)]
        struct TestCircuit<F: FieldExt> {
            values: Option<Vec<(u64, u64)>>,
            // checks[i] = lt(values[i].0 - values[i].1)
            checks: Option<Vec<bool>>,
            _marker: PhantomData<F>,
        }

        impl<F: Field> Circuit<F> for TestCircuit<F> {
            type Config = TestCircuitConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let q_enable = meta.complex_selector();
                let (value_a, value_b) = (meta.advice_column(), meta.advice_column());
                let check = meta.advice_column();

                let lt = LtChip::configure(
                    meta,
                    |meta| meta.query_selector(q_enable),
                    |meta| meta.query_advice(value_a, Rotation::cur()),
                    |meta| meta.query_advice(value_b, Rotation::cur()),
                );

                let config = Self::Config {
                    q_enable,
                    value_a,
                    value_b,
                    check,
                    lt,
                };

                meta.create_gate("check is_lt between columns in the same row", |meta| {
                    let q_enable = meta.query_selector(q_enable);

                    // This verifies lt(lhs, rhs) is calculated correctly
                    let check = meta.query_advice(config.check, Rotation::cur());

                    vec![q_enable * (config.lt.is_lt(meta, None) - check)]
                });

                config
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let chip = LtChip::construct(config.lt);

                let values: Vec<_> = self
                    .values
                    .as_ref()
                    .map(|values| {
                        values
                            .iter()
                            .map(|(value_a, value_b)| (F::from(*value_a), F::from(*value_b)))
                            .collect()
                    })
                    .ok_or(Error::Synthesis)?;
                let checks = self.checks.as_ref().ok_or(Error::Synthesis)?;

                layouter.assign_region(
                    || "witness",
                    |mut region| {
                        for (idx, ((value_a, value_b), check)) in
                            values.iter().zip(checks).enumerate()
                        {
                            config.q_enable.enable(&mut region, idx + 1)?;
                            region.assign_advice(
                                || "check",
                                config.check,
                                idx + 1,
                                || Value::known(F::from(*check as u64)),
                            )?;
                            region.assign_advice(
                                || "value_a",
                                config.value_a,
                                idx + 1,
                                || Value::known(*value_a),
                            )?;
                            region.assign_advice(
                                || "value_b",
                                config.value_b,
                                idx + 1,
                                || Value::known(*value_b),
                            )?;
                            chip.assign(&mut region, idx + 1, *value_a, *value_b)?;
                        }

                        Ok(())
                    },
                )
            }
        }

        // ok
        try_test_circuit!(
            vec![(1, 2), (4, 4), (5, 5)],
            vec![true, false, false],
            Ok(())
        );
        try_test_circuit!(
            vec![
                (14124, 14124),
                (383168732, 383168731),
                (383168731, 383168732)
            ],
            vec![false, false, true],
            Ok(())
        );
        // error
        try_test_circuit_error!(vec![(1, 2), (3, 4), (5, 6)], vec![false, false, false]);
        try_test_circuit_error!(vec![(1, 1), (3, 4), (6, 6)], vec![true, false, true]);
    }
}
