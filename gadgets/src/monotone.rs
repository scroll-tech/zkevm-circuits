//! # Monotone mod
//! Monotone gadget helps to check if an advice column is monotonically
//! increasing within a range. With strict enabled, it disallows equality of two
//! cell.
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::{
    circuit::{Chip, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use std::{marker::PhantomData, u64};

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct MonotoneConfig {
    range_table: Column<Fixed>,
    value: Column<Advice>,
}

/// MonotoneChip helps to check if an advice column is monotonically increasing
/// within a range. With strict enabled, it disallows equality of two cell.
pub(crate) struct MonotoneChip<F, const RANGE: usize, const INCR: bool, const STRICT: bool> {
    config: MonotoneConfig,
    _marker: PhantomData<F>,
}

#[allow(dead_code)]
impl<F: FieldExt, const RANGE: usize, const INCR: bool, const STRICT: bool>
    MonotoneChip<F, RANGE, INCR, STRICT>
{
    /// configure which column should be check. q_enable here as a fn is
    /// flexible for synthetic selector instead of a fixed one.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: Column<Advice>,
    ) -> MonotoneConfig {
        let range_table = meta.fixed_column();

        let config = MonotoneConfig { range_table, value };

        meta.lookup_any("Range check", |meta| {
            let q_enable = q_enable(meta);
            let range_table = meta.query_fixed(config.range_table, Rotation::cur());
            let value_diff = {
                let value_cur = meta.query_advice(value, Rotation::cur());
                let value_prev = meta.query_advice(value, Rotation::prev());
                if INCR {
                    value_cur - value_prev
                } else {
                    value_prev - value_cur
                }
            };

            // If strict monotone, we subtract diff by one
            // to make sure zero lookup fail
            let min_diff = Expression::Constant(F::from(STRICT as u64));

            vec![(q_enable * (value_diff - min_diff), range_table)]
        });

        config
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "range_table",
            |mut meta| {
                let max = RANGE - STRICT as usize;

                for idx in 0..=max {
                    meta.assign_fixed(
                        || "range_table_value",
                        self.config.range_table,
                        idx,
                        || Value::known(F::from(idx as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }

    pub fn construct(config: MonotoneConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }
}

impl<F: FieldExt, const RANGE: usize, const INCR: bool, const STRICT: bool> Chip<F>
    for MonotoneChip<F, RANGE, INCR, STRICT>
{
    type Config = MonotoneConfig;
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
    use super::{MonotoneChip, MonotoneConfig, Value};
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{
            FailureLocation, MockProver,
            VerifyFailure::{self, Lookup},
        },
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    };
    use std::marker::PhantomData;

    #[derive(Clone, Debug)]
    struct TestCircuitConfig {
        q_enable: Selector,
        value: Column<Advice>,
        mono_incr: MonotoneConfig,
    }

    #[derive(Default)]
    struct TestCircuit<F: FieldExt, const RANGE: usize, const INCR: bool, const STRICT: bool> {
        values: Option<Vec<u64>>,
        _marker: PhantomData<F>,
    }

    impl<F: FieldExt, const RANGE: usize, const INCR: bool, const STRICT: bool> Circuit<F>
        for TestCircuit<F, RANGE, INCR, STRICT>
    {
        type Config = TestCircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let q_enable = meta.complex_selector();
            let value = meta.advice_column();

            let mono_incr = MonotoneChip::<F, RANGE, INCR, STRICT>::configure(
                meta,
                |meta| meta.query_selector(q_enable),
                value,
            );

            Self::Config {
                q_enable,
                value,
                mono_incr,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let monotone_chip =
                MonotoneChip::<F, RANGE, INCR, STRICT>::construct(config.mono_incr.clone());

            monotone_chip.load(&mut layouter)?;

            let values: Vec<_> = self
                .values
                .as_ref()
                .map(|values| values.iter().map(|value| F::from(*value)).collect())
                .ok_or(Error::Synthesis)?;

            layouter.assign_region(
                || "witness",
                |mut region| {
                    for (idx, value) in values.iter().enumerate() {
                        region.assign_advice(
                            || "value",
                            config.value,
                            idx,
                            || Value::known(*value),
                        )?;
                        if idx > 0 {
                            config.q_enable.enable(&mut region, idx)?;
                        }
                    }

                    Ok(())
                },
            )
        }
    }

    macro_rules! gen_try_test_circuit {
        ($range:expr, $incr:expr, $strict:expr) => {
            fn try_test_circuit(values: Vec<u64>, result: Result<(), Vec<VerifyFailure>>) {
                let circuit = TestCircuit::<Fp, $range, $incr, $strict> {
                    values: Some(values),
                    _marker: PhantomData,
                };
                let prover = MockProver::<Fp>::run(
                    usize::BITS - ($range as usize).leading_zeros(),
                    &circuit,
                    vec![],
                )
                .unwrap();
                if result.is_err() {
                    assert_eq!(prover.verify_par(), result)
                } else {
                    prover.assert_satisfied_par()
                }
            }
        };
    }

    #[test]
    fn strict_monotonically_increasing() {
        gen_try_test_circuit!(100, true, true);

        // strict monotone in range (ok)
        try_test_circuit(vec![1, 2, 3, 4, 104], Ok(()));
        try_test_circuit(vec![1001, 1002, 1003, 1004, 1104], Ok(()));
        // non-strict monotone in range (error)
        try_test_circuit(
            vec![1, 2, 2, 4, 4],
            Err(vec![
                Lookup {
                    name: "Range check",
                    lookup_index: 0,
                    location: FailureLocation::InRegion {
                        region: halo2_proofs::dev::metadata::Region::from((1, "witness")),
                        offset: 2,
                    },
                },
                Lookup {
                    name: "Range check",
                    lookup_index: 0,
                    location: FailureLocation::InRegion {
                        region: halo2_proofs::dev::metadata::Region::from((1, "witness")),
                        offset: 4,
                    },
                },
            ]),
        );
        // out of range (error)
        try_test_circuit(
            vec![1, 2, 3, 4, 105],
            Err(vec![Lookup {
                name: "Range check",
                lookup_index: 0,
                location: FailureLocation::InRegion {
                    region: halo2_proofs::dev::metadata::Region::from((1, "witness")),
                    offset: 4,
                },
            }]),
        );
        // not monotone (error)
        try_test_circuit(
            vec![1, 2, 3, 103, 4],
            Err(vec![Lookup {
                name: "Range check",
                lookup_index: 0,
                location: FailureLocation::InRegion {
                    region: halo2_proofs::dev::metadata::Region::from((1, "witness")),
                    offset: 4,
                },
            }]),
        );
    }

    #[test]
    fn non_strict_monotonically_increasing() {
        gen_try_test_circuit!(100, true, false);

        // strict monotone in range (ok)
        try_test_circuit(vec![1, 2, 3, 4, 104], Ok(()));
        try_test_circuit(vec![1001, 1002, 1003, 1004, 1104], Ok(()));
        // non-strict monotone in range (ok)
        try_test_circuit(vec![1, 2, 2, 4, 4], Ok(()));
        // out of range (error)
        try_test_circuit(
            vec![1, 2, 3, 4, 105],
            Err(vec![Lookup {
                name: "Range check",
                lookup_index: 0,
                location: FailureLocation::InRegion {
                    region: halo2_proofs::dev::metadata::Region::from((1, "witness")),
                    offset: 4,
                },
            }]),
        );
        // not monotone (error)
        try_test_circuit(
            vec![1, 2, 3, 103, 4],
            Err(vec![Lookup {
                name: "Range check",
                lookup_index: 0,
                location: FailureLocation::InRegion {
                    region: halo2_proofs::dev::metadata::Region::from((1, "witness")),
                    offset: 4,
                },
            }]),
        );
    }
}
