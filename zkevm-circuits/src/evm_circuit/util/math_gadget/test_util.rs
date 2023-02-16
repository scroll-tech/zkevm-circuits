use itertools::Itertools;
use std::marker::PhantomData;
use strum::IntoEnumIterator;

use crate::evm_circuit::{
    param::{MAX_STEP_HEIGHT, N_PHASE2_COLUMNS, STEP_WIDTH},
    step::{ExecutionState, Step},
    table::{FixedTableTag, Table},
    util::{
        constraint_builder::ConstraintBuilder, rlc, CachedRegion, CellType, Expr, StoredExpression,
        LOOKUP_CONFIG,
    },
    Advice, Column, Fixed,
};
use crate::table::LookupTable;

#[cfg(not(feature = "onephase"))]
use crate::util::Challenges;
#[cfg(feature = "onephase")]
use crate::util::MockChallenges as Challenges;

use halo2_proofs::plonk::FirstPhase;
#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as ThirdPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::ThirdPhase;

use eth_types::{Field, Word, U256};
pub(crate) use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::{
    circuit::SimpleFloorPlanner,
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error, Selector},
};

pub(crate) const WORD_LOW_MAX: Word = U256([u64::MAX, u64::MAX, 0, 0]);
pub(crate) const WORD_HIGH_MAX: Word = U256([0, 0, u64::MAX, u64::MAX]);
// Maximum field value in bn256: bn256::MODULES - 1
pub(crate) const WORD_CELL_MAX: Word = U256([
    0x43e1f593f0000000,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
]);

// I256::MAX = 2^255 - 1, and I256::MIN = 2^255.
pub(crate) const WORD_SIGNED_MAX: Word = U256([u64::MAX, u64::MAX, u64::MAX, i64::MAX as _]);
pub(crate) const WORD_SIGNED_MIN: Word = U256([0, 0, 0, i64::MIN as _]);

pub(crate) fn generate_power_of_randomness<F: Field>(randomness: F) -> Vec<F> {
    (1..32).map(|exp| randomness.pow(&[exp, 0, 0, 0])).collect()
}

pub(crate) trait MathGadgetContainer<F: Field>: Clone {
    fn configure_gadget_container(cb: &mut ConstraintBuilder<F>) -> Self
    where
        Self: Sized;

    fn assign_gadget_container(
        &self,
        witnesses: &[Word],
        region: &mut CachedRegion<'_, '_, F>,
    ) -> Result<(), Error>;
}

#[derive(Debug, Clone)]
pub(crate) struct UnitTestMathGadgetBaseCircuitConfig<F: Field, G>
where
    G: MathGadgetContainer<F>,
{
    q_usable: Selector,
    fixed_table: [Column<Fixed>; 4],
    advices: [Column<Advice>; STEP_WIDTH],
    step: Step<F>,
    stored_expressions: Vec<StoredExpression<F>>,
    math_gadget_container: G,
    _marker: PhantomData<F>,
}

pub(crate) struct UnitTestMathGadgetBaseCircuit<G> {
    size: usize,
    witnesses: Vec<Word>,
    _marker: PhantomData<G>,
}

impl<G> UnitTestMathGadgetBaseCircuit<G> {
    fn new(size: usize, witnesses: Vec<Word>) -> Self {
        UnitTestMathGadgetBaseCircuit {
            size,
            witnesses,
            _marker: PhantomData,
        }
    }
}

impl<F: Field, G: MathGadgetContainer<F>> Circuit<F> for UnitTestMathGadgetBaseCircuit<G> {
    type Config = (UnitTestMathGadgetBaseCircuitConfig<F, G>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        UnitTestMathGadgetBaseCircuit {
            size: 0,
            witnesses: vec![],
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenges_exprs = challenges.exprs(meta);

        let q_usable = meta.selector();
        let fixed_table = [(); 4].map(|_| meta.fixed_column());

        let lookup_column_count: usize = LOOKUP_CONFIG.iter().map(|(_, count)| *count).sum();
        let advices = [(); STEP_WIDTH]
            .iter()
            .enumerate()
            .map(|(n, _)| {
                if n < lookup_column_count {
                    meta.advice_column_in(ThirdPhase)
                } else if n < lookup_column_count + N_PHASE2_COLUMNS {
                    meta.advice_column_in(SecondPhase)
                } else {
                    meta.advice_column_in(FirstPhase)
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let step_curr = Step::new(meta, advices, 0, false);
        let step_next = Step::new(meta, advices, MAX_STEP_HEIGHT, true);
        let mut cb = ConstraintBuilder::new(
            step_curr.clone(),
            step_next,
            &challenges_exprs,
            ExecutionState::STOP,
        );
        let math_gadget_container = G::configure_gadget_container(&mut cb);
        let (constraints, stored_expressions, _) = cb.build();

        if !constraints.step.is_empty() {
            let step_constraints = constraints.step;
            meta.create_gate("MathGadgetTestContainer", |meta| {
                let q_usable = meta.query_selector(q_usable);
                step_constraints
                    .into_iter()
                    .map(move |(name, constraint)| (name, q_usable.clone() * constraint))
            });
        }

        let cell_manager = step_curr.cell_manager.clone();
        for column in cell_manager.columns().iter() {
            if let CellType::Lookup(table) = column.cell_type {
                if table == Table::Fixed {
                    let name = format!("{:?}", table);
                    meta.lookup_any(Box::leak(name.into_boxed_str()), |meta| {
                        let table_expressions = fixed_table.table_exprs(meta);
                        vec![(
                            column.expr(),
                            rlc::expr(&table_expressions, challenges_exprs.lookup_input()),
                        )]
                    });
                }
            }
        }

        (
            UnitTestMathGadgetBaseCircuitConfig::<F, G> {
                q_usable,
                fixed_table,
                advices,
                step: step_curr,
                stored_expressions,
                math_gadget_container,
                _marker: PhantomData,
            },
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let (config, challenges) = config;
        let challenge_values = challenges.values(&layouter);
        layouter.assign_region(
            || "assign test container",
            |mut region| {
                let offset = 0;
                config.q_usable.enable(&mut region, offset)?;
                let cached_region = &mut CachedRegion::<'_, '_, F>::new(
                    &mut region,
                    &challenge_values,
                    config.advices.to_vec(),
                    MAX_STEP_HEIGHT * 3,
                    offset,
                );
                config.step.state.execution_state.assign(
                    cached_region,
                    offset,
                    ExecutionState::STOP as usize,
                )?;
                config
                    .math_gadget_container
                    .assign_gadget_container(&self.witnesses, cached_region)?;

                for stored_expr in &config.stored_expressions {
                    stored_expr.assign(cached_region, offset)?;
                }

                Ok(())
            },
        )?;

        // assign fixed range tables only as they are the only tables referred by a
        // specfic math gadget -- ConstantDivisionGadget.
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                for (offset, row) in std::iter::once([F::zero(); 4])
                    .chain(
                        FixedTableTag::iter()
                            .filter(|t| {
                                matches!(
                                    t,
                                    FixedTableTag::Range5
                                        | FixedTableTag::Range16
                                        | FixedTableTag::Range32
                                        | FixedTableTag::Range64
                                        | FixedTableTag::Range128
                                        | FixedTableTag::Range256
                                        | FixedTableTag::Range512
                                        | FixedTableTag::Range1024
                                )
                            })
                            .flat_map(|tag| tag.build()),
                    )
                    .enumerate()
                {
                    for (column, value) in config.fixed_table.iter().zip_eq(row) {
                        region.assign_fixed(|| "", *column, offset, || Value::known(value))?;
                    }
                }

                Ok(())
            },
        )
    }
}

/// This fn test_math_gadget_container takes math gadget container and run a
/// container based circuit. All test logic should be included in the container,
/// and witness words are used for both input & output data. How to deal with
/// the witness words is left to each container.
pub(crate) fn test_math_gadget_container<F: Field, G: MathGadgetContainer<F>>(
    witnesses: Vec<Word>,
    expected_success: bool,
) {
    const K: usize = 12;
    let circuit = UnitTestMathGadgetBaseCircuit::<G>::new(K, witnesses);

    let prover = MockProver::<F>::run(K as u32, &circuit, vec![]).unwrap();
    if expected_success {
        assert_eq!(prover.verify(), Ok(()));
    } else {
        assert_ne!(prover.verify(), Ok(()));
    }
}

/// A simple macro for less code & better readability
macro_rules! try_test {
    ($base_class:ty, $witnesses:expr, $expect_success:expr $(,)?) => {{
        test_math_gadget_container::<Fr, $base_class>($witnesses.to_vec(), $expect_success)
    }};
}

#[cfg(test)]
pub(crate) use try_test;
