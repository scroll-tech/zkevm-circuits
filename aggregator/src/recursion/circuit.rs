#![allow(clippy::type_complexity)]
use std::{fs::File, iter, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use snark_verifier::{
    loader::halo2::{halo2_ecc::halo2_base as sv_halo2_base, EccInstructions, IntegerInstructions},
    pcs::{
        kzg::{Bdfg21, Kzg, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey},
        AccumulationScheme, AccumulationSchemeProver,
    },
    util::{
        arithmetic::{fe_to_fe, fe_to_limbs},
        hash,
    },
};
use snark_verifier_sdk::{
    types::{Halo2Loader, Plonk},
    SnarkWitness,
};
use sv_halo2_base::{
    gates::GateInstructions, halo2_proofs, AssignedValue, Context, ContextParams,
    QuantumCell::Existing,
};

use crate::param::ConfigParams as RecursionCircuitConfigParams;

use super::*;

/// Convenience type to represent the verifying key.
type Svk = KzgSuccinctVerifyingKey<G1Affine>;

/// Convenience type to represent the polynomial commitment scheme.
type Pcs = Kzg<Bn256, Bdfg21>;

/// Convenience type to represent the accumulation scheme for accumulating proofs from multiple
/// SNARKs.
type As = KzgAs<Pcs>;

/// Select condition ? LHS : RHS.
fn select_accumulator<'a>(
    loader: &Rc<Halo2Loader<'a>>,
    condition: &AssignedValue<Fr>,
    lhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
    rhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
    let [lhs, rhs]: [_; 2] = [lhs.lhs.assigned(), lhs.rhs.assigned()]
        .iter()
        .zip([rhs.lhs.assigned(), rhs.rhs.assigned()].iter())
        .map(|(lhs, rhs)| {
            loader
                .ecc_chip()
                .select(&mut loader.ctx_mut(), lhs, rhs, condition)
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    Ok(KzgAccumulator::new(
        loader.ec_point_from_assigned(lhs),
        loader.ec_point_from_assigned(rhs),
    ))
}

/// Accumulate a value into the current accumulator.
fn accumulate<'a>(
    loader: &Rc<Halo2Loader<'a>>,
    accumulators: Vec<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
    as_proof: Value<&'_ [u8]>,
) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, as_proof);
    let proof = As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
    As::verify(&Default::default(), &accumulators, &proof).unwrap()
}

#[derive(Clone)]
pub struct RecursionCircuit<ST> {
    /// The verifying key for the circuit.
    svk: Svk,
    /// The default accumulator to initialise the circuit.
    default_accumulator: KzgAccumulator<G1Affine, NativeLoader>,
    /// The SNARK witness from the k-th BatchCircuit.
    app: SnarkWitness,
    /// The SNARK witness from the (k-1)-th BatchCircuit.
    previous: SnarkWitness,
    /// The recursion round, starting at round=0 and incrementing at every subsequent recursion.
    round: usize,
    /// The public inputs to the RecursionCircuit itself.
    instances: Vec<Fr>,
    /// The accumulation of the SNARK proofs recursed over thus far.
    as_proof: Value<Vec<u8>>,

    _marker: PhantomData<ST>,
}

impl<ST: StateTransition> RecursionCircuit<ST> {
    /// The index of the preprocessed digest in the [`RecursionCircuit`]'s instances. Note that we
    /// need a single cell to hold this value as it is a poseidon hash over the bn256 curve, hence
    /// it fits within an [`Fr`] cell.
    ///
    /// [`Fr`]: halo2_proofs::halo2curves::bn256::Fr
    const PREPROCESSED_DIGEST_ROW: usize = 4 * LIMBS;

    /// The index within the instances to find the "initial" state in the state transition.
    const INITIAL_STATE_ROW: usize = Self::PREPROCESSED_DIGEST_ROW + 1;

    /// Construct a new instance of the [`RecursionCircuit`] given the SNARKs from the current and
    /// previous [`BatchCircuit`], and the recursion round.
    ///
    /// [`BatchCircuit`]: aggregator::BatchCircuit
    pub fn new(
        params: &ParamsKZG<Bn256>,
        app: Snark,
        previous: Snark,
        rng: impl Rng + Send,
        round: usize,
    ) -> Self {
        let svk = params.get_g()[0].into();
        let default_accumulator = KzgAccumulator::new(params.get_g()[1], params.get_g()[0]);

        let succinct_verify = |snark: &Snark| {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
            let proof =
                Plonk::<Pcs>::read_proof(&svk, &snark.protocol, &snark.instances, &mut transcript);
            Plonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof)
        };

        let accumulators = iter::empty()
            .chain(succinct_verify(&app))
            .chain(
                (round > 0)
                    .then(|| succinct_verify(&previous))
                    .unwrap_or_else(|| {
                        let num_accumulator = 1 + previous.protocol.accumulator_indices.len();
                        vec![default_accumulator.clone(); num_accumulator]
                    }),
            )
            .collect_vec();

        let (accumulator, as_proof) = {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
            let accumulator =
                As::create_proof(&Default::default(), &accumulators, &mut transcript, rng).unwrap();
            (accumulator, transcript.finalize())
        };

        let init_instances = if round > 0 {
            // pick from prev snark
            Vec::from(
                &previous.instances[0][Self::INITIAL_STATE_ROW
                    ..Self::INITIAL_STATE_ROW + ST::num_transition_instance()],
            )
        } else {
            // pick from app
            ST::state_prev_indices()
                .into_iter()
                .map(|i| app.instances[0][i])
                .collect::<Vec<_>>()
        };

        let state_instances = ST::state_indices()
            .into_iter()
            .map(|i| &app.instances[0][i])
            .chain(
                ST::additional_indices()
                    .into_iter()
                    .map(|i| &app.instances[0][i]),
            );

        let preprocessed_digest = {
            let inputs = previous
                .protocol
                .preprocessed
                .iter()
                .flat_map(|preprocessed| [preprocessed.x, preprocessed.y])
                .map(fe_to_fe)
                .chain(previous.protocol.transcript_initial_state)
                .collect_vec();
            let mut hasher = hash::Poseidon::from_spec(&NativeLoader, POSEIDON_SPEC.clone());
            hasher.update(&inputs);
            hasher.squeeze()
        };

        let instances = [
            accumulator.lhs.x,
            accumulator.lhs.y,
            accumulator.rhs.x,
            accumulator.rhs.y,
        ]
        .into_iter()
        .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .chain(iter::once(preprocessed_digest))
        .chain(init_instances)
        .chain(state_instances.copied())
        .chain(iter::once(Fr::from(round as u64)))
        .collect();

        log::debug!("recursive instance: {:#?}", instances);

        Self {
            svk,
            default_accumulator,
            app: app.into(),
            previous: previous.into(),
            round,
            instances,
            as_proof: Value::known(as_proof),
            _marker: Default::default(),
        }
    }

    fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }

    fn load_default_accumulator<'a>(
        &self,
        loader: &Rc<Halo2Loader<'a>>,
    ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
        let [lhs, rhs] =
            [self.default_accumulator.lhs, self.default_accumulator.rhs].map(|default| {
                let assigned = loader
                    .ecc_chip()
                    .assign_constant(&mut loader.ctx_mut(), default)
                    .unwrap();
                loader.ec_point_from_assigned(assigned)
            });
        Ok(KzgAccumulator::new(lhs, rhs))
    }

    /// Returns the number of instance cells in the Recursion Circuit, help to refine the CircuitExt trait
    pub fn num_instance_fixed() -> usize {
        // [
        //     ..lhs (accumulator LHS),
        //     ..rhs (accumulator RHS),
        //     preprocessed_digest,
        //     initial_state,
        //     state,
        //     round
        // ]
        4 * LIMBS + 2 * ST::num_transition_instance() + ST::num_additional_instance() + 2
    }
}

impl<ST: StateTransition> Circuit<Fr> for RecursionCircuit<ST> {
    type Config = config::RecursionConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            default_accumulator: self.default_accumulator.clone(),
            app: self.app.without_witnesses(),
            previous: self.previous.without_witnesses(),
            round: self.round,
            instances: self.instances.clone(),
            as_proof: Value::unknown(),
            _marker: Default::default(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let path = std::env::var("BUNDLE_CONFIG")
            .unwrap_or_else(|_| "configs/bundle_circuit.config".to_owned());
        let params: RecursionCircuitConfigParams = serde_json::from_reader(
            File::open(path.as_str()).unwrap_or_else(|err| panic!("{err:?}")),
        )
        .unwrap();

        Self::Config::configure(meta, params)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        config.range().load_lookup_table(&mut layouter)?;
        let max_rows = config.range().gate.max_rows;
        let main_gate = config.gate();

        let mut first_pass = halo2_base::SKIP_FIRST_PASS; // assume using simple floor planner
        let assigned_instances = layouter.assign_region(
            || "recursion circuit",
            |region| -> Result<Vec<Cell>, Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.base_field_config.range.gate.constants.clone(),
                    },
                );

                // The index of the "initial state", i.e. the state last finalised on L1.
                let index_init_state = Self::INITIAL_STATE_ROW;
                // The index of the "state", i.e. the state achieved post the current batch.
                let index_state = index_init_state + ST::num_transition_instance();
                // The index where the "additional" fields required to define the state are
                // present.
                let index_additional_state = index_state + ST::num_transition_instance();
                // The index to find the "round" of recursion in the current instance of the
                // Recursion Circuit.
                let index_round = index_additional_state + ST::num_additional_instance();

                log::debug!(
                    "indices within instances: init {} |cur {} | add {} | round {}",
                    index_init_state,
                    index_state,
                    index_additional_state,
                    index_round,
                );

                // Get the field elements representing the "preprocessed digest" and "recursion round".
                let [preprocessed_digest, round] = [
                    self.instances[Self::PREPROCESSED_DIGEST_ROW],
                    self.instances[index_round],
                ]
                .map(|instance| {
                    main_gate
                        .assign_integer(&mut ctx, Value::known(instance))
                        .unwrap()
                });

                // Get the field elements representing the "initial state"
                let initial_state = self.instances[index_init_state..index_state]
                    .iter()
                    .map(|&instance| {
                        main_gate
                            .assign_integer(&mut ctx, Value::known(instance))
                            .unwrap()
                    })
                    .collect::<Vec<_>>();

                // Get the field elements representing the "state" post batch. This includes the
                // additional state fields as well.
                let state = self.instances[index_state..index_round]
                    .iter()
                    .map(|&instance| {
                        main_gate
                            .assign_integer(&mut ctx, Value::known(instance))
                            .unwrap()
                    })
                    .collect::<Vec<_>>();

                // Whether or not we are in the first round of recursion.
                let first_round = main_gate.is_zero(&mut ctx, &round);
                let not_first_round = main_gate.not(&mut ctx, Existing(first_round));

                let loader = Halo2Loader::new(config.ecc_chip(), ctx);
                let (mut app_instances, app_accumulators) =
                    dynamic_verify::<Pcs>(&self.svk, &loader, &self.app, None);
                let (mut previous_instances, previous_accumulators) = dynamic_verify::<Pcs>(
                    &self.svk,
                    &loader,
                    &self.previous,
                    Some(preprocessed_digest),
                );

                // Choose between the default accumulator or the previous accumulator depending on
                // whether or not we are in the first round of recursion.
                let default_accumulator = self.load_default_accumulator(&loader)?;
                let previous_accumulators = previous_accumulators
                    .iter()
                    .map(|previous_accumulator| {
                        select_accumulator(
                            &loader,
                            &first_round,
                            &default_accumulator,
                            previous_accumulator,
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                // Accumulate the accumulators over the previous accumulators, to compute the
                // accumulator values for this instance of the Recursion Circuit.
                let KzgAccumulator { lhs, rhs } = accumulate(
                    &loader,
                    [app_accumulators, previous_accumulators].concat(),
                    self.as_proof(),
                );

                let lhs = lhs.into_assigned();
                let rhs = rhs.into_assigned();
                let app_instances = app_instances.pop().unwrap();
                let previous_instances = previous_instances.pop().unwrap();

                let mut ctx = loader.ctx_mut();

                //////////////////////////////////////////////////////////////////////////////////
                /////////////////////////////// CONSTRAINTS //////////////////////////////////////
                //////////////////////////////////////////////////////////////////////////////////

                // Propagate the "initial state"
                let initial_state_propagate = initial_state
                    .iter()
                    .zip_eq(previous_instances[index_init_state..index_state].iter())
                    .zip_eq(
                        ST::state_prev_indices()
                            .into_iter()
                            .map(|i| &app_instances[i]),
                    )
                    .flat_map(|((&st, &previous_st), &app_inst)| {
                        [
                            // Verify initial_state is same as the first application snark in the
                            // first round of recursion.
                            (
                                main_gate.mul(&mut ctx, Existing(st), Existing(first_round)),
                                main_gate.mul(&mut ctx, Existing(app_inst), Existing(first_round)),
                            ),
                            // Propagate initial_state for subsequent rounds of recursion.
                            (
                                main_gate.mul(&mut ctx, Existing(st), Existing(not_first_round)),
                                previous_st,
                            ),
                        ]
                    })
                    .collect::<Vec<_>>();

                // Verify that the current "state" is the same as the state defined in the
                // application SNARK.
                let verify_app_state = state
                    .iter()
                    .zip_eq(
                        ST::state_indices()
                            .into_iter()
                            .map(|i| &app_instances[i])
                            .chain(
                                ST::additional_indices()
                                    .into_iter()
                                    .map(|i| &app_instances[i]),
                            ),
                    )
                    .map(|(&st, &app_inst)| (st, app_inst))
                    .collect::<Vec<_>>();

                // Verify that the "previous state" (additional state not included) is the same
                // as the previous state defined in the current application SNARK. This check is
                // meaningful only in subsequent recursion rounds after the first round.
                let verify_app_init_state = previous_instances[index_state..index_additional_state]
                    .iter()
                    .zip_eq(
                        ST::state_prev_indices()
                            .into_iter()
                            .map(|i| &app_instances[i]),
                    )
                    .map(|(&st, &app_inst)| {
                        (
                            main_gate.mul(&mut ctx, Existing(app_inst), Existing(not_first_round)),
                            st,
                        )
                    })
                    .collect::<Vec<_>>();

                // Finally apply the equality constraints between the (LHS, RHS) values constructed
                // above.
                for (lhs, rhs) in [
                    // Propagate the preprocessed digest.
                    (
                        main_gate.mul(
                            &mut ctx,
                            Existing(preprocessed_digest),
                            Existing(not_first_round),
                        ),
                        previous_instances[Self::PREPROCESSED_DIGEST_ROW],
                    ),
                    // Verify that "round" increments by 1 when not the first round of recursion.
                    (
                        round,
                        main_gate.add(
                            &mut ctx,
                            Existing(not_first_round),
                            Existing(previous_instances[index_round]),
                        ),
                    ),
                ]
                .into_iter()
                .chain(initial_state_propagate)
                .chain(verify_app_state)
                .chain(verify_app_init_state)
                {
                    ctx.region.constrain_equal(lhs.cell(), rhs.cell())?;
                }

                // Mark the end of this phase.
                config.base_field_config.finalize(&mut ctx);

                #[cfg(feature = "display")]
                dbg!(ctx.total_advice);
                #[cfg(feature = "display")]
                println!("Advice columns used: {}", ctx.advice_alloc[0][0].0 + 1);

                // Return the computed instance cells for this Recursion Circuit.
                Ok([lhs.x(), lhs.y(), rhs.x(), rhs.y()]
                    .into_iter()
                    .flat_map(|coordinate| coordinate.limbs())
                    .chain(iter::once(&preprocessed_digest))
                    .chain(initial_state.iter())
                    .chain(state.iter())
                    .chain(iter::once(&round))
                    .map(|assigned| assigned.cell())
                    .collect())
            },
        )?;

        assert_eq!(assigned_instances.len(), self.num_instance()[0]);

        // Ensure that the computed instances are in fact the instances for this circuit.
        for (row, limb) in assigned_instances.into_iter().enumerate() {
            layouter.constrain_instance(limb, config.instance, row)?;
        }

        Ok(())
    }
}

impl<ST: StateTransition> CircuitExt<Fr> for RecursionCircuit<ST> {
    fn num_instance(&self) -> Vec<usize> {
        vec![Self::num_instance_fixed()]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        config.base_field_config.range.gate.basic_gates[0]
            .iter()
            .map(|gate| gate.q_enable)
            .collect()
    }
}
