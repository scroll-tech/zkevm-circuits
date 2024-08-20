#![allow(clippy::type_complexity)]
use super::*;
use crate::{
    common::{poseidon, succinct_verify},
    types::{As, BaseFieldEccChip, PlonkSuccinctVerifier, Svk},
};
use aggregator::ConfigParams as RecursionCircuitConfigParams;
use ce_snark_verifier::{
    halo2_base::{
        gates::{
            circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, BaseConfig},
            GateInstructions, RangeInstructions,
        },
        AssignedValue, Context,
        QuantumCell::Existing,
    },
    loader::halo2::{
        halo2_ecc::{bn254::FpChip, ecc::EcPoint},
        EccInstructions, IntegerInstructions,
    },
    pcs::{kzg::KzgAccumulator, AccumulationScheme, AccumulationSchemeProver},
    util::{
        arithmetic::{fe_to_fe, fe_to_limbs},
        hash,
    },
    verifier::SnarkVerifier,
};
use ce_snark_verifier_sdk::{
    halo2::{aggregation::Halo2Loader, PoseidonTranscript, POSEIDON_SPEC},
    Snark, BITS, LIMBS,
};
use halo2_proofs::{
    circuit::{Cell, Layouter, SimpleFloorPlanner, Value},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use rand::rngs::OsRng;
use std::{fs::File, iter, marker::PhantomData, mem, rc::Rc};

const SECURE_MDS: usize = 0;

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
            loader.ecc_chip().select(
                loader.ctx_mut().main(),
                EcPoint::clone(lhs),
                EcPoint::clone(rhs),
                *condition,
            )
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
    as_proof: &[u8],
) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>> {
    let mut transcript =
        PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(loader, as_proof);
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
    app: Snark,
    /// The SNARK witness from the previous RecursionCircuit, i.e. RecursionCircuit up to the
    /// (k-1)-th BatchCircuit.
    previous: Snark,
    /// The recursion round, starting at round=0 and incrementing at every subsequent recursion.
    round: usize,
    /// The public inputs to the RecursionCircuit itself.
    instances: Vec<Fr>,
    /// The accumulation of the SNARK proofs recursed over thus far.
    as_proof: Vec<u8>,

    inner: BaseCircuitBuilder<Fr>,

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

    const STATE_ROW: usize = 4 * LIMBS + 2;
    const ROUND_ROW: usize = 4 * LIMBS + 3;

    /// Construct a new instance of the [`RecursionCircuit`] given the SNARKs from the current and
    /// previous [`BatchCircuit`], and the recursion round.
    ///
    /// [`BatchCircuit`]: aggregator::BatchCircuit
    pub fn new(
        params: &ParamsKZG<Bn256>,
        app: Snark,
        previous: Snark,
        _rng: impl Rng + Send,
        round: usize,
    ) -> Self {
        let svk = params.get_g()[0].into();
        let default_accumulator = KzgAccumulator::new(params.get_g()[1], params.get_g()[0]);

        let succinct_verify = |snark: &Snark| {
            let mut transcript =
                PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(snark.proof.as_slice());
            let proof = PlonkSuccinctVerifier::read_proof(
                &svk,
                &snark.protocol,
                &snark.instances,
                &mut transcript,
            )
            .unwrap();
            PlonkSuccinctVerifier::verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap()
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
            let mut transcript =
                PoseidonTranscript::<NativeLoader, _>::new::<SECURE_MDS>(Vec::new());
            let accumulator =
                As::create_proof(&Default::default(), &accumulators, &mut transcript, OsRng)
                    .unwrap();
            (accumulator, transcript.finalize())
        };

        let preprocessed_digest = {
            let inputs = previous
                .protocol
                .preprocessed
                .iter()
                .flat_map(|preprocessed| [preprocessed.x, preprocessed.y])
                .map(fe_to_fe)
                .chain(previous.protocol.transcript_initial_state)
                .collect_vec();
            poseidon(&NativeLoader, &inputs)
        };

        // TODO: allow more than 1 element for state.
        let state = ST::state_indices()
            .into_iter()
            .map(|i| &app.instances[0][i])
            .chain(
                ST::additional_indices()
                    .into_iter()
                    .map(|i| &app.instances[0][i]),
            )
            .next()
            .unwrap();
        let initial_state = if round > 0 {
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
        }
        .first()
        .unwrap();

        let instances = [
            accumulator.lhs.x,
            accumulator.lhs.y,
            accumulator.rhs.x,
            accumulator.rhs.y,
        ]
        .into_iter()
        .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .chain([
            preprocessed_digest,
            *initial_state,
            *state,
            Fr::from(round as u64),
        ])
        .collect();

        let inner = BaseCircuitBuilder::new(false).use_params(config_params);
        let mut circuit = Self {
            svk,
            default_accumulator,
            app,
            previous,
            round,
            instances,
            as_proof,
            inner,
            _marker: Default::default(),
        };
        circuit.build();
        circuit
    }

    fn build(&mut self) {
        let range = self.inner.range_chip();
        let main_gate = range.gate();
        let pool = self.inner.pool(0);
        let [preprocessed_digest, initial_state, state, round] = [
            self.instances[Self::PREPROCESSED_DIGEST_ROW],
            self.instances[Self::INITIAL_STATE_ROW],
            self.instances[Self::STATE_ROW],
            self.instances[Self::ROUND_ROW],
        ]
        .map(|instance| main_gate.assign_integer(pool, instance));
        let first_round = main_gate.is_zero(pool.main(), round);
        let not_first_round = main_gate.not(pool.main(), first_round);

        let fp_chip = FpChip::<Fr>::new(&range, BITS, LIMBS);
        let ecc_chip = BaseFieldEccChip::new(&fp_chip);
        let loader = Halo2Loader::new(ecc_chip, mem::take(self.inner.pool(0)));
        let (mut app_instances, app_accumulators) =
            succinct_verify(&self.svk, &loader, &self.app, None);
        let (mut previous_instances, previous_accumulators) = succinct_verify(
            &self.svk,
            &loader,
            &self.previous,
            Some(preprocessed_digest),
        );

        let default_accmulator = self.load_default_accumulator(&loader).unwrap();
        let previous_accumulators = previous_accumulators
            .iter()
            .map(|previous_accumulator| {
                select_accumulator(
                    &loader,
                    &first_round,
                    &default_accmulator,
                    previous_accumulator,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let KzgAccumulator { lhs, rhs } = accumulate(
            &loader,
            [app_accumulators, previous_accumulators].concat(),
            self.as_proof(),
        );

        let lhs = lhs.into_assigned();
        let rhs = rhs.into_assigned();
        let app_instances = app_instances.pop().unwrap();
        let previous_instances = previous_instances.pop().unwrap();

        let mut pool = loader.take_ctx();
        let ctx = pool.main();
        for (lhs, rhs) in [
            // Propagate preprocessed_digest
            (
                &main_gate.mul(ctx, preprocessed_digest, not_first_round),
                &previous_instances[Self::PREPROCESSED_DIGEST_ROW],
            ),
            // Propagate initial_state
            (
                &main_gate.mul(ctx, initial_state, not_first_round),
                &previous_instances[Self::INITIAL_STATE_ROW],
            ),
            // Verify initial_state is same as the first application snark
            (
                &main_gate.mul(ctx, initial_state, first_round),
                &main_gate.mul(ctx, app_instances[0], first_round),
            ),
            // Verify current state is same as the current application snark
            (&state, &app_instances[1]),
            // Verify previous state is same as the current application snark
            (
                &main_gate.mul(ctx, app_instances[0], not_first_round),
                &previous_instances[Self::STATE_ROW],
            ),
            // Verify round is increased by 1 when not at first round
            (
                &round,
                &main_gate.add(ctx, not_first_round, previous_instances[Self::ROUND_ROW]),
            ),
        ] {
            ctx.constrain_equal(lhs, rhs);
        }
        *self.inner.pool(0) = pool;

        self.inner.assigned_instances[0].extend(
            [lhs.x(), lhs.y(), rhs.x(), rhs.y()]
                .into_iter()
                .flat_map(|coordinate| coordinate.limbs())
                .chain([preprocessed_digest, initial_state, state, round].iter())
                .copied(),
        );
    }

    fn as_proof(&self) -> &[u8] {
        &self.as_proof
    }

    fn load_default_accumulator<'a>(
        &self,
        loader: &Rc<Halo2Loader<'a>>,
    ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
        let [lhs, rhs] =
            [self.default_accumulator.lhs, self.default_accumulator.rhs].map(|default| {
                let assigned = loader
                    .ecc_chip()
                    .assign_constant(&mut loader.ctx_mut(), default);
                loader.ec_point_from_assigned(assigned)
            });
        Ok(KzgAccumulator::new(lhs, rhs))
    }

    /// Returns the number of instance cells in the Recursion Circuit, help to refine the CircuitExt
    /// trait
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
    type Config = BaseConfig<Fr>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = BaseCircuitParams;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let path = std::env::var("BUNDLE_CONFIG")
            .unwrap_or_else(|_| "configs/bundle_circuit.config".to_owned());
        let bundle_params: RecursionCircuitConfigParams = serde_json::from_reader(
            File::open(path.as_str()).unwrap_or_else(|err| panic!("{err:?}")),
        )
        .unwrap();

        let base_circuit_params = BaseCircuitParams {
            k: usize::try_from(bundle_params.degree).unwrap(),
            lookup_bits: Some(bundle_params.lookup_bits),
            num_lookup_advice_per_phase: bundle_params.num_lookup_advice,
            num_advice_per_phase: bundle_params.num_advice,
            num_fixed: bundle_params.num_fixed,
            num_instance_columns: 1,
        };
        Self::Config::configure(meta, base_circuit_params)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fr>) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
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
        config.gate().basic_gates[0]
            .iter()
            .map(|gate| gate.q_enable)
            .collect()
    }
}
