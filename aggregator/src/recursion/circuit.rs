#![allow(clippy::type_complexity)]

use super::*;
use snark_verifier::{
    loader::halo2::{
        halo2_ecc::halo2_base as sv_halo2_base,
        EccInstructions, IntegerInstructions,
    },
    pcs::{
        kzg::{Gwc19, Kzg, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey, LimbsEncoding},
        PolynomialCommitmentScheme, AccumulationScheme, AccumulationSchemeProver,
    },
    util::{
        arithmetic::{fe_to_fe, fe_from_limbs, fe_to_limbs},
        hash,
    },
};
use sv_halo2_base::{
    halo2_proofs,
    gates::GateInstructions, AssignedValue, Context, ContextParams, QuantumCell::Existing,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        Rotation, VerificationStrategy,
    },
};
use snark_verifier_sdk::{
    SnarkWitness,
    types::{Plonk, Halo2Loader, BaseFieldEccChip},
    gen_pk, gen_snark_shplonk, verify_snark_shplonk
};

mod application {
    use super::*;

    #[derive(Clone, Default)]
    pub struct Square(Fr);

    impl Circuit<Fr> for Square {
        type Config = Selector;
        type FloorPlanner = SimpleFloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let q = meta.selector();
            let i = meta.instance_column();
            meta.create_gate("square", |meta| {
                let q = meta.query_selector(q);
                let [i, i_w] = [0, 1].map(|rotation| meta.query_instance(i, Rotation(rotation)));
                Some(q * (i.clone() * i - i_w))
            });
            q
        }

        fn synthesize(
            &self,
            q: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            layouter.assign_region(|| "", |mut region| q.enable(&mut region, 0))
        }
    }

    impl CircuitExt<Fr> for Square {
        fn num_instance(&self) -> Vec<usize> {
            vec![2]
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![vec![self.0, self.0.square()]]
        }
    }

    impl StateTransition for Square {
        type Input = [Fr;1];

        fn new(state: Self::Input) -> Self {
            Self(state[0])
        }

        fn state_transition(&self) -> Self::Input {
            [self.0.square()]
        }
    }
}


use std::{rc::Rc, fs::File, iter};
type Svk = KzgSuccinctVerifyingKey<G1Affine>;
type Pcs = Kzg<Bn256, Gwc19>;

type As = KzgAs<Pcs>;

// use halo2_base::{
//     gates::GateInstructions, AssignedValue, Context, ContextParams, QuantumCell::Existing,
// };
// use halo2_ecc::ecc::EccChip;
// use halo2_proofs::plonk::{Column, Instance};
// use snark_verifier::loader::halo2::{EccInstructions, IntegerInstructions};


fn select_accumulator<'a>(
    loader: &Rc<Halo2Loader<'a>>,
    condition: &AssignedValue<Fr>,
    lhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
    rhs: &KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
    let [lhs, rhs]: [_; 2] = [lhs.lhs.assigned(), lhs.rhs.assigned()]
        .iter()
        .zip([rhs.lhs.assigned(), rhs.rhs.assigned()].iter())
        .map(|(lhs, rhs)| loader.ecc_chip().select(&mut loader.ctx_mut(), lhs, rhs, condition))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    Ok(KzgAccumulator::new(
        loader.ec_point_from_assigned(lhs),
        loader.ec_point_from_assigned(rhs),
    ))
}

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
pub struct RecursionCircuit<const ST: usize> {
    svk: Svk,
    default_accumulator: KzgAccumulator<G1Affine, NativeLoader>,
    app: SnarkWitness,
    previous: SnarkWitness,
    round: usize,
    instances: Vec<Fr>,
    as_proof: Value<Vec<u8>>,
}

impl<const ST: usize> RecursionCircuit<ST> {
    const PREPROCESSED_DIGEST_ROW: usize = 4 * LIMBS;
    const INITIAL_STATE_ROW: usize = Self::PREPROCESSED_DIGEST_ROW + 1;
    const STATE_ROW: usize = Self::INITIAL_STATE_ROW + ST;
    const ROUND_ROW: usize = Self::STATE_ROW + ST;

    pub fn new(
        params: &ParamsKZG<Bn256>,
        app: Snark,
        previous: Snark,
        rng: impl Rng + Send,
        initial_state: [Fr; ST],
        state: [Fr; ST],
        round: usize,
    ) -> Self {
        let svk = params.get_g()[0].into();
        let default_accumulator = KzgAccumulator::new(params.get_g()[1], params.get_g()[0]);

        let succinct_verify = |snark: &Snark| {
            let mut transcript =
                PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
            let proof =
                Plonk::<Pcs>::read_proof(&svk, &snark.protocol, &snark.instances, &mut transcript);
            Plonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof)
        };

        let accumulators = iter::empty()
            .chain(succinct_verify(&app))
            .chain((round > 0).then(|| succinct_verify(&previous)).unwrap_or_else(|| {
                let num_accumulator = 1 + previous.protocol.accumulator_indices.len();
                vec![default_accumulator.clone(); num_accumulator]
            }))
            .collect_vec();

        let (accumulator, as_proof) = {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
            let accumulator =
                As::create_proof(&Default::default(), &accumulators, &mut transcript, rng)
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
            let mut hasher = hash::Poseidon::from_spec(
                &NativeLoader, POSEIDON_SPEC.clone());
            hasher.update(&inputs);
            hasher.squeeze()
        };
        let instances =
            [accumulator.lhs.x, accumulator.lhs.y, accumulator.rhs.x, accumulator.rhs.y]
                .into_iter()
                .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
                .chain(iter::once(preprocessed_digest))
                .chain(initial_state)
                .chain(state)
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
        }
    }

    // fn initial_snark(params: &ParamsKZG<Bn256>, vk: Option<&VerifyingKey<G1Affine>>) -> Snark {
    //     let mut snark = gen_dummy_snark::<RecursionCircuit>(params, vk);
    //     let g = params.get_g();
    //     snark.instances = vec![[g[1].x, g[1].y, g[0].x, g[0].y]
    //         .into_iter()
    //         .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
    //         .chain([Fr::ZERO; 4])
    //         .collect_vec()];
    //     snark
    // }

    fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }

    fn load_default_accumulator<'a>(
        &self,
        loader: &Rc<Halo2Loader<'a>>,
    ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>, Error> {
        let [lhs, rhs] =
            [self.default_accumulator.lhs, self.default_accumulator.rhs].map(|default| {
                let assigned =
                    loader.ecc_chip().assign_constant(&mut loader.ctx_mut(), default).unwrap();
                loader.ec_point_from_assigned(assigned)
            });
        Ok(KzgAccumulator::new(lhs, rhs))
    }

    /// get the number of instance, help to refine the CircuitExt trait
    pub fn num_instance_fixed() -> usize {
        // [..lhs, ..rhs, preprocessed_digest, initial_state, state, round]
        4 * LIMBS + ST*2 + 2
    }

}

impl<const ST: usize> Circuit<Fr> for RecursionCircuit<ST> {
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
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let path = std::env::var("VERIFY_CONFIG")
            .unwrap_or_else(|_| "configs/verify_circuit.config".to_owned());
        let params: BatchCircuitConfigParamsParams = serde_json::from_reader(
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
        let mut assigned_instances = Vec::new();
        layouter.assign_region(
            || "",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows,
                        num_context_ids: 1,
                        fixed_columns: config.base_field_config.range.gate.constants.clone(),
                    },
                );

                let [preprocessed_digest, initial_state, state, round] = [
                    self.instances[Self::PREPROCESSED_DIGEST_ROW],
                    self.instances[Self::INITIAL_STATE_ROW],
                    self.instances[Self::STATE_ROW],
                    self.instances[Self::ROUND_ROW],
                ]
                .map(|instance| {
                    main_gate.assign_integer(&mut ctx, Value::known(instance)).unwrap()
                });
                let first_round = main_gate.is_zero(&mut ctx, &round);
                let not_first_round = main_gate.not(&mut ctx, Existing(first_round));

                let loader = Halo2Loader::new(config.ecc_chip(), ctx);
                let (mut app_instances, app_accumulators) =
                    dynamic_verify::<Pcs>(&self.svk, &loader, &self.app, None);
                let (mut previous_instances, previous_accumulators) = 
                dynamic_verify::<Pcs>(
                    &self.svk,
                    &loader,
                    &self.previous,
                    Some(preprocessed_digest.clone()),
                );

                let default_accmulator = self.load_default_accumulator(&loader)?;
                let previous_accumulators = previous_accumulators
                    .iter()
                    .map(|previous_accumulator| {
                        select_accumulator(
                            &loader,
                            &first_round,
                            &default_accmulator,
                            previous_accumulator,
                        )
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

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
                for (lhs, rhs) in [
                    // Propagate preprocessed_digest
                    (
                        &main_gate.mul(
                            &mut ctx,
                            Existing(preprocessed_digest),
                            Existing(not_first_round),
                        ),
                        &previous_instances[Self::PREPROCESSED_DIGEST_ROW],
                    ),
                    // Propagate initial_state
                    (
                        &main_gate.mul(
                            &mut ctx,
                            Existing(initial_state),
                            Existing(not_first_round),
                        ),
                        &previous_instances[Self::INITIAL_STATE_ROW],
                    ),
                    // Verify initial_state is same as the first application snark
                    (
                        &main_gate.mul(
                            &mut ctx,
                            Existing(initial_state),
                            Existing(first_round),
                        ),
                        &main_gate.mul(
                            &mut ctx,
                            Existing(app_instances[0]),
                            Existing(first_round),
                        ),
                    ),
                    // Verify current state is same as the current application snark
                    (&state, &app_instances[1]),
                    // Verify previous state is same as the current application snark
                    (
                        &main_gate.mul(
                            &mut ctx,
                            Existing(app_instances[0]),
                            Existing(not_first_round),
                        ),
                        &previous_instances[Self::STATE_ROW],
                    ),
                    // Verify round is increased by 1 when not at first round
                    (
                        &round,
                        &main_gate.add(
                            &mut ctx,
                            Existing(not_first_round),
                            Existing(previous_instances[Self::ROUND_ROW]),
                        ),
                    ),
                ] {
                    ctx.region.constrain_equal(lhs.cell(), rhs.cell())?;
                }

                // IMPORTANT:
                config.base_field_config.finalize(&mut ctx);
                #[cfg(feature = "display")]
                dbg!(ctx.total_advice);
                #[cfg(feature = "display")]
                println!("Advice columns used: {}", ctx.advice_alloc[0][0].0 + 1);

                assigned_instances.extend(
                    [lhs.x(), lhs.y(), rhs.x(), rhs.y()]
                        .into_iter()
                        .flat_map(|coordinate| coordinate.limbs())
                        .chain([preprocessed_digest, initial_state, state, round].iter())
                        .map(|assigned| assigned.cell()),
                );
                Ok(())
            },
        )?;

        assert_eq!(assigned_instances.len(), 4 * LIMBS + 4);
        for (row, limb) in assigned_instances.into_iter().enumerate() {
            layouter.constrain_instance(limb, config.instance, row)?;
        }

        Ok(())
    }
}

impl<const ST: usize> CircuitExt<Fr> for RecursionCircuit<ST> {
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

pub fn gen_recursion_pk<ConcreteCircuit: CircuitExt<Fr>>(
    recursion_params: &ParamsKZG<Bn256>,
    app_params: &ParamsKZG<Bn256>,
    app_vk: &VerifyingKey<G1Affine>,
) -> ProvingKey<G1Affine> {
    let recursion = RecursionCircuit::new(
        recursion_params,
        gen_dummy_snark::<ConcreteCircuit>(app_params, Some(app_vk)),
        RecursionCircuit::initial_snark(recursion_params, None),
        Fr::ZERO,
        Fr::ZERO,
        0,
    );
    gen_pk(recursion_params, &recursion)
}

pub fn gen_recursion_snark<ConcreteCircuit: CircuitExt<Fr> + StateTransition>(
    app_params: &ParamsKZG<Bn256>,
    recursion_params: &ParamsKZG<Bn256>,
    app_pk: &ProvingKey<G1Affine>,
    recursion_pk: &ProvingKey<G1Affine>,
    initial_state: Fr,
    inputs: Vec<ConcreteCircuit::Input>,
) -> (Fr, Snark) {
    let mut state = initial_state;
    let mut app = ConcreteCircuit::new(state);
    let mut previous =
        RecursionCircuit::initial_snark(recursion_params, Some(recursion_pk.get_vk()));
    for (round, input) in inputs.into_iter().enumerate() {
        state = app.state_transition(input);
        println!("Generate app snark");
        let app_snark = gen_snark(app_params, app_pk, app);
        let recursion = RecursionCircuit::new(
            recursion_params,
            app_snark,
            previous,
            initial_state,
            state,
            round,
        );
        println!("Generate recursion snark");
        previous = gen_snark(recursion_params, recursion_pk, recursion);
        app = ConcreteCircuit::new(state);
    }
    (state, previous)
}


fn test() {
    use std::fs;
    use sv_halo2_base::utils::fs::gen_srs;
    
    let app_params = gen_srs(3);
    let recursion_config: BatchCircuitConfigParamsParams =
        serde_json::from_reader(fs::File::open("configs/verify_circuit.config").unwrap()).unwrap();
    let k = recursion_config.degree;
    let recursion_params = gen_srs(k);

//     let app_pk = gen_pk(&app_params, &application::Square::default());

//     let pk_time = start_timer!(|| "Generate recursion pk");
//     let recursion_pk = gen_recursion_pk::<application::Square>(
//         &recursion_params,
//         &app_params,
//         app_pk.get_vk(),
//     );
//     end_timer!(pk_time);

//     let num_round = 1;
//     let pf_time = start_timer!(|| "Generate full recursive snark");
//     let (final_state, snark) = gen_recursion_snark::<application::Square>(
//         &app_params,
//         &recursion_params,
//         &app_pk,
//         &recursion_pk,
//         Fr::from(2u64),
//         vec![(); num_round],
//     );
//     end_timer!(pf_time);
//     assert_eq!(final_state, Fr::from(2u64).pow(&[1 << num_round, 0, 0, 0]));

//     let accept = {
//         let svk = recursion_params.get_g()[0].into();
//         let dk = (recursion_params.g2(), recursion_params.s_g2()).into();
//         let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
//         let proof = Plonk::read_proof(&svk, &snark.protocol, &snark.instances, &mut transcript);
//         Plonk::verify(&svk, &dk, &snark.protocol, &snark.instances, &proof)
//     };
//     assert!(accept)
// }
