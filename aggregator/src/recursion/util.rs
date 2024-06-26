
use super::*;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, CircuitExt, Snark};
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
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
// required by kzg specific implements
use snark_verifier::{
    util::{
        arithmetic::{fe_to_fe, fe_from_limbs, fe_to_limbs},
        transcript::{Transcript, TranscriptWrite, TranscriptRead},
    },
    pcs::{kzg::{Gwc19, Kzg}},
};

mod dummy_circuit {
    use super::*;
    use std::marker::PhantomData;

    pub struct CsProxy<F, C>(PhantomData<(F, C)>);

    impl<F, C> Default for CsProxy<F, C>{
        fn default() -> Self {
            Self(Default::default())
        }
    }

    impl<F: Field, C: CircuitExt<F>> Circuit<F> for CsProxy<F, C>
    {
        type Config = C::Config;
        type FloorPlanner = C::FloorPlanner;
        #[cfg(feature = "circuit-params")]
        type Params = ();

        fn without_witnesses(&self) -> Self {
            CsProxy(PhantomData)
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            C::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            // when `C` has simple selectors, we tell `CsProxy` not to over-optimize the selectors (e.g., compressing them  all into one) by turning all selectors on in the first row
            // currently this only works if all simple selector columns are used in the actual circuit and there are overlaps amongst all enabled selectors (i.e., the actual circuit will not optimize constraint system further)
            layouter.assign_region(
                || "",
                |mut region| {
                    for q in C::selectors(&config).iter() {
                        q.enable(&mut region, 0)?;
                    }
                    Ok(())
                },
            )?;
            Ok(())
        }
    }

}

// gen a "dummy" snark in case we need to "skip" the verify part 
// inside the recursive circuit: cost would be high if we apply conditional
// selection above the verify circuits (it is in fact a ecc chip, and
// selection increase the maxium degree by 1).
// Instead, a "dummy" snark ensure the ecc chip is valid with providen
// witness and we just skip the output accumulator later
// it can "mock" any circuit (with vk being provided in argument)
// specified by ConcreteCircuit
fn gen_dummy_snark<ConcreteCircuit, RNG>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: &[usize],
    rng: &mut impl FnMut() -> RNG,
) -> Snark 
where
    ConcreteCircuit: CircuitExt<Fr>,
    RNG: Rng + Send,
{

    use std::iter;
    use snark_verifier::cost::CostEstimation;
    type Pcs = Kzg<Bn256, Gwc19>;

    let protocol = compile(
        params,
        &vk,
        Config::kzg()
            .with_num_instance(Vec::from(num_instance))
            .with_accumulator_indices(ConcreteCircuit::accumulator_indices()),
    );
    let instances = num_instance
        .into_iter()
        .map(|&n| iter::repeat_with(|| Fr::random(rng())).take(n).collect())
        .collect();
    let proof = {
        let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
        for _ in 0..protocol
            .num_witness
            .iter()
            .chain(Some(&protocol.quotient.num_chunk()))
            .sum::<usize>()
        {
            transcript.write_ec_point(G1Affine::random(rng())).unwrap();
        }
        for _ in 0..protocol.evaluations.len() {
            transcript.write_scalar(Fr::random(rng())).unwrap();
        }
        let queries = PlonkProof::<G1Affine, NativeLoader, Pcs>::empty_queries(&protocol);
        for _ in 0..Pcs::estimate_cost(&queries).num_commitment {
            transcript.write_ec_point(G1Affine::random(rng())).unwrap();
        }
        transcript.finalize()
    };

    Snark::new(protocol, instances, proof)
}


// pub fn initial_recursion_snark(
//     params: &ParamsKZG<Bn256>, 
//     vk: Option<&VerifyingKey<G1Affine>>) 
//     -> Snark {
//     let mut snark = gen_dummy_snark::<RecursionCircuit>(params, vk);
//     let g = params.get_g();
//     snark.instances = vec![[g[1].x, g[1].y, g[0].x, g[0].y]
//         .into_iter()
//         .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
//         .chain([Fr::ZERO; 4])
//         .collect_vec()];
//     snark
// }

/// gen the pk for recursion
pub fn gen_recursion_pk<AppCircuit, RNG, const ST: usize>(
    recursion_params: &ParamsKZG<Bn256>,
    app_params: &ParamsKZG<Bn256>,
    app_vk: &VerifyingKey<G1Affine>,
    mut rng: impl FnMut() -> RNG,
) -> ProvingKey<G1Affine> 
where
    AppCircuit: CircuitExt<Fr>,
    RNG: Rng + Send
{

    // to generate the pk we need to construct a recursion circuit,
    // which require another snark being build from itself (and so, need
    // a pk), to break this cycling we use a "dummy" circuit for
    // generating the snark
    let dummy_vk = keygen_vk(
        recursion_params, 
        &dummy_circuit::CsProxy::<Fr, RecursionCircuit<ST>>::default()
    ).unwrap();
    let mut recursive_snark = gen_dummy_snark::<RecursionCircuit<ST>, _>(
        recursion_params, &dummy_vk, &[ST], &mut rng,
    );
    let g = recursion_params.get_g();
    recursive_snark.instances = vec![[g[1].x, g[1].y, g[0].x, g[0].y]
        .into_iter()
        .flat_map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .chain([Fr::ZERO; 4])
        .collect_vec()];

    // we need to construct a "snark of a recursion circuit"
    // before we 
    let recursion = RecursionCircuit::<ST>::new(
        recursion_params,
        gen_dummy_snark::<AppCircuit, _>(
            app_params, app_vk, &[ST], &mut rng,
        ),
        recursive_snark,
        rng(),
        [Fr::ZERO; ST],
        [Fr::ZERO; ST],
        0,
    );
    gen_pk(recursion_params, &recursion, None)
}

// pub fn gen_recursion_snark<ConcreteCircuit: CircuitExt<Fr> + StateTransition>(
//     app_params: &ParamsKZG<Bn256>,
//     recursion_params: &ParamsKZG<Bn256>,
//     app_pk: &ProvingKey<G1Affine>,
//     recursion_pk: &ProvingKey<G1Affine>,
//     initial_state: Fr,
//     inputs: Vec<ConcreteCircuit::Input>,
// ) -> (Fr, Snark) {
//     let mut state = initial_state;
//     let mut app = ConcreteCircuit::new(state);
//     let mut previous =
//         RecursionCircuit::initial_snark(recursion_params, Some(recursion_pk.get_vk()));
//     for (round, input) in inputs.into_iter().enumerate() {
//         state = app.state_transition(input);
//         println!("Generate app snark");
//         let app_snark = gen_snark_shplonk(app_params, app_pk, app, None);
//         let recursion = RecursionCircuit::new(
//             recursion_params,
//             app_snark,
//             previous,
//             initial_state,
//             state,
//             round,
//         );
//         println!("Generate recursion snark");
//         previous = gen_snark_shplonk(recursion_params, recursion_pk, recursion, None);
//         app = ConcreteCircuit::new(state);
//     }
//     (state, previous)
// }
