
use super::*;
use snark_verifier::{
    loader::halo2::EccInstructions,
    util::hash,
    pcs::{
        kzg::KzgAccumulator,
        MultiOpenScheme, PolynomialCommitmentScheme,
    },
};
use snark_verifier_sdk::{
    SnarkWitness,
    types::{Plonk, Halo2Loader, BaseFieldEccChip}
};
use std::rc::Rc;

// pub const LIMBS: usize = 3;
// pub const BITS: usize = 88;
// pub const T: usize = 5;
// pub const RATE: usize = 4;
// pub const R_F: usize = 8;
// pub const R_P: usize = 60;

// pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;
// pub type As = KzgAs<Pcs>;
// pub use snark_verifier_sdk::types::{Plonk, Halo2Loader, BaseFieldEccChip};
// pub type Poseidon<L> = hash::Poseidon<Fr, L, T, RATE>;
// // TODO: replace with POSEIDON_SPEC
// pub type PoseidonTranscript<L, S> =
//     halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;




// pub struct Snark {
//     pub protocol: Protocol<G1Affine>,
//     pub instances: Vec<Vec<Fr>>,
//     pub proof: Vec<u8>,
// }

// impl Snark {
//     pub fn new(protocol: Protocol<G1Affine>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> Self {
//         Self { protocol, instances, proof }
//     }
// }

// impl From<Snark> for SnarkWitness {
//     fn from(snark: Snark) -> Self {
//         Self {
//             protocol: snark.protocol,
//             instances: snark
//                 .instances
//                 .into_iter()
//                 .map(|instances| instances.into_iter().map(Value::known).collect_vec())
//                 .collect(),
//             proof: Value::known(snark.proof),
//         }
//     }
// }

// #[derive(Clone)]
// pub struct SnarkWitness {
//     pub protocol: Protocol<G1Affine>,
//     pub instances: Vec<Vec<Value<Fr>>>,
//     pub proof: Value<Vec<u8>>,
// }

// impl SnarkWitness {
//     pub fn without_witnesses(&self) -> Self {
//         SnarkWitness {
//             protocol: self.protocol.clone(),
//             instances: self
//                 .instances
//                 .iter()
//                 .map(|instances| vec![Value::unknown(); instances.len()])
//                 .collect(),
//             proof: Value::unknown(),
//         }
//     }

//     pub fn proof(&self) -> Value<&[u8]> {
//         self.proof.as_ref().map(Vec::as_slice)
//     }
// }

// pub fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
//     let vk = keygen_vk(params, circuit).unwrap();
//     keygen_pk(params, vk, circuit).unwrap()
// }

// pub fn gen_proof<C: Circuit<Fr>>(
//     params: &ParamsKZG<Bn256>,
//     pk: &ProvingKey<G1Affine>,
//     circuit: C,
//     rng: impl Rng + Send,
//     instances: Vec<Vec<Fr>>,
// ) -> Vec<u8> {
//     if params.k() > 3 {
//         let mock = start_timer!(|| "Mock prover");
//         MockProver::run(params.k(), &circuit, instances.clone())
//             .unwrap()
//             .assert_satisfied_par();
//         end_timer!(mock);
//     }

//     let instances = instances.iter().map(Vec::as_slice).collect_vec();
//     let proof = {
//         let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
//         create_proof::<_, ProverGWC<_>, _, _, _, _>(
//             params,
//             pk,
//             &[circuit],
//             &[instances.as_slice()],
//             rng,
//             &mut transcript,
//         )
//         .unwrap();
//         transcript.finalize()
//     };

//     let accept = {
//         let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(proof.as_slice());
//         VerificationStrategy::<_, VerifierGWC<_>>::finalize(
//             verify_proof::<_, VerifierGWC<_>, _, _, _>(
//                 params.verifier_params(),
//                 pk.get_vk(),
//                 AccumulatorStrategy::new(params.verifier_params()),
//                 &[instances.as_slice()],
//                 &mut transcript,
//             )
//             .unwrap(),
//         )
//     };
//     assert!(accept);

//     proof
// }

// pub fn gen_snark<ConcreteCircuit: CircuitExt<Fr>>(
//     params: &ParamsKZG<Bn256>,
//     pk: &ProvingKey<G1Affine>,
//     circuit: ConcreteCircuit,
//     rng: impl Rng + Send,
// ) -> Snark {
//     let protocol = compile(
//         params,
//         pk.get_vk(),
//         Config::kzg()
//             .with_num_instance(ConcreteCircuit::num_instance())
//             .with_accumulator_indices(ConcreteCircuit::accumulator_indices()),
//     );

//     let instances = circuit.instances();
//     let proof = gen_proof(params, pk, circuit, rng, instances.clone());

//     Snark::new(protocol, instances, proof)
// }

// pub fn gen_dummy_snark<ConcreteCircuit: CircuitExt<Fr>>(
//     params: &ParamsKZG<Bn256>,
//     vk: Option<&VerifyingKey<G1Affine>>,
//     rng: impl Rng + Send,
// ) -> Snark {
//     use std::{iter, marker::PhantomData};
//     struct CsProxy<F, C>(PhantomData<(F, C)>);

//     impl<F: Field, C: CircuitExt<F>> Circuit<F> for CsProxy<F, C> {
//         type Config = C::Config;
//         type FloorPlanner = C::FloorPlanner;
//         #[cfg(feature = "circuit-params")]
//         type Params = ();

//         fn without_witnesses(&self) -> Self {
//             CsProxy(PhantomData)
//         }

//         fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
//             C::configure(meta)
//         }

//         fn synthesize(
//             &self,
//             config: Self::Config,
//             mut layouter: impl Layouter<F>,
//         ) -> Result<(), Error> {
//             // when `C` has simple selectors, we tell `CsProxy` not to over-optimize the selectors (e.g., compressing them  all into one) by turning all selectors on in the first row
//             // currently this only works if all simple selector columns are used in the actual circuit and there are overlaps amongst all enabled selectors (i.e., the actual circuit will not optimize constraint system further)
//             layouter.assign_region(
//                 || "",
//                 |mut region| {
//                     for q in C::selectors(&config).iter() {
//                         q.enable(&mut region, 0)?;
//                     }
//                     Ok(())
//                 },
//             )?;
//             Ok(())
//         }
//     }

//     let dummy_vk = vk
//         .is_none()
//         .then(|| keygen_vk(params, &CsProxy::<Fr, ConcreteCircuit>(PhantomData)).unwrap());
//     let protocol = compile(
//         params,
//         vk.or(dummy_vk.as_ref()).unwrap(),
//         Config::kzg()
//             .with_num_instance(ConcreteCircuit::num_instance())
//             .with_accumulator_indices(ConcreteCircuit::accumulator_indices()),
//     );
//     let instances = ConcreteCircuit::num_instance()
//         .into_iter()
//         .map(|n| iter::repeat_with(|| Fr::random(rng)).take(n).collect())
//         .collect();
//     let proof = {
//         let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
//         for _ in 0..protocol
//             .num_witness
//             .iter()
//             .chain(Some(&protocol.quotient.num_chunk()))
//             .sum::<usize>()
//         {
//             transcript.write_ec_point(G1Affine::random(rng)).unwrap();
//         }
//         for _ in 0..protocol.evaluations.len() {
//             transcript.write_scalar(Fr::random(rng)).unwrap();
//         }
//         let queries = PlonkProof::<G1Affine, NativeLoader, Pcs>::empty_queries(&protocol);
//         for _ in 0..Pcs::estimate_cost(&queries).num_commitment {
//             transcript.write_ec_point(G1Affine::random(rng)).unwrap();
//         }
//         transcript.finalize()
//     };

//     Snark::new(protocol, instances, proof)
// }

type AssignedScalar<'a> = <BaseFieldEccChip as EccInstructions<'a, G1Affine>>::AssignedScalar;

fn poseidon<L: Loader<G1Affine>>(
    loader: &L,
    inputs: &[L::LoadedScalar],
) -> L::LoadedScalar {
    let mut hasher = hash::Poseidon::from_spec(loader, POSEIDON_SPEC.clone());
    hasher.update(inputs);
    hasher.squeeze()
}

// TODO: maybe it can be added into snark-verifier sdk later?
// Now it is still a version specified for Kzg since the only
// type support AccumulatorEncoding trait in verifier::Plonk
// is LimbsEncoding, which only be generic with PCS whose Accmulator
// is KzgAccmulator ...

/// It is similar to `succient_verify` method inside of snark-verifier 
/// but allow it allow loader to load preprocessed part as witness (so ANY circuit)
/// can be verified
/// 
/// 
pub fn dynamic_verify<'a, PCS>(
    svk: &PCS::SuccinctVerifyingKey,
    loader: &Rc<Halo2Loader<'a>>,
    snark: &SnarkWitness,
    preprocessed_digest: Option<AssignedScalar<'a>>,
) -> (
    Vec<Vec<AssignedScalar<'a>>>, 
    Vec<PCS::Accumulator>
)
where
    PCS: PolynomialCommitmentScheme<
            G1Affine,
            Rc<Halo2Loader<'a>>,
            Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
        > + MultiOpenScheme<G1Affine, Rc<Halo2Loader<'a>>>, 
{
    let protocol = if let Some(preprocessed_digest) = preprocessed_digest {
        let preprocessed_digest = loader.scalar_from_assigned(preprocessed_digest);
        let protocol = snark.protocol.loaded_preprocessed_as_witness(loader);
        let inputs = protocol
            .preprocessed
            .iter()
            .flat_map(|preprocessed| {
                let assigned = preprocessed.assigned();
                [assigned.x(), assigned.y()]
                    .map(|coordinate| loader.scalar_from_assigned(coordinate.native().clone()))
            })
            .chain(protocol.transcript_initial_state.clone())
            .collect_vec();
        loader.assert_eq("", &poseidon(loader, &inputs), &preprocessed_digest).unwrap();
        protocol
    } else {
        snark.protocol.loaded(loader)
    };

    let instances = snark
        .instances
        .iter()
        .map(|instances| {
            instances.iter().map(|instance| loader.assign_scalar(*instance)).collect_vec()
        })
        .collect_vec();
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, snark.proof());
    let proof = Plonk::<PCS>::read_proof(svk, &protocol, &instances, &mut transcript);
    let accumulators = Plonk::<PCS>::succinct_verify(svk, &protocol, &instances, &proof);

    (
        instances
            .into_iter()
            .map(|instance| {
                instance.into_iter().map(|instance| instance.into_assigned()).collect()
            })
            .collect(),
        accumulators,
    )
}

