use crate::{
    sv_halo2_base::AssignedValue,
    types::{As, BaseFieldEccChip, PlonkSuccinctVerifier, Svk},
    G1Affine,
};
use ce_snark_verifier::{
    loader::{halo2::EccInstructions, Loader},
    pcs::{
        kzg::{Bdfg21, KzgAccumulator, KzgAs},
        PolynomialCommitmentScheme,
    },
    util::hash,
    verifier::SnarkVerifier,
};
use ce_snark_verifier_sdk::{
    halo2::{aggregation::Halo2Loader, PoseidonTranscript, POSEIDON_SPEC},
    Snark,
};
use halo2curves::bn256::Fr;
use std::rc::Rc;

pub fn poseidon<L: Loader<G1Affine>>(loader: &L, inputs: &[L::LoadedScalar]) -> L::LoadedScalar {
    let mut hasher = hash::Poseidon::from_spec(loader, POSEIDON_SPEC.clone());
    hasher.update(inputs);
    hasher.squeeze()
}

/// It is similar to `succinct_verify` method inside of snark-verifier
/// but allow it allow loader to load preprocessed part as witness (so ANY circuit)
/// can be verified.
pub fn dynamic_verify<'a>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snark: &Snark,
    preprocessed_digest: Option<AssignedValue<Fr>>,
)
// -> (Vec<Vec<AssignedScalar<'a>>>, Vec<PCS::Accumulator>)
//where
// PCS: PolynomialCommitmentScheme<
//         G1Affine,
//         Rc<Halo2Loader<'a>>,
//         Accumulator = KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>,
//     >
// + MultiOpenScheme<G1Affine, Rc<Halo2Loader<'a>>>,
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
                    .map(|coordinate| loader.scalar_from_assigned(*coordinate.native()))
            })
            .chain(protocol.transcript_initial_state.clone())
            .collect_vec();
        loader
            .assert_eq("", &poseidon(loader, &inputs), &preprocessed_digest)
            .unwrap();
        protocol
    } else {
        snark.protocol.loaded(loader)
    };

    let instances = snark
        .instances
        .iter()
        .map(|instances| {
            instances
                .iter()
                .map(|instance| loader.assign_scalar(*instance))
                .collect_vec()
        })
        .collect_vec();
    let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new(loader, snark.proof());
    let proof = PlonkSuccinctVerifier::read_proof(svk, &protocol, &instances, &mut transcript);
    let accumulators = PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof);

    (
        instances
            .into_iter()
            .map(|instance| {
                instance
                    .into_iter()
                    .map(|instance| instance.into_assigned())
                    .collect()
            })
            .collect(),
        accumulators,
    )
}
