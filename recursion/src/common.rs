use crate::{
    sv_halo2_base::AssignedValue,
    types::{PlonkSuccinctVerifier, Svk},
    G1Affine,
};
use ce_snark_verifier::{
    loader::{Loader, ScalarLoader},
    pcs::kzg::KzgAccumulator,
    util::hash,
    verifier::SnarkVerifier,
};
use ce_snark_verifier_sdk::{
    halo2::{aggregation::Halo2Loader, PoseidonTranscript, POSEIDON_SPEC},
    Snark,
};
use halo2curves::bn256::Fr;
use itertools::Itertools;
use std::rc::Rc;

pub fn poseidon<L: Loader<G1Affine>>(loader: &L, inputs: &[L::LoadedScalar]) -> L::LoadedScalar {
    let mut hasher = hash::Poseidon::from_spec(loader, POSEIDON_SPEC.clone());
    hasher.update(inputs);
    hasher.squeeze()
}

const SECURE_MDS: usize = 0;

pub fn succinct_verify<'a>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a>>,
    snark: &Snark,
    preprocessed_digest: Option<AssignedValue<Fr>>,
) -> (
    Vec<Vec<AssignedValue<Fr>>>,
    Vec<KzgAccumulator<G1Affine, Rc<Halo2Loader<'a>>>>,
) {
    let protocol = if let Some(preprocessed_digest) = preprocessed_digest {
        let preprocessed_digest = loader.scalar_from_assigned(preprocessed_digest);
        let protocol = snark.protocol.loaded_preprocessed_as_witness(loader, false);
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
        loader.assert_eq("", &poseidon(loader, &inputs), &preprocessed_digest);
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
    let mut transcript =
        PoseidonTranscript::<Rc<Halo2Loader>, _>::new::<SECURE_MDS>(loader, snark.proof());
    let proof =
        PlonkSuccinctVerifier::read_proof(svk, &protocol, &instances, &mut transcript).unwrap();
    let accumulators = PlonkSuccinctVerifier::verify(svk, &protocol, &instances, &proof).unwrap();

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
