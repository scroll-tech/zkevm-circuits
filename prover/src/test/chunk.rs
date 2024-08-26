use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};

use crate::{
    config::ZKEVM_DEGREES,
    utils::read_env_var,
    zkevm::{Prover, Verifier},
    ChunkProof, ChunkProvingTask,
};
use std::{
    collections::BTreeMap,
    sync::{LazyLock, Mutex},
};

static PARAMS_MAP: LazyLock<BTreeMap<u32, ParamsKZG<Bn256>>> = LazyLock::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    crate::common::Prover::load_params_map(&params_dir, &ZKEVM_DEGREES)
});

static CHUNK_PROVER: LazyLock<Mutex<Prover>> = LazyLock::new(|| {
    let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());
    let prover = Prover::from_params_map(&PARAMS_MAP, &assets_dir);
    log::info!("Constructed chunk-prover");

    Mutex::new(prover)
});

pub fn chunk_prove(desc: &str, chunk: ChunkProvingTask) -> ChunkProof {
    log::info!("{desc}: chunk-prove BEGIN");

    let mut prover = CHUNK_PROVER.lock().expect("poisoned chunk-prover");

    let proof = prover
        .gen_chunk_proof(chunk, None, None, None)
        .unwrap_or_else(|err| panic!("{desc}: failed to generate chunk snark: {err}"));
    log::info!("{desc}: generated chunk proof");

    let verifier = {
        let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());
        let verifier = Verifier::from_params_map(prover.prover_impl.params_map, &assets_dir);
        log::info!("Constructed chunk-verifier");
        verifier
    };

    let verified = verifier.verify_chunk_proof(proof.clone());
    assert!(verified, "{desc}: failed to verify chunk snark");

    log::info!("{desc}: chunk-prove END");

    proof
}
