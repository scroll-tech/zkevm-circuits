use crate::{
    utils::read_env_var,
    zkevm::{Prover, Verifier},
    ChunkProof, ChunkProvingTask,
};
use std::sync::{LazyLock, Mutex};

static CHUNK_PROVER: LazyLock<Mutex<Prover>> = LazyLock::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());
    let prover = Prover::from_dirs(&params_dir, &assets_dir);
    log::info!("Constructed chunk-prover");

    Mutex::new(prover)
});

static CHUNK_VERIFIER: LazyLock<Mutex<Verifier>> = LazyLock::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());

    let verifier = Verifier::from_dirs(&params_dir, &assets_dir);
    log::info!("Constructed chunk-verifier");

    Mutex::new(verifier)
});

pub fn chunk_prove(desc: &str, chunk: ChunkProvingTask) -> ChunkProof {
    log::info!("{desc}: chunk-prove BEGIN");

    let mut prover = CHUNK_PROVER.lock().expect("poisoned chunk-prover");

    let proof = prover
        .gen_chunk_proof(chunk, None, None, None)
        .unwrap_or_else(|err| panic!("{desc}: failed to generate chunk snark: {err}"));
    log::info!("{desc}: generated chunk proof");

    let verifier = CHUNK_VERIFIER.lock().expect("poisoned chunk-verifier");

    let verified = verifier.verify_chunk_proof(proof.clone());
    assert!(verified, "{desc}: failed to verify chunk snark");

    log::info!("{desc}: chunk-prove END");

    proof
}
