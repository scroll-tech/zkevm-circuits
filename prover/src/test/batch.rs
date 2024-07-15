use crate::{
    aggregator::{Prover, Verifier},
    config::LayerId,
    consts::DEPLOYMENT_CODE_FILENAME,
    io::force_to_read,
    types::BundleProvingTask,
    utils::read_env_var,
    BatchProvingTask,
};
use std::sync::{LazyLock, Mutex};

static BATCH_PROVER: LazyLock<Mutex<Prover>> = LazyLock::new(|| {
    let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());

    let prover = Prover::from_dirs(&params_dir, &assets_dir);
    log::info!("Constructed batch-prover");

    Mutex::new(prover)
});

static BATCH_VERIFIER: LazyLock<Mutex<Verifier>> = LazyLock::new(|| {
    let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());

    let mut prover = BATCH_PROVER.lock().expect("poisoned batch-prover");
    let params = prover.prover_impl.params(LayerId::Layer4.degree()).clone();

    let deployment_code = force_to_read(&assets_dir, &DEPLOYMENT_CODE_FILENAME);

    let pk = prover
        .prover_impl
        .pk(LayerId::Layer4.id())
        .expect("Failed to get batch-prove PK");
    let vk = pk.get_vk().clone();

    let verifier = Verifier::new(params, vk, deployment_code);
    log::info!("Constructed batch-verifier");

    Mutex::new(verifier)
});

pub fn batch_prove(test: &str, batch: BatchProvingTask) {
    log::info!("{test}: batch-prove BEGIN");

    let proof = BATCH_PROVER
        .lock()
        .expect("poisoned batch-prover")
        .gen_batch_proof(batch, None, None)
        .unwrap_or_else(|err| panic!("{test}: failed to generate batch proof: {err}"));
    log::info!("{test}: generated batch proof");

    let verified = BATCH_VERIFIER
        .lock()
        .expect("poisoned batch-verifier")
        .verify_batch_proof(&proof);
    assert!(verified, "{test}: failed to verify batch proof");

    log::info!("{test}: batch-prove END");
}

pub fn bundle_prove(test: &str, bundle: BundleProvingTask) {
    log::info!("{test}: bundle-prove BEGIN");

    let proof = BATCH_PROVER
        .lock()
        .expect("poisoned batch-prover")
        .gen_bundle_proof(bundle, None, None)
        .unwrap_or_else(|err| panic!("{test}: failed to generate bundle proof: {err}"));
    log::info!("{test}: generated bundle proof");

    let verified = BATCH_VERIFIER
        .lock()
        .expect("poisoned batch-verifier")
        .verify_bundle_proof(proof);
    assert!(verified, "{test}: failed to verify bundle proof");

    log::info!("{test}: bundle-prove END");
}
