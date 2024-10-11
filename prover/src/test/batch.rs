use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};

use crate::{
    aggregator::{Prover, Verifier},
    config::{LayerId, AGG_DEGREES},
    consts::DEPLOYMENT_CODE_FILENAME,
    io::force_to_read,
    types::BundleProvingTask,
    utils::read_env_var,
    BatchProvingTask,
};
use std::{
    collections::BTreeMap,
    sync::{LazyLock, Mutex},
};

static PARAMS_MAP: LazyLock<BTreeMap<u32, ParamsKZG<Bn256>>> = LazyLock::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    crate::common::Prover::load_params_map(&params_dir, &AGG_DEGREES)
});

static BATCH_PROVER: LazyLock<Mutex<Prover>> = LazyLock::new(|| {
    let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());

    let prover = Prover::from_params_and_assets(&PARAMS_MAP, &assets_dir);
    log::info!("Constructed batch-prover");

    Mutex::new(prover)
});

pub fn batch_prove(test: &str, batch: BatchProvingTask) {
    log::info!("{test}: batch-prove BEGIN");

    let mut prover = BATCH_PROVER.lock().expect("poisoned batch-prover");
    let proof = prover
        .gen_batch_proof(batch, None, None)
        .unwrap_or_else(|err| panic!("{test}: failed to generate batch proof: {err}"));
    log::info!("{test}: generated batch proof");

    let verifier = {
        let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());

        let params = prover.prover_impl.params(LayerId::Layer4.degree());

        let deployment_code = force_to_read(&assets_dir, &DEPLOYMENT_CODE_FILENAME);

        let pk = prover
            .prover_impl
            .pk(LayerId::Layer4.id())
            .expect("Failed to get batch-prove PK");
        let vk = pk.get_vk().clone();

        let verifier = Verifier::new(params, vk, deployment_code);
        log::info!("Constructed batch-verifier");
        verifier
    };
    let verified = verifier.verify_batch_proof(&proof);
    assert!(verified, "{test}: failed to verify batch proof");

    log::info!("{test}: batch-prove END");
}

pub fn bundle_prove(test: &str, bundle: BundleProvingTask) {
    log::info!("{test}: bundle-prove BEGIN");

    let mut prover = BATCH_PROVER.lock().expect("poisoned batch-prover");
    let proof = prover
        .gen_bundle_proof(bundle, None, None)
        .unwrap_or_else(|err| panic!("{test}: failed to generate bundle proof: {err}"));
    log::info!("{test}: generated bundle proof");

    // FIXME: clean redundant code
    let verifier = {
        let assets_dir = read_env_var("SCROLL_PROVER_ASSETS_DIR", "./test_assets".to_string());

        let params = prover.prover_impl.params(LayerId::Layer4.degree());

        let deployment_code = force_to_read(&assets_dir, &DEPLOYMENT_CODE_FILENAME);

        let pk = prover
            .prover_impl
            .pk(LayerId::Layer4.id())
            .expect("Failed to get batch-prove PK");
        let vk = pk.get_vk().clone();

        let verifier = Verifier::new(params, vk, deployment_code);
        log::info!("Constructed batch-verifier");
        verifier
    };

    let verified = verifier.verify_bundle_proof(proof);
    assert!(verified, "{test}: failed to verify bundle proof");

    log::info!("{test}: bundle-prove END");
}
