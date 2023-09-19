use crate::{
    common::{Prover, Verifier},
    config::{LayerId, ZKEVM_DEGREES},
    utils::read_env_var,
    CompressionCircuit, WitnessBlock,
};
use once_cell::sync::Lazy;
use std::env;

static mut CHUNK_PROVER: Lazy<Prover> = Lazy::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    let prover = Prover::from_params_dir(&params_dir, &ZKEVM_DEGREES);
    log::info!("Constructed chunk-prover");

    prover
});

static mut CHUNK_VERIFIER: Lazy<Verifier<CompressionCircuit>> = Lazy::new(|| {
    env::set_var("COMPRESSION_CONFIG", LayerId::Layer2.config_path());

    let prover = unsafe { &mut CHUNK_PROVER };
    let params = prover.params(LayerId::Layer2.degree()).clone();

    let pk = prover
        .pk(LayerId::Layer2.id())
        .expect("Failed to get chunk-prove PK");
    let vk = pk.get_vk().clone();

    let verifier = Verifier::new(params, vk);
    log::info!("Constructed chunk-verifier");

    verifier
});

pub fn chunk_prove(test: &str, witness_block: &WitnessBlock) {
    log::info!("{test}: chunk-prove BEGIN");

    let prover = unsafe { &mut CHUNK_PROVER };
    let inner_id = read_env_var("INNER_LAYER_ID", LayerId::Inner.id().to_string());
    let inner_id_changed = prover.pk(&inner_id).is_none();

    // Clear previous PKs if inner-layer ID changed.
    if inner_id_changed {
        prover.clear_pks();
    }

    let snark = prover
        .load_or_gen_final_chunk_snark(test, witness_block, Some(&inner_id), None)
        .unwrap_or_else(|err| panic!("{test}: failed to generate chunk snark: {err}"));
    log::info!("{test}: generated chunk snark");

    let verifier = unsafe { &mut CHUNK_VERIFIER };

    // Reset VK if inner-layer ID changed.
    if inner_id_changed {
        let pk = prover
            .pk(LayerId::Layer2.id())
            .unwrap_or_else(|| panic!("{test}: failed to get inner-prove PK"));
        let vk = pk.get_vk().clone();
        verifier.set_vk(vk);
    }

    let verified = verifier.verify_snark(snark);
    assert!(verified, "{test}: failed to verify chunk snark");

    log::info!("{test}: chunk-prove END");
}
