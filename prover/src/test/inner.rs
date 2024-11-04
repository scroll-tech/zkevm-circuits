use std::sync::{LazyLock, Mutex};

use crate::{
    common::{Prover, Verifier},
    config::{LayerId, INNER_DEGREE},
    utils::read_env_var,
    zkevm::circuit::{SuperCircuit, TargetCircuit},
    ParamsMap, WitnessBlock,
};

static PARAMS_MAP: LazyLock<ParamsMap> = LazyLock::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    crate::common::Prover::load_params_map(&params_dir, &[*INNER_DEGREE])
});

static INNER_PROVER: LazyLock<Mutex<Prover>> = LazyLock::new(|| {
    let prover = Prover::from_params_map(&PARAMS_MAP);
    log::info!("Constructed inner-prover");

    Mutex::new(prover)
});

pub fn inner_prove(test: &str, witness_block: &WitnessBlock) {
    log::info!("{test}: inner-prove BEGIN");

    let mut prover = INNER_PROVER.lock().expect("poisoned inner-prover");

    let snark = prover
        .load_or_gen_inner_snark("", "inner", witness_block, None)
        .unwrap_or_else(|err| panic!("{test}: failed to generate inner snark: {err}"));
    log::info!("{test}: generated inner snark");

    let verifier: Verifier<'_, <SuperCircuit as TargetCircuit>::Inner> = {
        let params = prover.params(*INNER_DEGREE);

        let inner_id = LayerId::Inner.id().to_string();
        let pk = prover.pk(&inner_id).expect("Failed to get inner-prove PK");
        let vk = pk.get_vk().clone();

        let verifier = Verifier::new(params, vk);
        log::info!("Constructed inner-verifier");
        verifier
    };

    let verified = verifier.verify_snark(snark);
    assert!(verified, "{test}: failed to verify inner snark");

    log::info!("{test}: inner-prove END");
}
