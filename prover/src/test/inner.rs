use crate::{
    common::{Prover, Verifier},
    config::{LayerId, INNER_DEGREE},
    utils::{gen_rng, read_env_var},
    zkevm::circuit::{SuperCircuit, TargetCircuit},
    WitnessBlock,
};
use std::sync::{LazyLock, Mutex};

static INNER_PROVER: LazyLock<Mutex<Prover>> = LazyLock::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    let prover = Prover::from_params_dir(&params_dir, &[*INNER_DEGREE]);
    log::info!("Constructed inner-prover");

    Mutex::new(prover)
});

static INNER_VERIFIER: LazyLock<Mutex<Verifier<<SuperCircuit as TargetCircuit>::Inner>>> =
    LazyLock::new(|| {
        let mut prover = INNER_PROVER.lock().expect("poisoned inner-prover");
        let params = prover.params(*INNER_DEGREE).clone();

        let inner_id = LayerId::Inner.id().to_string();
        let pk = prover.pk(&inner_id).expect("Failed to get inner-prove PK");
        let vk = pk.get_vk().clone();

        let verifier = Verifier::new(params, vk);
        log::info!("Constructed inner-verifier");

        Mutex::new(verifier)
    });

pub fn inner_prove(test: &str, witness_block: &WitnessBlock) {
    log::info!("{test}: inner-prove BEGIN");

    let mut prover = INNER_PROVER.lock().expect("poisoned inner-prover");

    let rng = gen_rng();
    let snark = prover
        .gen_inner_snark::<SuperCircuit>("inner", rng, witness_block)
        .unwrap_or_else(|err| panic!("{test}: failed to generate inner snark: {err}"));
    log::info!("{test}: generated inner snark");

    let verifier = INNER_VERIFIER.lock().expect("poisoned inner-verifier");

    let verified = verifier.verify_snark(snark);
    assert!(verified, "{test}: failed to verify inner snark");

    log::info!("{test}: inner-prove END");
}
