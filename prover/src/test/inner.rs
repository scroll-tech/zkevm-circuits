use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG};

use crate::{
    common::{Prover, Verifier},
    config::{LayerId, INNER_DEGREE},
    utils::{gen_rng, read_env_var},
    zkevm::circuit::{SuperCircuit, TargetCircuit},
    WitnessBlock,
};
use std::{
    collections::BTreeMap,
    sync::{LazyLock, Mutex},
};

static PARAMS_MAP: LazyLock<BTreeMap<u32, ParamsKZG<Bn256>>> = LazyLock::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    crate::common::Prover::load_params_map(&params_dir, &[*INNER_DEGREE])
});

static INNER_PROVER: LazyLock<Mutex<Prover>> = LazyLock::new(|| {
    let prover = Prover::from_params(&PARAMS_MAP);
    log::info!("Constructed inner-prover");

    Mutex::new(prover)
});

pub fn inner_prove(test: &str, witness_block: &WitnessBlock) {
    log::info!("{test}: inner-prove BEGIN");

    let mut prover = INNER_PROVER.lock().expect("poisoned inner-prover");

    let rng = gen_rng();
    let snark = prover
        .gen_inner_snark::<SuperCircuit>("inner", rng, witness_block)
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
