use crate::{
    common::{Prover, Verifier},
    config::{LayerId, INNER_DEGREE},
    utils::{gen_rng, read_env_var},
    zkevm::circuit::{SuperCircuit, TargetCircuit},
    WitnessBlock,
};
use once_cell::sync::Lazy;

static mut INNER_PROVER: Lazy<Prover> = Lazy::new(|| {
    let params_dir = read_env_var("SCROLL_PROVER_PARAMS_DIR", "./test_params".to_string());
    let prover = Prover::from_params_dir(&params_dir, &[*INNER_DEGREE]);
    log::info!("Constructed inner-prover");

    prover
});

static mut INNER_VERIFIER: Lazy<Verifier<<SuperCircuit as TargetCircuit>::Inner>> =
    Lazy::new(|| {
        let prover = unsafe { &mut INNER_PROVER };
        let params = prover.params(*INNER_DEGREE).clone();

        let inner_id = read_env_var("INNER_LAYER_ID", LayerId::Inner.id().to_string());
        let pk = prover.pk(&inner_id).expect("Failed to get inner-prove PK");
        let vk = pk.get_vk().clone();

        let verifier = Verifier::new(params, vk);
        log::info!("Constructed inner-verifier");

        verifier
    });

pub fn inner_prove(test: &str, witness_block: &WitnessBlock) {
    log::info!("{test}: inner-prove BEGIN");

    let prover = unsafe { &mut INNER_PROVER };
    let inner_id = read_env_var("INNER_LAYER_ID", LayerId::Inner.id().to_string());
    let inner_id_changed = prover.pk(&inner_id).is_none();

    // Clear previous PKs if inner-layer ID changed.
    if inner_id_changed {
        prover.clear_pks();
    }

    let rng = gen_rng();
    let snark = prover
        .gen_inner_snark::<SuperCircuit>(&inner_id, rng, witness_block)
        .unwrap_or_else(|err| panic!("{test}: failed to generate inner snark: {err}"));
    log::info!("{test}: generated inner snark");

    let verifier = unsafe { &mut INNER_VERIFIER };

    // Reset VK if inner-layer ID changed.
    if inner_id_changed {
        let pk = prover
            .pk(&inner_id)
            .unwrap_or_else(|| panic!("{test}: failed to get inner-prove PK"));
        let vk = pk.get_vk().clone();
        verifier.set_vk(vk);
    }

    let verified = verifier.verify_snark(snark);
    assert!(verified, "{test}: failed to verify inner snark");

    log::info!("{test}: inner-prove END");
}
