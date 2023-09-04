use crate::{
    aggregator::{Prover, Verifier},
    common,
    config::LayerId,
    test_util::PARAMS_DIR,
    zkevm, BatchProof, ChunkProof, EvmProof,
};
use aggregator::CompressionCircuit;
use eth_types::l2_types::StorageTrace;
use snark_verifier_sdk::Snark;
use std::env;

pub fn gen_and_verify_batch_proofs(agg_prover: &mut Prover, layer3_snark: Snark, output_dir: &str) {
    let evm_proof = gen_and_verify_normal_and_evm_proofs(
        &mut agg_prover.inner,
        LayerId::Layer4,
        layer3_snark,
        Some(output_dir),
    )
    .1;
    verify_batch_proof(evm_proof, output_dir);
}

pub fn gen_and_verify_chunk_proofs(
    zkevm_prover: &mut zkevm::Prover,
    layer1_snark: Snark,
    output_dir: &str,
) {
    let normal_proof = gen_and_verify_normal_and_evm_proofs(
        &mut zkevm_prover.inner,
        LayerId::Layer2,
        layer1_snark,
        Some(output_dir),
    )
    .0;
    verify_chunk_proof(&zkevm_prover.inner, normal_proof, output_dir);
}

pub fn gen_and_verify_normal_and_evm_proofs(
    prover: &mut common::Prover,
    layer_id: LayerId,
    previous_snark: Snark,
    output_dir: Option<&str>,
) -> (Snark, EvmProof) {
    let normal_proof = gen_normal_proof(prover, layer_id, previous_snark.clone(), output_dir);
    let evm_proof = gen_evm_proof(prover, layer_id, previous_snark, output_dir);
    verify_normal_and_evm_proofs(
        prover,
        layer_id,
        normal_proof.clone(),
        &evm_proof,
        output_dir,
    );

    (normal_proof, evm_proof)
}

fn gen_evm_proof(
    prover: &mut common::Prover,
    layer_id: LayerId,
    previous_snark: Snark,
    output_dir: Option<&str>,
) -> EvmProof {
    let id = layer_id.id();
    let degree = layer_id.degree();

    // Load or generate compression EVM proof.
    let evm_proof = prover
        .load_or_gen_comp_evm_proof("evm", id, true, degree, previous_snark, output_dir)
        .unwrap();
    log::info!("Generated EVM proof: {id}");

    evm_proof
}

fn gen_normal_proof(
    prover: &mut common::Prover,
    layer_id: LayerId,
    previous_snark: Snark,
    output_dir: Option<&str>,
) -> Snark {
    let id = layer_id.id();
    let degree = layer_id.degree();

    // Load or generate compression snark.
    let snark = prover
        .load_or_gen_comp_snark("normal", id, true, degree, previous_snark, output_dir)
        .unwrap();
    log::info!("Generated compression snark: {id}");

    snark
}

fn verify_batch_proof(evm_proof: EvmProof, output_dir: &str) {
    let batch_proof = BatchProof::from(evm_proof.proof);
    batch_proof.dump(output_dir, "agg").unwrap();
    batch_proof.clone().assert_calldata();

    env::set_var("AGG_VK_FILENAME", "vk_evm_layer4_evm.vkey");
    let verifier = Verifier::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed aggregator verifier");

    assert!(verifier.verify_agg_evm_proof(batch_proof));
    log::info!("Verified batch proof");
}

fn verify_chunk_proof(prover: &common::Prover, normal_proof: Snark, output_dir: &str) {
    let pk = prover.pk(LayerId::Layer2.id()).unwrap();
    let chunk_proof =
        ChunkProof::new(normal_proof, StorageTrace::default(), Some(pk), None).unwrap();
    chunk_proof.dump(output_dir, "0").unwrap();

    env::set_var("CHUNK_VK_FILENAME", "vk_chunk_0.vkey");
    let verifier = zkevm::Verifier::from_dirs(PARAMS_DIR, output_dir);
    log::info!("Constructed zkevm verifier");

    assert!(verifier.verify_chunk_proof(chunk_proof));
    log::info!("Verified chunk proof");
}

fn verify_normal_and_evm_proofs(
    prover: &mut common::Prover,
    layer_id: LayerId,
    normal_proof: Snark,
    evm_proof: &EvmProof,
    output_dir: Option<&str>,
) {
    let id = layer_id.id();
    let degree = layer_id.degree();
    let config_path = layer_id.config_path();

    env::set_var("COMPRESSION_CONFIG", config_path);
    let vk = evm_proof.proof.vk::<CompressionCircuit>();

    let params = prover.params(degree).clone();
    let verifier = common::Verifier::<CompressionCircuit>::new(params, vk);
    log::info!("Constructed common verifier");

    assert!(verifier.verify_snark(normal_proof));
    log::info!("Verified normal proof: {id}");

    verifier.evm_verify(evm_proof, output_dir);
    log::info!("Verified EVM proof: {id}");
}
