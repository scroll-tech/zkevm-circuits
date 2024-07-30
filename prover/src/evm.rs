use crate::{io::write_file, EvmProof};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::CircuitExt;
use std::{path::PathBuf, str::FromStr};

/// Dump YUL and binary bytecode(use `solc` in PATH) to output_dir.
/// Panic if error encountered.
pub fn gen_evm_verifier<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    evm_proof: &EvmProof,
    output_dir: Option<&str>,
) {
    let yul_file_path = output_dir.map(|dir| {
        let mut path = PathBuf::from_str(dir).unwrap();
        path.push("evm_verifier.yul");
        path
    });

    // Generate deployment code and dump YUL file.
    let deployment_code = snark_verifier_sdk::gen_evm_verifier::<C, Kzg<Bn256, Bdfg21>>(
        params,
        vk,
        evm_proof.num_instance.clone(),
        yul_file_path.as_deref(),
    );

    if let Some(dir) = output_dir {
        // Dump bytecode.
        let mut dir = PathBuf::from_str(dir).unwrap();
        write_file(&mut dir, "evm_verifier.bin", &deployment_code);
    }

    let success = evm_proof.proof.evm_verify(deployment_code);
    assert!(success);
}
