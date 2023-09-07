use super::Verifier;
use crate::{io::write_file, EvmProof};
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::{gen_evm_verifier, CircuitExt};
use std::{path::PathBuf, str::FromStr};

impl<C: CircuitExt<Fr>> Verifier<C> {
    // Should panic if failed to verify.
    pub fn evm_verify(&self, evm_proof: &EvmProof, output_dir: Option<&str>) {
        let yul_file_path = output_dir.map(|dir| {
            let mut path = PathBuf::from_str(dir).unwrap();
            path.push("evm_verifier.yul");
            path
        });

        // Generate deployment code and dump YUL file.
        let deployment_code = gen_evm_verifier::<C, Kzg<Bn256, Bdfg21>>(
            &self.params,
            &self.vk,
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
}
