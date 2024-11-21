use std::path::{Path, PathBuf};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use revm::{
    primitives::{self, Env, ExecutionResult, Output, TxEnv, TxKind},
    Evm, Handler, InMemoryDB,
};

use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::CircuitExt;

use crate::{utils::write, BatchProverError, EvmProof, ProverError};

/// Dump YUL and binary bytecode(use `solc` in PATH) to output_dir.
///
/// Panics if the verifier contract cannot successfully verify the [`EvmProof`].
pub fn gen_evm_verifier<C: CircuitExt<Fr>>(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    evm_proof: &EvmProof,
    output_dir: Option<&str>,
) -> Result<(), ProverError> {
    // YUL contract code will be dumped to the following path.
    let yul_path = output_dir.map(|dir| PathBuf::from(dir).join("evm_verifier.yul"));

    // Generate deployment code and dump YUL file.
    let deployment_code = snark_verifier_sdk::gen_evm_verifier::<C, Kzg<Bn256, Bdfg21>>(
        params,
        vk,
        evm_proof.num_instance.clone(),
        yul_path.as_deref(),
    );

    // Write the contract binary if an output directory was specified.
    if let Some(dir) = output_dir {
        let path = Path::new(dir).join("evm_verifier.bin");
        write(&path, &deployment_code)?;
    }

    if evm_proof.proof.evm_verify(deployment_code) {
        Ok(())
    } else {
        Err(ProverError::BatchProverError(
            BatchProverError::SanityEVMVerifier,
        ))
    }
}

/// Deploy contract and then call with calldata.
///
/// Returns the gas used to verify proof.
pub fn deploy_and_call(deployment_code: Vec<u8>, calldata: Vec<u8>) -> Result<u64, String> {
    let mut env = Box::<Env>::default();
    env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TxKind::Create,
        data: deployment_code.into(),
        ..Default::default()
    };
    let mut db = InMemoryDB::default();
    let mut evm = Evm::builder()
        .with_db(&mut db)
        .with_env(env.clone())
        .with_handler(Handler::mainnet::<primitives::CancunSpec>())
        .build();
    let result = evm.transact_commit().unwrap();
    let contract = match result {
        ExecutionResult::Success {
            output: Output::Create(_, Some(contract)),
            ..
        } => contract,
        ExecutionResult::Revert { gas_used, output } => {
            return Err(format!(
                "Contract deployment transaction reverts with gas_used {gas_used} and output {:#x}",
                output
            ))
        }
        ExecutionResult::Halt { reason, gas_used } => return Err(format!(
            "Contract deployment transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
            reason
        )),
        _ => unreachable!(),
    };
    drop(evm);

    env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TxKind::Call(contract),
        data: calldata.into(),
        ..Default::default()
    };
    let mut evm = Evm::builder()
        .with_db(&mut db)
        .with_env(env.clone())
        .with_handler(Handler::mainnet::<primitives::CancunSpec>())
        .build();
    let result = evm.transact_commit().unwrap();
    match result {
        ExecutionResult::Success { gas_used, .. } => Ok(gas_used),
        ExecutionResult::Revert { gas_used, output } => Err(format!(
            "Contract call transaction reverts with gas_used {gas_used} and output {:#x}",
            output
        )),
        ExecutionResult::Halt { reason, gas_used } => Err(format!(
            "Contract call transaction halts unexpectedly with gas_used {gas_used} and reason {:?}",
            reason
        )),
    }
}
