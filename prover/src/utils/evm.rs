use std::{path::PathBuf, str::FromStr};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use revm::{
    primitives::{CreateScheme, ExecutionResult, Output, TransactTo, TxEnv},
    InMemoryDB, EVM,
};
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use snark_verifier_sdk::CircuitExt;

use crate::{utils::write_file, EvmProof};

/// Dump YUL and binary bytecode(use `solc` in PATH) to output_dir.
///
/// Panics if the verifier contract cannot successfully verify the [`EvmProof`].
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

    // Write the contract binary if an output directory was specified.
    if let Some(dir) = output_dir {
        let mut dir = PathBuf::from_str(dir).unwrap();
        write_file(&mut dir, "evm_verifier.bin", &deployment_code);
    }

    assert!(evm_proof.proof.evm_verify(deployment_code));
}

/// Deploy contract and then call with calldata.
///
/// Returns the gas used to verify proof.
pub fn deploy_and_call(deployment_code: Vec<u8>, calldata: Vec<u8>) -> Result<u64, String> {
    let mut evm = EVM {
        env: Default::default(),
        db: Some(InMemoryDB::default()),
    };

    evm.env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TransactTo::Create(CreateScheme::Create),
        data: deployment_code.into(),
        ..Default::default()
    };

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

    evm.env.tx = TxEnv {
        gas_limit: u64::MAX,
        transact_to: TransactTo::Call(contract),
        data: calldata.into(),
        ..Default::default()
    };

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
