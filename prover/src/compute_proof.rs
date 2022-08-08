use bus_mapping::circuit_input_builder::BuilderClient;
use bus_mapping::rpc::GethClient;
use ethers_providers::Http;
use halo2_proofs::{
    pairing::bn256::{Fr, G1Affine},
    plonk::*,
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;

use std::str::FromStr;
use std::time::Instant;

use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::{
    table::FixedTableTag, test::EvmTestCircuit, witness::block_convert,
};
use zkevm_circuits::state_circuit::StateCircuit;

use crate::structs::Proofs;

/// Gathers debug trace(s) from `rpc_url` for block `block_num` with `params`
/// created via the `gen_params` tool.
/// Expects a go-ethereum node with debug & archive capabilities on `rpc_url`.
pub async fn compute_proof(
    params: &Params<G1Affine>,
    block_num: &u64,
    rpc_url: &str,
) -> Result<Proofs, Box<dyn std::error::Error>> {
    // request & build the inputs for the circuits
    let time_started = Instant::now();
    let url = Http::from_str(rpc_url)?;
    let geth_client = GethClient::new(url);
    let builder = BuilderClient::new(geth_client).await?;
    let builder = builder.gen_inputs(*block_num).await?;

    // TODO: only {evm,state}_proof are implemented right now
    let evm_proof;
    let state_proof;
    let block = block_convert(&builder.block, &builder.code_db);
    {
        // generate evm_circuit proof
        let circuit = EvmTestCircuit::<Fr>::new(block.clone(), FixedTableTag::iter().collect());

        // TODO: can this be pre-generated to a file?
        // related
        // https://github.com/zcash/halo2/issues/443
        // https://github.com/zcash/halo2/issues/449
        let vk = keygen_vk(params, &circuit)?;
        let pk = keygen_pk(params, vk, &circuit)?;

        // Create randomness
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(params, &pk, &[circuit], &[], rng, &mut transcript)?;
        evm_proof = transcript.finalize();
    }

    {
        // generate state_circuit proof
        const N_ROWS: usize = 1 << 16;
        let circuit = StateCircuit::<Fr>::new(block.randomness, block.rws, N_ROWS);

        // TODO: same quest like in the first scope
        let vk = keygen_vk(params, &circuit)?;
        let pk = keygen_pk(params, vk, &circuit)?;

        // Create randomness
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(params, &pk, &[circuit], &[], rng, &mut transcript)?;
        state_proof = transcript.finalize();
    }

    let ret = Proofs {
        evm_proof: evm_proof.into(),
        state_proof: state_proof.into(),
        duration: Instant::now().duration_since(time_started).as_millis() as u64,
    };

    Ok(ret)
}
