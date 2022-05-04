use bus_mapping::circuit_input_builder::BuilderClient;
use bus_mapping::rpc::GethClient;
use env_logger::Env;
use ethers_providers::Http;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use pairing::bn256::{Bn256, Fr, G1Affine};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::{env::var, fs::File, io::BufReader};

use std::str::FromStr;
use zkevm_circuits::evm_circuit::{
    table::FixedTableTag, test::TestCircuit, witness::block_convert,
};
use zkevm_circuits::state_circuit::StateCircuit;

#[derive(serde::Serialize)]
pub struct Proofs {
    state_proof: eth_types::Bytes,
    evm_proof: eth_types::Bytes,
}

/// This command generates and prints the proofs to stdout.
/// Required environment variables:
/// - BLOCK_NUM - the block number to generate the proof for
/// - RPC_URL - a geth http rpc that supports the debug namespace
/// - PARAMS_PATH - a path to a file generated with the gen_params tool
// TODO: move the proof generation into a module once we implement a rpc daemon for generating
// proofs.
#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let block_num: u64 = var("BLOCK_NUM")
        .expect("BLOCK_NUM env var")
        .parse()
        .expect("Cannot parse BLOCK_NUM env var");
    let rpc_url: String = var("RPC_URL")
        .expect("RPC_URL env var")
        .parse()
        .expect("Cannot parse RPC_URL env var");

    let params_path: String = match var("PARAMS_PATH") {
        Ok(path) => path,
        Err(e) => {
            log::warn!(
                "PARAMS_PATH env var is invalid: {:?}. Params will be setup locally.",
                e
            );
            "".to_string()
        }
    };

    let params: Params<G1Affine> = if params_path.is_empty() {
        let degree = 18;
        log::debug!("setup with degree {}", degree);
        let params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(degree);
        log::debug!("setup done");
        params
    } else {
        // load polynomial commitment parameters from file
        let params_fs = File::open(&params_path).expect("couldn't open params");
        Params::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params")
    };

    // request & build the inputs for the circuits
    let geth_client = GethClient::new(Http::from_str(&rpc_url).expect("GethClient from RPC_URL"));
    let builder = BuilderClient::new(geth_client)
        .await
        .expect("BuilderClient from GethClient");
    let builder = builder
        .gen_inputs(block_num)
        .await
        .expect("gen_inputs for BLOCK_NUM");

    // TODO: only {evm,state}_proof are implemented right now
    let evm_proof;
    let state_proof;
    let block = block_convert(&builder.block, &builder.code_db);
    {
        log::info!("generate evm_circuit proof");
        // generate evm_circuit proof
        let circuit = TestCircuit::<Fr>::new(block.clone(), FixedTableTag::iterator().collect());

        // TODO: can this be pre-generated to a file?
        // related
        // https://github.com/zcash/halo2/issues/443
        // https://github.com/zcash/halo2/issues/449
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk for params, evm_circuit");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk for params, vk, evm_circuit");

        // Create randomness
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(&params, &pk, &[circuit], &[], rng, &mut transcript).expect("evm proof");
        evm_proof = transcript.finalize();

        log::info!("generate evm_circuit proof done");
    }

    {
        let circuit = StateCircuit::new(block.randomness, block.rws);

        // generate state_circuit proof
        let instance = circuit.instance();
        let instance_slices: Vec<_> = instance.iter().map(Vec::as_slice).collect();

        // TODO: same quest like in the first scope
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk for params, state_circuit");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk for params, vk, state_circuit");

        // Create randomness
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            &pk,
            &[circuit],
            &[&instance_slices],
            rng,
            &mut transcript,
        )
        .expect("state proof");
        state_proof = transcript.finalize();
    }

    serde_json::to_writer(
        std::io::stdout(),
        &Proofs {
            evm_proof: evm_proof.into(),
            state_proof: state_proof.into(),
        },
    )
    .expect("serialize and write");
}
