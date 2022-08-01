use env_logger::Env;
use halo2_proofs::pairing::bn256::{Bn256, G1Affine};
use halo2_proofs::poly::commitment::Params;
use std::{env::var, fs::File, io::BufReader};

use prover::compute_proof::compute_proof;

/// This command generates and prints the proofs to stdout.
/// Required environment variables:
/// - BLOCK_NUM - the block number to generate the proof for
/// - RPC_URL - a geth http rpc that supports the debug namespace
/// - PARAMS_PATH - a path to a file generated with the gen_params tool
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

    let result = compute_proof(&params, &block_num, &rpc_url)
        .await
        .expect("compute_proof");

    serde_json::to_writer(std::io::stdout(), &result).expect("serialize and write");
}
