use crate::{
    types::BlockTraceJsonRpcResult,
    zkevm::circuit::{block_traces_to_witness_block, check_batch_capacity},
};
use anyhow::{bail, Result};
use chrono::Utc;
use eth_types::{l2_types::BlockTrace, Address};
use git_version::git_version;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use log::LevelFilter;
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        file::FileAppender,
    },
    config::{Appender, Config, Root},
};
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use std::{
    fs::{self, metadata, File},
    io::{BufReader, Read},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Once,
};
use zkevm_circuits::evm_circuit::witness::Block;

pub static LOGGER: Once = Once::new();

pub const DEFAULT_SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytesUnchecked;
pub const GIT_VERSION: &str = git_version!(args = ["--abbrev=7", "--always"]);

pub const PARAMS_G2_SECRET_POWER: &str = "(Fq2 { c0: 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2, c1: 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac }, Fq2 { c0: 0x297772d34bc9aa8ae56162486363ffe417b02dc7e8c207fc2cc20203e67a02ad, c1: 0x298adc7396bd3865cbf6d6df91bae406694e6d2215baa893bdeadb63052895f4 })";

/// Load setup params from a file.
pub fn load_params(
    params_dir: &str,
    degree: u32,
    serde_fmt: Option<SerdeFormat>,
) -> Result<ParamsKZG<Bn256>> {
    log::info!("Start loading params with degree {}", degree);
    let params_path = if metadata(params_dir)?.is_dir() {
        // auto load
        param_path_for_degree(params_dir, degree)
    } else {
        params_dir.to_string()
    };
    if !Path::new(&params_path).exists() {
        bail!("Need to download params by `make download-setup -e degree={degree}`");
    }
    let f = File::open(params_path)?;

    // check params file length:
    //   len: 4 bytes
    //   g: 2**DEGREE g1 points, each 32 bytes(256bits)
    //   g_lagrange: 2**DEGREE g1 points, each 32 bytes(256bits)
    //   g2: g2 point, 64 bytes
    //   s_g2: g2 point, 64 bytes
    let file_size = f.metadata()?.len();
    let g1_num = 2 * (1 << degree);
    let g2_num = 2;

    let serde_fmt = serde_fmt.unwrap_or(DEFAULT_SERDE_FORMAT);
    let g1_bytes_len = match serde_fmt {
        SerdeFormat::Processed => 32,
        SerdeFormat::RawBytes | SerdeFormat::RawBytesUnchecked => 64,
    };
    let g2_bytes_len = 2 * g1_bytes_len;
    let expected_len = 4 + g1_num * g1_bytes_len + g2_num * g2_bytes_len;
    if file_size != expected_len {
        bail!("invalid params file len {} for degree {}. check DEGREE or remove the invalid params file", file_size, degree);
    }

    let p = ParamsKZG::<Bn256>::read_custom::<_>(&mut BufReader::new(f), serde_fmt)?;
    if format!("{:?}", p.s_g2()) != PARAMS_G2_SECRET_POWER {
        bail!("Wrong params file of degree {}", degree);
    }

    log::info!("load params successfully!");
    Ok(p)
}

/// get a block-result from file
pub fn get_block_trace_from_file<P: AsRef<Path>>(path: P) -> BlockTrace {
    let mut buffer = Vec::new();
    let mut f = File::open(&path).unwrap();
    f.read_to_end(&mut buffer).unwrap();

    let mut trace = serde_json::from_slice::<BlockTrace>(&buffer).unwrap_or_else(|e1| {
        serde_json::from_slice::<BlockTraceJsonRpcResult>(&buffer)
            .map_err(|e2| {
                panic!(
                    "unable to load BlockTrace from {:?}, {:?}, {:?}",
                    path.as_ref(),
                    e1,
                    e2
                )
            })
            .unwrap()
            .result
    });
    // fill intrinsicStorageProofs into tx storage proof
    let addrs = vec![
        Address::from_str("0x5300000000000000000000000000000000000000").unwrap(),
        Address::from_str("0x5300000000000000000000000000000000000002").unwrap(),
    ];
    for tx_storage_trace in &mut trace.tx_storage_trace {
        if let Some(proof) = tx_storage_trace.proofs.as_mut() {
            for addr in &addrs {
                proof.insert(
                    *addr,
                    trace
                        .storage_trace
                        .proofs
                        .as_ref()
                        .map(|p| p[addr].clone())
                        .unwrap(),
                );
            }
        }
        for addr in &addrs {
            tx_storage_trace
                .storage_proofs
                .insert(*addr, trace.storage_trace.storage_proofs[addr].clone());
        }
    }

    trace
}

pub fn read_env_var<T: Clone + FromStr>(var_name: &'static str, default: T) -> T {
    std::env::var(var_name)
        .map(|s| s.parse::<T>().unwrap_or_else(|_| default.clone()))
        .unwrap_or(default)
}

#[derive(Debug)]
pub struct BatchMetric {
    pub num_block: usize,
    pub num_tx: usize,
    pub num_step: usize,
}

pub fn metric_of_witness_block(block: &Block<Fr>) -> BatchMetric {
    BatchMetric {
        num_block: block.context.ctxs.len(),
        num_tx: block.txs.len(),
        num_step: block.txs.iter().map(|tx| tx.steps.len()).sum::<usize>(),
    }
}

pub fn chunk_trace_to_witness_block(mut chunk_trace: Vec<BlockTrace>) -> Result<Block<Fr>> {
    if chunk_trace.is_empty() {
        bail!("Empty chunk trace");
    }

    // Check if the trace exceeds the circuit capacity.
    check_batch_capacity(&mut chunk_trace)?;

    block_traces_to_witness_block(&chunk_trace)
}

// Return the output dir.
pub fn init_env_and_log(id: &str) -> String {
    dotenv::dotenv().ok();
    let output_dir = create_output_dir(id);

    LOGGER.call_once(|| {
        // TODO: cannot support complicated `RUST_LOG` for now.
        let log_level = read_env_var("RUST_LOG", "INFO".to_string());
        let log_level = LevelFilter::from_str(&log_level).unwrap_or(LevelFilter::Info);

        let mut log_file_path = PathBuf::from(output_dir.clone());
        log_file_path.push("log.txt");
        let log_file = FileAppender::builder().build(log_file_path).unwrap();

        let stderr = ConsoleAppender::builder().target(Target::Stderr).build();

        let config = Config::builder()
            .appenders([
                Appender::builder().build("log-file", Box::new(log_file)),
                Appender::builder().build("stderr", Box::new(stderr)),
            ])
            .build(
                Root::builder()
                    .appender("log-file")
                    .appender("stderr")
                    .build(log_level),
            )
            .unwrap();

        log4rs::init_config(config).unwrap();

        log::info!("git version {}", GIT_VERSION);
        log::info!("short git version {}", short_git_version());
    });

    output_dir
}

fn create_output_dir(id: &str) -> String {
    let mode = read_env_var("MODE", "multi".to_string());
    let output = read_env_var(
        "OUTPUT_DIR",
        format!(
            "{}_output_{}_{}",
            id,
            mode,
            Utc::now().format("%Y%m%d_%H%M%S")
        ),
    );

    let output_dir = PathBuf::from_str(&output).unwrap();
    fs::create_dir_all(output_dir).unwrap();

    output
}

pub fn param_path_for_degree(params_dir: &str, degree: u32) -> String {
    format!("{params_dir}/params{degree}")
}

pub fn gen_rng() -> impl Rng + Send {
    let seed = [0u8; 16];
    XorShiftRng::from_seed(seed)
}

pub fn short_git_version() -> String {
    let commit_version = GIT_VERSION.split('-').last().unwrap();

    // Check if use commit object as fallback.
    if commit_version.len() < 8 {
        commit_version.to_string()
    } else {
        commit_version[1..8].to_string()
    }
}
