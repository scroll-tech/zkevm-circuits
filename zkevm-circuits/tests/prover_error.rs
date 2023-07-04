// This file is intended to be used with fixtures generated from zkevm-chain.
// Copy the `errors/<block number>` directory into the zkevm-circuits git root
// as `block` and run via `cargo test -p zkevm-circuits --features test
// prover_error -- --nocapture --ignored`. Change any constant variables like
// `MAX_TXS` to suit your needs.
use bus_mapping::{circuit_input_builder::CircuitsParams, mock::BlockData};
use env_logger::Env;
use eth_types::{
    geth_types::{Account, GethData},
    Block, Bytes, Error, Transaction, Word, H160, U256,
};
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use mock::test_ctx::{gen_geth_traces, LoggerConfig};
use serde_json::{from_value, Value};
use std::{collections::HashMap, fs::File, io::BufReader};
use zkevm_circuits::{super_circuit::SuperCircuit, util::SubCircuit, witness::block_convert};

#[derive(serde::Deserialize)]
struct MyAccount {
    pub nonce: u64,
    pub balance: Word,
    pub code: Bytes,
    pub storage: HashMap<Word, Word>,
}

fn load_json(path: &str) -> Value {
    let file = File::open(path).expect(path);
    let reader = BufReader::new(file);
    let output: Value = serde_json::from_reader(reader)
        .map_err(Error::SerdeError)
        .unwrap();
    output
}

#[test]
#[ignore]
fn prover_error() {
    // change any of these values to your needs
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 256;
    const MOCK_RANDOMNESS: u64 = 0x100;
    let k = 19;
    let chain_id = 99;
    let circuit_params = CircuitsParams {
        max_txs: MAX_TXS,
        max_calldata: MAX_CALLDATA,
        max_rws: 16388,
        ..Default::default()
    };

    env_logger::Builder::from_env(Env::default().default_filter_or("trace")).init();
    let eth_block = load_json("../block/block.json");
    let mut eth_block: Block<Transaction> = from_value(eth_block).unwrap();
    eth_block.base_fee_per_gas = Some(U256::zero());
    println!("block {eth_block:#?}");
    let history_hashes: Vec<U256> = {
        let hashes = load_json("../block/block_hashes.json");
        let mut hashes: Vec<U256> = from_value(hashes).unwrap();
        let block_num: usize = eth_block.number.unwrap().as_usize();

        if block_num < hashes.len() {
            hashes.drain((hashes.len() - block_num)..).collect()
        } else {
            hashes
        }
    };
    let mut accounts: Vec<Account> = vec![];
    {
        let state = load_json("../block/prestate.json");
        let state: HashMap<H160, MyAccount> = from_value(state[0]["result"].clone()).unwrap();
        for (address, acc) in state {
            let account = Account {
                address,
                nonce: acc.nonce.into(),
                balance: acc.balance,
                code: acc.code,
                storage: acc.storage,
            };
            accounts.push(account);
        }
    }
    let geth_traces = gen_geth_traces(
        chain_id,
        eth_block.clone(),
        accounts.clone(),
        Some(history_hashes.clone()),
        LoggerConfig::default(),
    )
    .expect("gen_geth_traces");
    let geth_data = GethData {
        chain_id,
        history_hashes,
        eth_block,
        geth_traces,
        accounts,
    };
    let mut builder = BlockData::new_from_geth_data_with_params(geth_data.clone(), circuit_params)
        .new_circuit_input_builder();
    builder
        .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
        .expect("handle_block");
    let block_witness = {
        let mut block = block_convert(&builder.block, &builder.code_db).expect("block_convert");
        block.randomness = Fr::from(MOCK_RANDOMNESS);
        block
    };
    let circuit = SuperCircuit::<Fr, MAX_TXS, MAX_CALLDATA, 64, MOCK_RANDOMNESS>::new_from_block(
        &block_witness,
    );
    let res = MockProver::run(k, &circuit, circuit.instance())
        .expect("MockProver::run")
        .verify_par();
    println!("MockProver: {res:#?}");
    res.expect("verify_par");
}
