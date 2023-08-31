use bus_mapping::{
    circuit_input_builder::{keccak_inputs, BuilderClient, CircuitsParams, PrecompileEcParams},
    Error::JSONRpcError,
};
use halo2_proofs::{
    circuit::Value,
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
    plonk::Circuit,
};
use integration_tests::{get_client, log_init, CIRCUIT, END_BLOCK, START_BLOCK, TX_ID};
use zkevm_circuits::{
    copy_circuit::CopyCircuit,
    evm_circuit::{witness::block_convert, EvmCircuit},
    keccak_circuit::keccak_packed_multi::multi_keccak,
    rlp_circuit_fsm::RlpCircuit,
    state_circuit::StateCircuit,
    super_circuit::SuperCircuit,
    tx_circuit::TestTxCircuit as TxCircuit,
    util::{Challenges, SubCircuit},
    witness,
    witness::Transaction,
};

const CIRCUITS_PARAMS: CircuitsParams = CircuitsParams {
    max_rws: 30000,
    max_copy_rows: 30000,
    max_txs: 20,
    max_calldata: 30000,
    max_inner_blocks: 64,
    max_bytecode: 30000,
    max_mpt_rows: 30000,
    max_keccak_rows: 0,
    max_poseidon_rows: 0,
    max_vertical_circuit_rows: 0,
    max_exp_steps: 1000,
    max_evm_rows: 0,
    max_rlp_rows: 33000,
    max_ec_ops: PrecompileEcParams {
        ec_add: 10,
        ec_mul: 10,
        ec_pairing: 4,
    },
};

#[tokio::test]
async fn test_mock_prove_tx() {
    log_init();
    let tx_id: &str = &TX_ID;
    log::info!("test {} circuit, tx: {}", *CIRCUIT, tx_id);
    if tx_id.is_empty() {
        return;
    }
    let cli = get_client();
    let params = CircuitsParams {
        max_rws: 100000,
        max_copy_rows: 100000,
        max_txs: 10,
        max_calldata: 40000,
        max_mpt_rows: 40000,
        max_inner_blocks: 64,
        max_bytecode: 40000,
        max_keccak_rows: 0,
        max_exp_steps: 5000,
        max_evm_rows: 0,
        max_rlp_rows: 42000,
        ..Default::default()
    };

    let cli = BuilderClient::new(cli, params).await.unwrap();
    let builder = cli.gen_inputs_tx(tx_id).await.unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    let errs = test_witness_block(&block);
    for err in &errs {
        log::error!("ERR: {}", err);
    }
    println!("err num: {}", errs.len());

    log::info!("prove done");
}

fn test_with<C: SubCircuit<Fr> + Circuit<Fr>>(block: &witness::Block<Fr>) -> MockProver<Fr> {
    let num_row = C::min_num_rows_block(block).1;
    let k = zkevm_circuits::util::log2_ceil(num_row + 256);
    let k = k.max(22);
    log::debug!("{} circuit needs k = {}", *CIRCUIT, k);
    //debug_assert!(k <= 22);
    let circuit = C::new_from_block(block);
    MockProver::<Fr>::run(k, &circuit, circuit.instance()).unwrap()
}
fn test_witness_block(block: &witness::Block<Fr>) -> Vec<VerifyFailure> {
    if *CIRCUIT == "none" {
        return Vec::new();
    }
    let prover = if *CIRCUIT == "evm" {
        test_with::<EvmCircuit<Fr>>(block)
    } else if *CIRCUIT == "copy" {
        test_with::<CopyCircuit<Fr>>(block)
    } else if *CIRCUIT == "rlp" {
        test_with::<RlpCircuit<Fr, Transaction>>(block)
    } else if *CIRCUIT == "tx" {
        test_with::<TxCircuit<Fr>>(block)
    } else if *CIRCUIT == "state" {
        test_with::<StateCircuit<Fr>>(block)
    } else if *CIRCUIT == "super" {
        test_with::<SuperCircuit<Fr, 350, 2_000_000, 64, 0x1000>>(block)
    } else {
        unimplemented!()
    };

    let result = prover.verify_par();
    result.err().unwrap_or_default()
}

#[tokio::test]
async fn test_circuit_all_block() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for blk in start..=end {
        let block_num = blk as u64;
        log::info!("test {} circuit, block number: {}", *CIRCUIT, block_num);
        let cli = get_client();
        let params = CircuitsParams {
            max_rws: 4_000_000,
            max_copy_rows: 0, // dynamic
            max_txs: 350,
            max_calldata: 2_000_000,
            max_inner_blocks: 64,
            max_bytecode: 3_000_000,
            max_mpt_rows: 2_000_000,
            max_keccak_rows: 0,
            max_exp_steps: 100_000,
            max_evm_rows: 0,
            max_rlp_rows: 2_070_000,
            ..Default::default()
        };
        let cli = BuilderClient::new(cli, params).await.unwrap();
        let builder = cli.gen_inputs(block_num).await;
        if builder.is_err() {
            let err = builder.err().unwrap();
            let err_msg = match err {
                JSONRpcError(_json_rpc_err) => "JSONRpcError".to_string(), // too long...
                _ => format!("{err:?}"),
            };
            log::error!("invalid builder {} {:?}, err num NA", block_num, err_msg);
            continue;
        }
        let builder = builder.unwrap().0;
        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            // skip empty block
            continue;
        }

        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        let errs = test_witness_block(&block);
        log::info!(
            "test {} circuit, block number: {} err num {:?}",
            *CIRCUIT,
            block_num,
            errs.len()
        );
        for err in errs {
            log::error!("circuit err: {}", err);
        }
    }
}
#[tokio::test]
async fn test_print_circuits_size() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for block_num in start..=end {
        log::info!("test circuits size, block number: {}", block_num);
        let cli = get_client();
        let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num as u64).await.unwrap();

        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            return;
        }

        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        let evm_rows = EvmCircuit::get_num_rows_required(&block);
        let keccak_inputs = keccak_inputs(&builder.block, &builder.code_db).unwrap();

        let challenges = Challenges::mock(
            Value::known(block.randomness),
            Value::known(block.randomness),
            Value::known(block.randomness),
        );
        let keccak_rows = multi_keccak(&keccak_inputs, challenges, None)
            .unwrap()
            .len();
        log::info!(
            "block number: {}, evm row {}, keccak row {}",
            block_num,
            evm_rows,
            keccak_rows
        );
    }
}

#[tokio::test]
async fn test_circuit_batch() {
    log_init();
    let start: usize = 1;
    let end: usize = 8;
    let cli = get_client();
    let cli = BuilderClient::new(cli, CIRCUITS_PARAMS).await.unwrap();
    let builder = cli
        .gen_inputs_multi_blocks(start as u64, end as u64 + 1)
        .await
        .unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
    log::info!("tx num: {}", builder.block.txs.len());
    let errs = test_witness_block(&block);
    log::info!(
        "test {} circuit, block number: [{},{}], err num {:?}",
        *CIRCUIT,
        start,
        end,
        errs.len()
    );
    for err in errs {
        log::error!("circuit err: {}", err);
    }
}
