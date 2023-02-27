use bus_mapping::circuit_input_builder::{keccak_inputs, BuilderClient, CircuitsParams};
use bus_mapping::Error::JSONRpcError;
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::dev::VerifyFailure;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::Circuit;
use integration_tests::{get_client, log_init};
use integration_tests::{CIRCUIT, END_BLOCK, START_BLOCK, TX_ID};
use zkevm_circuits::evm_circuit::witness::block_convert;
use zkevm_circuits::evm_circuit::EvmCircuit;
use zkevm_circuits::keccak_circuit::keccak_packed_multi::multi_keccak;
use zkevm_circuits::rlp_circuit::RlpCircuit;
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::TxCircuit;
use zkevm_circuits::util::{Challenges, SubCircuit};
use zkevm_circuits::witness;
use zkevm_circuits::witness::SignedTransaction;

const CIRCUITS_PARAMS: CircuitsParams = CircuitsParams {
    max_rws: 30000,
    max_copy_rows: 30000,
    max_txs: 20,
    max_calldata: 30000,
    max_inner_blocks: 64,
    max_bytecode: 30000,
    keccak_padding: None,
    max_exp_steps: 1000,
    max_evm_rows: 0,
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
        max_inner_blocks: 64,
        max_bytecode: 40000,
        keccak_padding: None,
        max_exp_steps: 5000,
        max_evm_rows: 0,
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
    let k = block.get_test_degree();
    log::debug!("{} circuit needs k = {}", *CIRCUIT, k);
    debug_assert!(k <= 22);
    let circuit = C::new_from_block(block);
    MockProver::<Fr>::run(k, &circuit, circuit.instance()).unwrap()
}
fn test_witness_block(block: &witness::Block<Fr>) -> Vec<VerifyFailure> {
    let prover = if *CIRCUIT == "evm" {
        test_with::<EvmCircuit<Fr>>(block)
    } else if *CIRCUIT == "rlp" {
        test_with::<RlpCircuit<Fr, SignedTransaction>>(block)
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
            max_copy_rows: 4_000_000,
            max_txs: 350,
            max_calldata: 2_000_000,
            max_inner_blocks: 64,
            max_bytecode: 3_000_000,
            keccak_padding: None,
            max_exp_steps: 100_000,
            max_evm_rows: 0,
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
            return;
        }

        let block = block_convert(&builder.block, &builder.code_db).unwrap();
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
