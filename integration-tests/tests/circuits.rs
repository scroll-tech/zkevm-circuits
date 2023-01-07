use bus_mapping::circuit_input_builder::{keccak_inputs, BuilderClient, CircuitsParams};
use halo2_proofs::circuit::Value;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::bn256::Fr;
use integration_tests::{get_client, log_init};
use integration_tests::{CIRCUIT, END_BLOCK, START_BLOCK, TX_ID};
use zkevm_circuits::evm_circuit::EvmCircuit;
use zkevm_circuits::evm_circuit::{
    test::get_test_cicuit_from_block, test::get_test_degree, test::run_test_circuit,
    witness::block_convert,
};
use zkevm_circuits::keccak_circuit::keccak_packed_multi::multi_keccak;
use zkevm_circuits::rlp_circuit::RlpCircuit;
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::tx_circuit::TxCircuit;
use zkevm_circuits::util::{Challenges, SubCircuit};

const CIRCUITS_PARAMS: CircuitsParams = CircuitsParams {
    max_rws: 30000,
    max_txs: 20,
    max_calldata: 30000,
    max_bytecode: 30000,
    keccak_padding: None,
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
        max_txs: 10,
        max_calldata: 40000,
        max_bytecode: 40000,
        keccak_padding: None,
    };

    let cli = BuilderClient::new(cli, params).await.unwrap();
    let builder = cli.gen_inputs_tx(tx_id).await.unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    let prover = if *CIRCUIT == "evm" {
        let k = get_test_degree(&block);
        let circuit = get_test_cicuit_from_block(block);
        let instance = vec![];
        MockProver::<Fr>::run(k, &circuit, instance).unwrap()
    } else if *CIRCUIT == "rlp" {
        let k = 18;
        let circuit = RlpCircuit::new_from_block(&block);
        let instance = vec![];
        MockProver::<Fr>::run(k, &circuit, instance).unwrap()
    } else if *CIRCUIT == "state" {
        let k = 18;
        let circuit = StateCircuit::new_from_block(&block);
        let instance = vec![];
        MockProver::<Fr>::run(k, &circuit, instance).unwrap()
    } else {
        unimplemented!()
    };

    let result = prover.verify_par();
    let errs = result.err().unwrap_or_default();
    for err in &errs {
        log::error!("ERR: {}", err);
    }
    println!("err num: {}", errs.len());

    log::info!("prove done");
}

#[tokio::test]
async fn test_super_circuit_all_block() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for blk in start..=end {
        let block_num = blk as u64;
        log::info!("test super circuit, block number: {}", block_num);
        let cli = get_client();
        // target k = 19
        let params = CircuitsParams {
            max_rws: 4_000_000,
            max_txs: 500,
            max_calldata: 2_000_000,
            max_bytecode: 2_000_000,
            keccak_padding: None,
        };
        let cli = BuilderClient::new(cli, params).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num).await.unwrap();

        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            return;
        }

        let (k, circuit, instance) =
            SuperCircuit::<Fr, 500, 2_000_000, 2_000_000>::build_from_circuit_input_builder(
                &builder,
            )
            .unwrap();
        let prover = MockProver::<Fr>::run(k, &circuit, instance).unwrap();
        let result = prover.verify_par();
        let errs = result.err().unwrap_or_default();
        log::info!(
            "test super circuit, block number: {} err num {:?}",
            block_num,
            errs.len(),
        );
        for err in errs {
            log::error!("circuit err: {}", err);
        }
    }
}

#[tokio::test]
async fn test_tx_circuit_all_block() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for blk in start..=end {
        let block_num = blk as u64;
        log::info!("test tx circuit, block number: {}", block_num);
        let cli = get_client();
        let params = CircuitsParams {
            max_rws: 200_000,
            max_txs: 14, // so max_txs * num_rows_per_tx < 2**21
            max_calldata: 200_000,
            max_bytecode: 200_000,
            keccak_padding: None,
        };
        let cli = BuilderClient::new(cli, params).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num).await.unwrap();

        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            return;
        }

        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        let circuit = TxCircuit::<Fr>::new_from_block(&block);
        let k = 21;
        let prover = MockProver::<Fr>::run(k, &circuit, vec![vec![]]).unwrap();
        let result = prover.verify_par();
        log::info!(
            "test tx circuit, block number: {} result {:?}",
            block_num,
            result
        );
    }
}

#[tokio::test]
async fn test_evm_circuit_all_block() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for blk in start..=end {
        let block_num = blk as u64;
        log::info!("test evm circuit, block number: {}", block_num);
        let cli = get_client();
        let params = CircuitsParams {
            max_rws: 5_000_000,
            max_txs: 500,
            max_calldata: 400000,
            max_bytecode: 400000,
            keccak_padding: None,
        };
        let cli = BuilderClient::new(cli, params).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num).await.unwrap();

        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            return;
        }

        let result = run_test_circuit(block);
        log::info!(
            "test evm circuit, block number: {} result {:?}",
            block_num,
            result
        );
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

        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        let evm_rows = EvmCircuit::get_num_rows_required(&block);
        let keccak_inputs = keccak_inputs(&builder.block, &builder.code_db).unwrap();

        let challenges = Challenges::mock(
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
async fn test_evm_circuit_batch() {
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

    let block = block_convert(&builder.block, &builder.code_db).unwrap();
    log::info!("tx num: {}", builder.block.txs.len());
    run_test_circuit(block).unwrap();
    log::info!("prove done");
}
