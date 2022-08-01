#![cfg(feature = "circuits")]

use bus_mapping::circuit_input_builder::{BuilderClient, ExecState};
use bus_mapping::evm::OpcodeId;
use bus_mapping::operation::OperationContainer;
use halo2_proofs::dev::MockProver;
use halo2_proofs::pairing::bn256::Fr;
use integration_tests::{get_client, log_init, GenDataOutput, END_BLOCK, FAST, START_BLOCK, TX_ID};
use lazy_static::lazy_static;
use log::trace;
use strum::IntoEnumIterator;
use zkevm_circuits::evm_circuit::table::FixedTableTag;
use zkevm_circuits::evm_circuit::test::TestCircuit;
use zkevm_circuits::evm_circuit::witness::RwMap;
use zkevm_circuits::evm_circuit::{
    test::run_test_circuit_complete_fixed_table, test::run_test_circuit_incomplete_fixed_table,
    witness::block_convert,
};
use zkevm_circuits::state_circuit::StateCircuit;

lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

#[tokio::test]
async fn test_mock_prove_tx() {
    log_init();
    log::info!("test evm circuit, tx: {}", *TX_ID);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli.gen_inputs_tx(&TX_ID).await.unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db);
    let need_bitwise_lookup = builder.block.txs.iter().any(|tx| {
        tx.steps().iter().any(|step| {
            matches!(
                step.exec_state,
                ExecState::Op(OpcodeId::AND)
                    | ExecState::Op(OpcodeId::OR)
                    | ExecState::Op(OpcodeId::XOR)
            )
        })
    });

    let fixed_table_tags = FixedTableTag::iter()
        .filter(|t| {
            need_bitwise_lookup
                || !matches!(
                    t,
                    FixedTableTag::BitwiseAnd
                        | FixedTableTag::BitwiseOr
                        | FixedTableTag::BitwiseXor
                )
        })
        .collect();
    let (active_gate_rows, active_lookup_rows) = TestCircuit::get_active_rows(&block);

    let circuit = TestCircuit::<Fr>::new(block, fixed_table_tags);
    let k = circuit.estimate_k();
    let prover = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();
    if *FAST {
        prover
            .verify_at_rows_par(active_gate_rows.into_iter(), active_lookup_rows.into_iter())
            .unwrap();
    } else {
        prover.verify_par().unwrap();
    }
    log::info!("prove done");
}

#[tokio::test]
async fn test_evm_circuit_all_block() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for blk in start..=end {
        test_evm_circuit_block(blk as u64).await;
    }
}

async fn test_evm_circuit_block(block_num: u64) {
    log::info!("test evm circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli.gen_inputs(block_num).await.unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db);
    let need_bitwise_lookup = builder.block.txs.iter().any(|tx| {
        tx.steps().iter().any(|step| {
            matches!(
                step.exec_state,
                ExecState::Op(OpcodeId::AND)
                    | ExecState::Op(OpcodeId::OR)
                    | ExecState::Op(OpcodeId::XOR)
            )
        })
    });
    let result = if need_bitwise_lookup {
        run_test_circuit_complete_fixed_table(block)
    } else {
        run_test_circuit_incomplete_fixed_table(block)
    };
    log::info!(
        "test evm circuit, block number: {} result {:?}",
        block_num,
        result
    );
}

async fn test_state_circuit_block(block_num: u64) {
    use halo2_proofs::arithmetic::BaseExt;

    log::info!("test state circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli.gen_inputs(block_num).await.unwrap();

    // Generate state proof
    let stack_ops = builder.block.container.sorted_stack();
    trace!("stack_ops: {:#?}", stack_ops);
    let memory_ops = builder.block.container.sorted_memory();
    trace!("memory_ops: {:#?}", memory_ops);
    let storage_ops = builder.block.container.sorted_storage();
    trace!("storage_ops: {:#?}", storage_ops);

    const DEGREE: usize = 17;

    let rw_map = RwMap::from(&OperationContainer {
        memory: memory_ops,
        stack: stack_ops,
        //storage: storage_ops,
        ..Default::default()
    });

    let randomness = Fr::rand();
    let circuit = StateCircuit::<Fr>::new(randomness, rw_map, 1 << 16);
    let power_of_randomness = circuit.instance();

    use halo2_proofs::pairing::bn256::Fr as Fp;
    let prover = MockProver::<Fp>::run(DEGREE as u32, &circuit, power_of_randomness).unwrap();
    prover.verify().expect("state_circuit verification failed");
}

macro_rules! declare_tests {
    ($test_evm_name:ident, $test_state_name:ident, $block_tag:expr) => {
        #[tokio::test]
        async fn $test_evm_name() {
            log_init();
            let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
            test_evm_circuit_block(*block_num).await;
        }

        #[tokio::test]
        async fn $test_state_name() {
            log_init();
            let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
            test_state_circuit_block(*block_num).await;
        }
    };
}

/*
declare_tests!(
    test_evm_circuit_block_transfer_0,
    test_state_circuit_block_transfer_0,
    "Transfer 0"
);
declare_tests!(
    test_evm_circuit_deploy_greeter,
    test_state_circuit_deploy_greeter,
    "Deploy Greeter"
);
declare_tests!(
    test_evm_circuit_multiple_transfers_0,
    test_state_circuit_multiple_transfers_0,
    "Multiple transfers 0"
);
*/
declare_tests!(
    test_evm_circuit_erc20_openzeppelin_transfer_fail,
    test_state_circuit_erc20_openzeppelin_transfer_fail,
    "ERC20 OpenZeppelin transfer failed"
);
declare_tests!(
    test_evm_circuit_erc20_openzeppelin_transfer_succeed,
    test_state_circuit_erc20_openzeppelin_transfer_succeed,
    "ERC20 OpenZeppelin transfer successful"
);
declare_tests!(
    test_evm_circuit_multiple_erc20_openzeppelin_transfers,
    test_state_circuit_multiple_erc20_openzeppelin_transfers,
    "Multiple ERC20 OpenZeppelin transfers"
);
