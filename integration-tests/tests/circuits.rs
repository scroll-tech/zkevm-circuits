#![cfg(feature = "circuits")]

use bus_mapping::circuit_input_builder::BuilderClient;
use bus_mapping::operation::OperationContainer;
use halo2_proofs::dev::MockProver;
use integration_tests::{get_client, log_init, GenDataOutput};
use lazy_static::lazy_static;
use log::trace;
use zkevm_circuits::evm_circuit::witness::RwMap;
use zkevm_circuits::evm_circuit::{
    test::run_test_circuit_complete_fixed_table, witness::block_convert,
};
use zkevm_circuits::state_circuit::StateCircuit;
lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

async fn test_evm_circuit_block(block_num: u64) {
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli.gen_inputs(block_num).await.unwrap();

    println!("builder block {:#?}", builder.block);
    let block = block_convert(&builder.block, &builder.code_db);

    println!("block {:#?}", block);
    run_test_circuit_complete_fixed_table(block).expect("evm_circuit verification failed");
}

#[tokio::test]
async fn test_evm_circuit_block_transfer_0() {
    log_init();
    let block_num = GEN_DATA.blocks.get("Transfer 0").unwrap();
    test_evm_circuit_block(*block_num).await;
}

#[tokio::test]
async fn test_evm_circuit_block_deploy_greeter() {
    log_init();
    let block_num = GEN_DATA.blocks.get("Deploy Greeter").unwrap();
    test_evm_circuit_block(*block_num).await;
}


#[tokio::test]
async fn test_evm_circuit_block_greeter_calls() {
    log_init();
    let block_num = GEN_DATA.blocks.get("Contract call").unwrap();
    test_evm_circuit_block(*block_num).await;
}

#[tokio::test]
async fn test_evm_circuit_block_multiple_transfers_0() {
    log_init();
    let block_num = GEN_DATA.blocks.get("Multiple transfers 0").unwrap();
    test_evm_circuit_block(*block_num).await;
}

async fn test_state_circuit_block(block_num: u64) {
    use halo2_proofs::arithmetic::BaseExt;
    use pairing::bn256::Fr;

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

    const DEGREE: usize = 16;
    const MEMORY_ADDRESS_MAX: usize = 2000;
    const STACK_ADDRESS_MAX: usize = 1024;

    const RW_COUNTER_MAX: usize = 1 << DEGREE;
    const ROWS_MAX: usize = 1 << DEGREE;

    let rw_map = RwMap::from(&OperationContainer {
        memory: memory_ops,
        stack: stack_ops,
        storage: storage_ops,
        ..Default::default()
    });
    let circuit = StateCircuit::<
        Fr,
        true,
        RW_COUNTER_MAX,
        MEMORY_ADDRESS_MAX,
        STACK_ADDRESS_MAX,
        ROWS_MAX,
    >::new(Fr::rand(), &rw_map);

    use pairing::bn256::Fr as Fp;
    let prover = MockProver::<Fp>::run(DEGREE as u32, &circuit, vec![]).unwrap();
    prover.verify().expect("state_circuit verification failed");
}

#[tokio::test]
async fn test_state_circuit_block_transfer_0() {
    log_init();
    let block_num = GEN_DATA.blocks.get("Transfer 0").unwrap();
    test_state_circuit_block(*block_num).await;
}

#[tokio::test]
async fn test_state_circuit_block_deploy_greeter() {
    log_init();
    let block_num = GEN_DATA.blocks.get("Deploy Greeter").unwrap();
    test_state_circuit_block(*block_num).await;
}

#[tokio::test]
async fn test_state_circuit_block_multiple_transfers_0() {
    log_init();
    let block_num = GEN_DATA.blocks.get("Multiple transfers 0").unwrap();
    test_state_circuit_block(*block_num).await;
}
