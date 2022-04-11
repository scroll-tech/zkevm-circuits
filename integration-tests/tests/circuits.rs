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

    let block = block_convert(&builder.block, &builder.code_db);
    run_test_circuit_complete_fixed_table(block).expect("evm_circuit verification failed");
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

    const DEGREE: usize = 17;

    let rw_map = RwMap::from(&OperationContainer {
        memory: memory_ops,
        stack: stack_ops,
        storage: storage_ops,
        ..Default::default()
    });

    let randomness = Fr::rand();
    let circuit = StateCircuit::<Fr>::new(randomness, rw_map);
    let power_of_randomness = circuit.instance();

    use pairing::bn256::Fr as Fp;
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
