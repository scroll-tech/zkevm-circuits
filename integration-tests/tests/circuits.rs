#![cfg(feature = "circuits")]

use bus_mapping::circuit_input_builder::BuilderClient;
use bus_mapping::operation::OperationContainer;
use eth_types::geth_types;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::{
    arithmetic::CurveAffine,
    dev::MockProver,
    halo2curves::{
        bn256::Fr,
        group::{Curve, Group},
    },
};
use integration_tests::{
    get_client, log_init, GenDataOutput, CHAIN_ID, END_BLOCK, START_BLOCK, TX_ID,
};
use lazy_static::lazy_static;
use log::trace;
use paste::paste;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::marker::PhantomData;
use zkevm_circuits::bytecode_circuit::dev::test_bytecode_circuit;
use zkevm_circuits::copy_circuit::dev::test_copy_circuit;
use zkevm_circuits::evm_circuit::test::TestCircuit;
use zkevm_circuits::evm_circuit::witness::RwMap;
use zkevm_circuits::evm_circuit::{test::run_test_circuit, witness::block_convert};
use zkevm_circuits::keccak_circuit::keccak_bit::multi_keccak;
use zkevm_circuits::state_circuit::StateCircuit;
use zkevm_circuits::tx_circuit::{sign_verify::SignVerifyChip, Secp256k1Affine, TxCircuit};
use zkevm_circuits::util::DEFAULT_RAND;

lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

#[tokio::test]
async fn test_mock_prove_tx() {
    log_init();
    let tx_id: &str = &TX_ID;
    log::info!("test evm circuit, tx: {}", tx_id);
    if tx_id.is_empty() {
        return;
    }
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli.gen_inputs_tx(tx_id).await.unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db);
    run_test_circuit(block).unwrap();
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

#[tokio::test]
async fn test_print_circuits_size() {
    log_init();
    let start: usize = *START_BLOCK;
    let end: usize = *END_BLOCK;
    for block_num in start..=end {
        log::info!("test circuits size, block number: {}", block_num);
        let cli = get_client();
        let cli = BuilderClient::new(cli).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num as u64).await.unwrap();

        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            return;
        }

        let block = block_convert(&builder.block, &builder.code_db);
        let evm_rows = TestCircuit::get_num_rows_required(&block);
        let keccak_inputs = builder.keccak_inputs().unwrap();
        let keccak_rows = multi_keccak(&keccak_inputs, Fr::from_u128(DEFAULT_RAND)).len();
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
    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli
        .gen_inputs_multi_blocks(start as u64, end as u64 + 1)
        .await
        .unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db);
    log::info!("tx num: {}", builder.block.txs.len());
    run_test_circuit(block).unwrap();
    log::info!("prove done");
}

async fn test_evm_circuit_block(block_num: u64) {
    log::info!("test evm circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();

    if builder.block.txs.is_empty() {
        log::info!("skip empty block");
        return;
    }

    let block = block_convert(&builder.block, &builder.code_db);
    let result = run_test_circuit(block);
    log::info!(
        "test evm circuit, block number: {} result {:?}",
        block_num,
        result
    );
}

async fn test_state_circuit_block(block_num: u64) {
    log::info!("test state circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();

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

    let randomness = Fr::from(0xcafeu64);
    let circuit = StateCircuit::<Fr>::new(randomness, rw_map, 1 << 16);
    let power_of_randomness = circuit.instance();

    let prover = MockProver::<Fr>::run(DEGREE as u32, &circuit, power_of_randomness).unwrap();
    prover.verify().expect("state_circuit verification failed");
}

async fn test_tx_circuit_block(block_num: u64) {
    const DEGREE: u32 = 20;

    log::info!("test tx circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();

    let (_, eth_block) = cli.gen_inputs(block_num).await.unwrap();
    let txs: Vec<_> = eth_block
        .transactions
        .iter()
        .map(geth_types::Transaction::from)
        .collect();

    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();

    let circuit = TxCircuit::<Fr, 4, { 4 * (4 + 32 + 32) }> {
        sign_verify: SignVerifyChip {
            aux_generator,
            window_size: 2,
            _marker: PhantomData,
        },
        txs,
        chain_id: CHAIN_ID,
    };

    let prover = MockProver::run(DEGREE, &circuit, vec![vec![]]).unwrap();

    prover.verify().expect("tx_circuit verification failed");
}

pub async fn test_bytecode_circuit_block(block_num: u64) {
    const DEGREE: u32 = 16;

    log::info!("test bytecode circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    let bytecodes: Vec<Vec<u8>> = builder.code_db.0.values().cloned().collect();

    test_bytecode_circuit::<Fr>(DEGREE, bytecodes);
}

pub async fn test_copy_circuit_block(block_num: u64) {
    const DEGREE: u32 = 16;

    log::info!("test copy circuit, block number: {}", block_num);
    let cli = get_client();
    let cli = BuilderClient::new(cli).await.unwrap();
    let (builder, _) = cli.gen_inputs(block_num).await.unwrap();
    let block = block_convert(&builder.block, &builder.code_db);

    assert!(test_copy_circuit(DEGREE, block).is_ok());
}

macro_rules! declare_tests {
    ($name:ident, $block_tag:expr) => {
        paste! {
            #[tokio::test]
            async fn [<serial_test_evm_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_evm_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_state_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_state_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_tx_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_tx_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_bytecode_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_bytecode_circuit_block(*block_num).await;
            }

            #[tokio::test]
            async fn [<serial_test_copy_ $name>]() {
                log_init();
                let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
                test_copy_circuit_block(*block_num).await;
            }

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
    circuit_erc20_openzeppelin_transfer_fail,
    "ERC20 OpenZeppelin transfer failed"
);
declare_tests!(
    circuit_erc20_openzeppelin_transfer_succeed,
    "ERC20 OpenZeppelin transfer successful"
);
declare_tests!(
    circuit_multiple_erc20_openzeppelin_transfers,
    "Multiple ERC20 OpenZeppelin transfers"
);
