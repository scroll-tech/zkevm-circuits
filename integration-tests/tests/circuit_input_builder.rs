#![cfg(feature = "circuit_input_builder")]

use bus_mapping::circuit_input_builder::{
    build_state_code_db, get_state_accesses, BuilderClient, CircuitsParams,
};
use integration_tests::{get_client, log_init, GenDataOutput};
use lazy_static::lazy_static;
use log::trace;

lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

async fn test_circuit_input_builder_block(block_num: u64) {
    let cli = get_client();
    let cli = BuilderClient::new(
        cli,
        CircuitsParams {
            max_rws: 16384,
            max_txs: 1,
            max_calldata: 4000,
            max_inner_blocks: 64,
            max_bytecode: 4000,
            max_copy_rows: 16384,
            max_evm_rows: 0,
            max_exp_steps: 1000,
            max_keccak_rows: 0,
        },
    )
    .await
    .unwrap();

    // 1. Query geth for Block, Txs and TxExecTraces
    let (eth_block, geth_trace, history_hashes, prev_state_root) =
        cli.get_block(block_num).await.unwrap();

    // 2. Get State Accesses from TxExecTraces
    let access_set = get_state_accesses(&eth_block, &geth_trace).unwrap();
    trace!("AccessSet: {:#?}", access_set);

    // 3. Query geth for all accounts, storage keys, and codes from Accesses
    let (proofs, codes) = cli.get_state(block_num, access_set.into()).await.unwrap();

    // 4. Build a partial StateDB from step 3
    let (state_db, code_db) = build_state_code_db(proofs, codes);
    trace!("StateDB: {:#?}", state_db);

    // 5. For each step in TxExecTraces, gen the associated ops and state
    // circuit inputs
    let builder = cli
        .gen_inputs_from_state(
            state_db,
            code_db,
            &eth_block,
            &geth_trace,
            history_hashes,
            prev_state_root,
        )
        .unwrap();

    trace!("CircuitInputBuilder: {:#?}", builder);
}

macro_rules! declare_tests {
    ($test_name:ident, $block_tag:expr) => {
        #[tokio::test]
        async fn $test_name() {
            log_init();
            let block_num = GEN_DATA.blocks.get($block_tag).unwrap();
            test_circuit_input_builder_block(*block_num).await;
        }
    };
}

// This test builds the complete circuit inputs for the block where 1 ETH is
// transfered.
declare_tests!(test_circuit_input_builder_block_transfer_0, "Transfer 0");
// This test builds the complete circuit inputs for the block where the Greeter
// contract is deployed.
declare_tests!(test_circuit_input_builder_deploy_greeter, "Deploy Greeter");
// This test builds the complete circuit inputs for the block with multiple
// transfer txs.
declare_tests!(
    test_circuit_input_builder_multiple_transfers_0,
    "Multiple transfers 0"
);
// This test builds the complete circuit inputs for the block with a failed
// OpenZeppelin ERC20 transfer tx.
declare_tests!(
    test_circuit_input_builder_erc20_openzeppelin_transfer_fail,
    "ERC20 OpenZeppelin transfer failed"
);
// This test builds the complete circuit inputs for the block with a successful
// OpenZeppelin ERC20 transfer tx.
declare_tests!(
    test_circuit_input_builder_erc20_openzeppelin_transfer_succeed,
    "ERC20 OpenZeppelin transfer successful"
);
// This test builds the complete circuit inputs for the block with multiple
// successful and failed OpenZeppelin ERC20 transfer txs.
declare_tests!(
    test_circuit_input_builder_multiple_erc20_openzeppelin_transfers,
    "Multiple ERC20 OpenZeppelin transfers"
);
