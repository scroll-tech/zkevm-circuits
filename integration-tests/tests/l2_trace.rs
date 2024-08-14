#![feature(lazy_cell)]
#![cfg(feature = "scroll")]

use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
    util::read_env_var,
};
use eth_types::l2_types::BlockTrace;
use integration_tests::log_init;
use std::fs::File;
use zkevm_circuits::witness;

fn test_circuit_input_builder_l2block(block_trace: BlockTrace) {
    let params = CircuitsParams {
        max_rws: 4_000_000,
        max_copy_rows: 0, // dynamic
        max_txs: read_env_var("MAX_TXS", 128),
        max_calldata: 2_000_000,
        max_inner_blocks: 64,
        max_bytecode: 3_000_000,
        max_mpt_rows: 2_000_000,
        max_poseidon_rows: 4_000_000,
        max_keccak_rows: 0,
        max_exp_steps: 100_000,
        max_evm_rows: 0,
        max_rlp_rows: 2_070_000,
        ..Default::default()
    };

    let mut builder = CircuitInputBuilder::new_from_l2_trace(params, block_trace, false)
        .expect("could not handle block tx");

    builder
        .finalize_building()
        .expect("could not finalize building block");

    log::trace!("CircuitInputBuilder: {:#?}", builder);

    let mut block = witness::block_convert(&builder.block, &builder.code_db).unwrap();
    block.apply_mpt_updates(&builder.mpt_init_state.unwrap());
}

#[test]
fn local_l2_trace() {
    log_init();
    let file_path = read_env_var("TRACE_FILE", "dump.json".to_string());
    let fd = File::open(file_path).unwrap();
    let trace: BlockTrace = serde_json::from_reader(fd).unwrap();

    test_circuit_input_builder_l2block(trace);
}
