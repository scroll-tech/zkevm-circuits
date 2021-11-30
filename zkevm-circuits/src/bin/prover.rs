use bus_mapping::bytecode;
use zkevm_circuits::evm_circuit::bus_mapping_tmp_convert;
use zkevm_circuits::evm_circuit::test::run_test_circuit_incomplete_fixed_table;
use zkevm_circuits::test_state_circuit;

fn test_bytecode(code: &bus_mapping::bytecode::Bytecode) {
    println!("Step0: fetch geth trace of bytecodes, and build `block` as circuit input");
    let t = std::time::Instant::now();
    let block =
        bus_mapping::mock::BlockData::new_single_tx_trace_code(&code).unwrap();
    let mut builder =
        bus_mapping::circuit_input_builder::CircuitInputBuilder::new(
            block.eth_block.clone(),
            block.block_ctants.clone(),
        );
    builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();
    println!("Construct block cost {:?}", t.elapsed());

    println!("Step1: mock prove state circuit");
    let t = std::time::Instant::now();
    let memory_ops = builder.block.container.sorted_memory();
    let stack_ops = builder.block.container.sorted_stack();
    let storage_ops = builder.block.container.sorted_storage();
    test_state_circuit!(
        14,   /* k */
        2000, /* global_counter_max */
        100,  /* memory_rows_max */
        2,    /* memory_address_max */
        100,  /* stack_rows_max */
        1023, /* stack_address_max */
        1000, /* storage_rows_max */
        memory_ops,
        stack_ops,
        storage_ops,
        Ok(())
    );
    println!("Cost of mock proving state circuit is {:?}", t.elapsed());

    println!("Step2: mock prove evm circuit");
    let t = std::time::Instant::now();
    let b = bus_mapping_tmp_convert::block_convert(&code, &builder.block);
    assert_eq!(run_test_circuit_incomplete_fixed_table(b), Ok(()));
    println!("Cost of mock proving evm circuit is {:?}", t.elapsed());
}

fn test_add() {
    let code = bytecode! {
        PUSH32(0x030201)
        PUSH32(0x060504)
        #[start]
        ADD
        STOP
    };
    test_bytecode(&code);
}

fn main() {
    test_add();
}
