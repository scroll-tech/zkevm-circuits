// TODO: migrate these over.

#[cfg(test)]
mod tests {
    use super::*;
    use bus_mapping::mock::BlockData;
    use bus_mapping::operation::{
        MemoryOp, Operation, OperationContainer, RWCounter, StackOp, StorageOp, RW,
    };
    use eth_types::{
        address, bytecode,
        evm_types::{MemoryAddress, StackAddress},
        geth_types::GethData,
        Word,
    };
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::dev::MockProver;
    use mock::TestContext;
    use pairing::bn256::Fr;

    macro_rules! test_state_circuit_ok {
        ($k:expr, $rw_counter_max:expr, $memory_rows_max:expr, $memory_address_max:expr, $stack_rows_max:expr, $stack_address_max:expr, $storage_rows_max:expr, $memory_ops:expr, $stack_ops:expr, $storage_ops:expr, $result:expr) => {{
            let rw_map = RwMap::from(&OperationContainer {
                memory: $memory_ops,
                stack: $stack_ops,
                storage: $storage_ops,
                ..Default::default()
            });
            let circuit = StateCircuit::<
                Fr,
                true,
                $rw_counter_max,
                $memory_address_max,
                $stack_address_max,
                { $memory_rows_max + $stack_rows_max + $storage_rows_max },
            >::new(Fr::rand(), &rw_map);

            let power_of_randomness: Vec<_> = (1..32)
                .map(|exp| {
                    vec![
                        circuit.randomness.pow(&[exp, 0, 0, 0]);
                        { $memory_rows_max + $stack_rows_max + $storage_rows_max } // I think this is the max offset?
                    ]
                })
                .collect();

            let prover = MockProver::<Fr>::run($k, &circuit, power_of_randomness).unwrap();
            let verify_result = prover.verify();
            assert!(verify_result.is_ok(), "verify err: {:#?}", verify_result);
        }};
    }

    macro_rules! test_state_circuit_error {
        ($k:expr, $rw_counter_max:expr, $memory_rows_max:expr, $memory_address_max:expr, $stack_rows_max:expr, $stack_address_max:expr, $storage_rows_max:expr, $memory_ops:expr, $stack_ops:expr, $storage_ops:expr) => {{
            let rw_map = RwMap::from(&OperationContainer {
                memory: $memory_ops,
                stack: $stack_ops,
                storage: $storage_ops,
                ..Default::default()
            });
            let circuit = StateCircuit::<
                Fr,
                false,
                $rw_counter_max,
                $memory_address_max,
                $stack_address_max,
                { $memory_rows_max + $stack_rows_max + $storage_rows_max },
            >::new(Fr::rand(), &rw_map);

            let power_of_randomness: Vec<_> = (1..32)
                .map(|exp| {
                    vec![
                        circuit.randomness.pow(&[exp, 0, 0, 0]);
                        { $memory_rows_max + $stack_rows_max + $storage_rows_max } // I think this is the max offset?
                    ]
                })
                .collect();

            let prover = MockProver::<Fr>::run($k, &circuit, power_of_randomness).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    #[test]
    fn state_circuit_simple() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        let memory_op_2 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );
        let memory_op_3 = Operation::new(
            RWCounter::from(87),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(1), Word::from(32)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(87),
            RW::READ,
            StackOp::new(1, StackAddress::from(1), Word::from(32)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(0),
            RW::WRITE,
            StorageOp::new(
                U256::from(100).to_address(),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(18),
            RW::WRITE,
            StorageOp::new(
                U256::from(100).to_address(),
                Word::from(0x40),
                Word::from(32),
                Word::from(32),
                1usize,
                Word::from(32),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(19),
            RW::WRITE,
            StorageOp::new(
                U256::from(100).to_address(),
                Word::from(0x40),
                Word::from(32),
                Word::from(32),
                1usize,
                Word::from(32),
            ),
        );

        test_state_circuit_ok!(
            17,
            2000,
            100,
            2,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2, memory_op_3],
            vec![stack_op_0, stack_op_1],
            vec![storage_op_0, storage_op_1, storage_op_2],
            Ok(())
        );
    }

    #[test]
    fn no_stack_padding() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        let memory_op_2 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );
        let memory_op_3 = Operation::new(
            RWCounter::from(87),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(1), Word::from(32)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(87),
            RW::READ,
            StackOp::new(1, StackAddress::from(1), Word::from(32)),
        );

        const STACK_ROWS_MAX: usize = 2;
        test_state_circuit_ok!(
            17,
            2000,
            100,
            STACK_ROWS_MAX,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2, memory_op_3],
            vec![stack_op_0, stack_op_1],
            vec![],
            Ok(())
        );
    }

    #[test]
    fn same_address_read() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 31),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            MemoryOp::new(
                1,
                MemoryAddress::from(0),
                32,
                /* This should fail as it not the same value as in previous
                 * write op */
            ),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(19),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(0), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(28),
            RW::READ,
            StackOp::new(
                1,
                StackAddress::from(0),
                Word::from(13),
                /* This should fail as it not the same value as in previous
                 * write op */
            ),
        );

        const MEMORY_ROWS_MAX: usize = 7;
        test_state_circuit_error!(
            17,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            100,
            1023,
            1000,
            vec![memory_op_0, memory_op_1],
            vec![stack_op_0, stack_op_1],
            vec![]
        );
    }

    #[test]
    fn first_write() {
        let stack_op_0 = Operation::new(
            RWCounter::from(28),
            RW::READ,
            StackOp::new(1, StackAddress::from(0), Word::from(13)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(17),
            RW::READ,
            StorageOp::new(
                /* Fails because the first storage op needs to be
                 * write. */
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(18),
            RW::READ,
            StorageOp::new(
                /* Fails because when storage key changes, the op
                 * needs to be write. */
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x41),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );

        let storage_op_2 = Operation::new(
            RWCounter::from(19),
            RW::READ,
            StorageOp::new(
                /* Fails because when address changes, the op
                 * needs to be write. */
                address!("0x0000000000000000000000000000000000000003"),
                Word::from(0x40),
                /* Intentionally different storage key as the last one in the previous ops to
                have two conditions met. */
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        test_state_circuit_error!(
            17,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            STORAGE_ROWS_MAX,
            1023,
            1000,
            vec![],
            vec![stack_op_0],
            vec![storage_op_0, storage_op_1, storage_op_2]
        );
    }

    #[test]
    fn max_values() {
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );
        let memory_op_2 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX + 1),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX), 32),
        );

        let memory_op_3 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX + 1), 32),
        );
        let memory_op_4 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(MEMORY_ADDRESS_MAX + 1), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX), Word::from(12)),
        );

        let stack_op_2 = Operation::new(
            RWCounter::from(17),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX + 1), Word::from(12)),
        );
        let stack_op_3 = Operation::new(
            RWCounter::from(RW_COUNTER_MAX + 1),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX + 1), Word::from(12)),
        );

        // Small MEMORY_MAX_ROWS is set to avoid having padded rows (all padded
        // rows would fail because of the address they would have - the
        // address of the last unused row)
        const MEMORY_ROWS_MAX: usize = 7;
        const STACK_ROWS_MAX: usize = 7;
        const STORAGE_ROWS_MAX: usize = 7;
        const RW_COUNTER_MAX: usize = 60000;
        const MEMORY_ADDRESS_MAX: usize = 100;
        const STACK_ADDRESS_MAX: usize = 1023;

        test_state_circuit_error!(
            18,
            RW_COUNTER_MAX,
            MEMORY_ROWS_MAX,
            MEMORY_ADDRESS_MAX,
            STACK_ROWS_MAX,
            STACK_ADDRESS_MAX,
            STORAGE_ROWS_MAX,
            vec![
                memory_op_0,
                memory_op_1,
                memory_op_2,
                memory_op_3,
                memory_op_4
            ],
            vec![stack_op_0, stack_op_1, stack_op_2, stack_op_3],
            vec![]
        );
    }

    #[test]
    fn max_values_first_row() {
        // first row of a target needs to be checked for address to be in range
        // too
        let memory_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            MemoryOp::new(
                1,
                MemoryAddress::from(MEMORY_ADDRESS_MAX + 1),
                // This address is not in the allowed range
                32,
            ),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(12),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX + 1), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(24),
            RW::READ,
            StackOp::new(1, StackAddress::from(STACK_ADDRESS_MAX + 1), Word::from(12)),
        );

        // Small MEMORY_MAX_ROWS is set to avoid having padded rows (all padded
        // rows would fail because of the address they would have - the
        // address of the last unused row)
        const MEMORY_ROWS_MAX: usize = 2;
        const STACK_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        const RW_COUNTER_MAX: usize = 60000;
        const MEMORY_ADDRESS_MAX: usize = 100;
        const STACK_ADDRESS_MAX: usize = 1023;

        test_state_circuit_error!(
            18,
            RW_COUNTER_MAX,
            MEMORY_ROWS_MAX,
            MEMORY_ADDRESS_MAX,
            STACK_ROWS_MAX,
            STACK_ADDRESS_MAX,
            STORAGE_ROWS_MAX,
            vec![memory_op_0],
            vec![stack_op_0, stack_op_1],
            vec![]
        );
    }

    #[test]
    fn non_monotone_rw_counter() {
        let memory_op_0 = Operation::new(
            RWCounter::from(1352),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(1255),
            RW::READ,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        // fails because it needs to be strictly monotone
        let memory_op_2 = Operation::new(
            RWCounter::from(1255),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(228),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(217),
            RW::READ,
            StackOp::new(1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_2 = Operation::new(
            RWCounter::from(217),
            RW::READ,
            StackOp::new(1, StackAddress::from(1), Word::from(12)),
        );

        let storage_op_0 = Operation::new(
            RWCounter::from(301),
            RW::WRITE,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(302),
            RW::READ,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(302),
            RW::READ,
            StorageOp::new(
                /*fails because the address and
                 * storage key are the same as in
                 * the previous row */
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_3 = Operation::new(
            RWCounter::from(297),
            RW::WRITE,
            StorageOp::new(
                // Global counter goes down, but it doesn't fail because
                // the storage key is not the same as in the previous row.
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x41),
                Word::from(32),
                Word::from(32),
                1usize,
                Word::from(32),
            ),
        );

        let storage_op_4 = Operation::new(
            RWCounter::from(296),
            RW::WRITE,
            StorageOp::new(
                // Global counter goes down, but it doesn't fail because the
                // address is not the same as in the previous row (while the
                // storage key is).
                address!("0x0000000000000000000000000000000000000002"),
                Word::from(0x41),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 100;
        const STACK_ROWS_MAX: usize = 100;
        test_state_circuit_error!(
            17,
            10000,
            MEMORY_ROWS_MAX,
            10000,
            STACK_ROWS_MAX,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2],
            vec![stack_op_0, stack_op_1, stack_op_2],
            vec![
                storage_op_0,
                storage_op_1,
                storage_op_2,
                storage_op_3,
                storage_op_4
            ]
        );
    }

    #[ignore = "disabled temporarily since we sort rws inside the assign method. FIXME later"]
    #[test]
    fn non_monotone_address() {
        let memory_op_0 = Operation::new(
            RWCounter::from(1352),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );
        let memory_op_1 = Operation::new(
            RWCounter::from(1255),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(1), 32),
        );

        // fails because it's not monotone
        let memory_op_2 = Operation::new(
            RWCounter::from(1255),
            RW::WRITE,
            MemoryOp::new(1, MemoryAddress::from(0), 32),
        );

        let stack_op_0 = Operation::new(
            RWCounter::from(228),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(0), Word::from(12)),
        );
        let stack_op_1 = Operation::new(
            RWCounter::from(229),
            RW::WRITE,
            StackOp::new(1, StackAddress::from(1), Word::from(12)),
        );
        let stack_op_2 = Operation::new(
            RWCounter::from(230),
            RW::WRITE,
            StackOp::new(
                1,
                StackAddress::from(0), /* this fails because the
                                        * address is not
                                        * monotone */
                Word::from(12),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 10;
        test_state_circuit_error!(
            18,
            10000,
            MEMORY_ROWS_MAX,
            10000,
            10,
            1023,
            1000,
            vec![memory_op_0, memory_op_1, memory_op_2],
            vec![stack_op_0, stack_op_1, stack_op_2],
            vec![]
        );
    }

    #[test]
    fn storage() {
        let storage_op_0 = Operation::new(
            RWCounter::from(18),
            RW::WRITE,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_1 = Operation::new(
            RWCounter::from(19),
            RW::READ,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(33), /* Fails because it is READ op
                                 * and not the same
                                 * value as in the previous
                                 * row. */
                Word::zero(),
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_2 = Operation::new(
            RWCounter::from(20),
            RW::WRITE,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::zero(), /* Fails because not the same
                               * as value in the previous row - note: this
                               * is WRITE. */
                1usize,
                Word::zero(),
            ),
        );
        let storage_op_3 = Operation::new(
            RWCounter::from(21),
            RW::READ,
            StorageOp::new(
                address!("0x0000000000000000000000000000000000000001"),
                Word::from(0x40),
                Word::from(32),
                Word::from(1), /* Fails because not the same
                                * as value_prev in the previous row - note:
                                * this is READ. */
                1usize,
                Word::from(1),
            ),
        );

        const MEMORY_ROWS_MAX: usize = 2;
        const STORAGE_ROWS_MAX: usize = 2;
        test_state_circuit_error!(
            17,
            2000,
            MEMORY_ROWS_MAX,
            1000,
            STORAGE_ROWS_MAX,
            1023,
            1000,
            vec![],
            vec![],
            vec![storage_op_0, storage_op_1, storage_op_2, storage_op_3]
        );
    }

    #[test]
    fn trace() {
        let bytecode = bytecode! {
            PUSH1(0x80)
            PUSH1(0x40)
            MSTORE
            PUSH1(0x40)
            MLOAD
            STOP
        };

        // Create a custom tx setting Gas to
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20))
                    .code(bytecode);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000000"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[1].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let stack_ops = builder.block.container.sorted_stack();
        let memory_ops = builder.block.container.sorted_memory();
        let storage_ops = builder.block.container.sorted_storage();

        test_state_circuit_ok!(
            17,
            2000,
            100,
            0x80,
            100,
            1023,
            1000,
            memory_ops,
            stack_ops,
            storage_ops,
            Ok(())
        );
    }
}
