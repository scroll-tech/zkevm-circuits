#[cfg(test)]
mod test {
    use zkevm_circuits::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{bytecode, Word};
    use mock::{
        generate_mock_call_bytecode,
        test_ctx::{helpers::*, TestContext},
        MockCallBytecodeParams,
    };

    fn test_root_ok(
        call_data_length: usize,
        length: usize,
        data_offset: Word,
        memory_offset: Word,
    ) {
        let bytecode = bytecode! {
            PUSH32(length)
            PUSH32(data_offset)
            PUSH32(memory_offset)
            #[start]
            CALLDATACOPY
            STOP
        };
        let call_data = rand_bytes(call_data_length);

        // Get the execution steps from the external tracer
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(bytecode),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .input(call_data.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_calldata: 600,
                ..CircuitsParams::default()
            })
            .run();
    }

    fn test_internal_ok(
        call_data_offset: usize,
        call_data_length: usize,
        length: usize,
        data_offset: Word,
        dst_offset: Word,
    ) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = bytecode! {
            .op_calldatacopy(dst_offset, data_offset, length)
            STOP
        };

        let code_a = generate_mock_call_bytecode(MockCallBytecodeParams {
            address: addr_b,
            pushdata: rand_bytes(32),
            call_data_length,
            call_data_offset,
            ..MockCallBytecodeParams::default()
        });

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn calldatacopy_gadget_simple() {
        test_root_ok(0x40, 10, 0x00.into(), 0x40.into());
        test_internal_ok(0x40, 0x40, 10, 0x10.into(), 0x00.into());
        test_internal_ok(0x40, 0x40, 10, 0x10.into(), 0xA0.into());
    }

    #[test]
    fn calldatacopy_gadget_large() {
        test_root_ok(0x204, 0x1, 0x102.into(), 0x101.into());
        test_root_ok(0x204, 0x101, 0x102.into(), 0x103.into());
        test_internal_ok(0x30, 0x204, 0x101, 0x102.into(), 0x103.into());
    }

    #[test]
    fn calldatacopy_gadget_out_of_bound() {
        test_root_ok(0x40, 40, 0x20.into(), 0x40.into());
        test_internal_ok(0x40, 0x20, 10, 0x28.into(), 0xA0.into());
    }

    #[test]
    fn calldatacopy_gadget_zero_length() {
        test_root_ok(0x40, 0, 0x00.into(), 0x40.into());
        test_internal_ok(0x40, 0x40, 0, 0x10.into(), 0xA0.into());
    }

    #[test]
    fn calldatacopy_gadget_data_offset_overflow() {
        test_root_ok(0x40, 10, Word::MAX, 0x40.into());
        test_internal_ok(0x40, 0x40, 10, Word::MAX, 0xA0.into());
    }

    #[test]
    fn calldatacopy_gadget_overflow_memory_offset_and_zero_length() {
        test_root_ok(0x40, 0, 0x40.into(), Word::MAX);
        test_internal_ok(0x40, 0x40, 0, 0x10.into(), Word::MAX);
    }
}
