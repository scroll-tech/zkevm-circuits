use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{CallContextField, MemoryOp, RW},
    Error,
};
use eth_types::{GethExecStep, U256};

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Calldataload;

impl Opcode for Calldataload {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // fetch the top of the stack, i.e. offset in calldata to start reading 32-bytes
        // from.
        let offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), offset)?;

        // Check if offset is Uint64 overflow.
        let calldata_word = if let Ok(offset) = u64::try_from(offset) {
            let is_root = state.call()?.is_root;
            let call_id = state.call()?.call_id;
            if is_root {
                state.call_context_read(
                    &mut exec_step,
                    call_id,
                    CallContextField::TxId,
                    state.tx_ctx.id().into(),
                );
                state.call_context_read(
                    &mut exec_step,
                    call_id,
                    CallContextField::CallDataLength,
                    state.call()?.call_data_length.into(),
                );
            } else {
                state.call_context_read(
                    &mut exec_step,
                    call_id,
                    CallContextField::CallerId,
                    state.call()?.caller_id.into(),
                );
                state.call_context_read(
                    &mut exec_step,
                    call_id,
                    CallContextField::CallDataLength,
                    state.call()?.call_data_length.into(),
                );
                state.call_context_read(
                    &mut exec_step,
                    call_id,
                    CallContextField::CallDataOffset,
                    state.call()?.call_data_offset.into(),
                );
            }

            let call_data_offset = state.call()?.call_data_offset;
            let call_data_length = state.call()?.call_data_length;
            let (src_addr, src_addr_end, caller_id, call_data) = (
                // Set source start to the minimum value of offset and call data length for
                // avoiding overflow.
                call_data_offset + offset.min(call_data_length),
                call_data_offset + call_data_length,
                state.call()?.caller_id,
                state.call_ctx()?.call_data.to_vec(),
            );

            let calldata: Vec<_> = (0..32)
                .map(|idx| {
                    let addr = src_addr.checked_add(idx).unwrap_or(src_addr_end);
                    if addr < src_addr_end {
                        let byte = call_data[(addr - call_data_offset) as usize];
                        if !is_root {
                            state.push_op(
                                &mut exec_step,
                                RW::READ,
                                MemoryOp::new(caller_id, (src_addr + idx).into(), byte),
                            );
                        }
                        byte
                    } else {
                        0
                    }
                })
                .collect();

            U256::from_big_endian(&calldata)
        } else {
            // Stack push `0` as result directly if overflow.
            U256::zero()
        };

        state.stack_write(&mut exec_step, geth_step.stack.last_filled(), calldata_word)?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod calldataload_tests {
    use crate::operation::CallContextOp;
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        ToWord, Word,
    };
    use mock::{test_ctx::helpers::account_0_code_account_1_no_code, TestContext};
    use rand::random;

    use crate::{circuit_input_builder::ExecState, mock::BlockData, operation::StackOp};

    use super::*;

    fn rand_bytes(size: usize) -> Vec<u8> {
        (0..size).map(|_| random()).collect::<Vec<u8>>()
    }

    fn test_internal_ok(
        call_data_length: usize,
        call_data_offset: usize,
        offset: usize,
        pushdata: Vec<u8>,
        call_data_word: Word,
    ) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = bytecode! {
            PUSH32(offset)
            CALLDATALOAD
            STOP
        };

        let mut memory_a = std::iter::repeat(0)
            .take(32 - pushdata.len() - call_data_offset)
            .chain(pushdata.clone())
            .collect::<Vec<u8>>();
        if memory_a.len() < call_data_length {
            memory_a.resize(call_data_length, 0);
        }
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH32(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call addr_b
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH1(call_data_length) // argsLength
            PUSH1(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<3, 1>::new(
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
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLDATALOAD))
            .unwrap();

        let call_id = builder.block.txs()[0].calls()[step.call_index].call_id;
        let caller_id = builder.block.txs()[0].calls()[step.call_index].caller_id;

        // 1 stack read, 3 call context reads, 32 memory reads and 1 stack write.
        assert_eq!(step.bus_mapping_instance.len(), 37);

        // stack read and write.
        assert_eq!(
            [0, 36]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(call_id, StackAddress::from(1023), Word::from(offset)),
                ),
                (
                    RW::WRITE,
                    &StackOp::new(call_id, StackAddress::from(1023), call_data_word),
                ),
            ]
        );

        // call context reads.
        assert_eq!(
            [1, 2, 3]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &CallContextOp {
                        call_id,
                        field: CallContextField::CallerId,
                        value: Word::from(caller_id),
                    },
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id,
                        field: CallContextField::CallDataLength,
                        value: Word::from(call_data_length),
                    },
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id,
                        field: CallContextField::CallDataOffset,
                        value: Word::from(call_data_offset),
                    }
                ),
            ],
        );

        // 32 memory reads from caller memory
        assert_eq!(
            (0..32)
                .map(|idx| &builder.block.container.memory
                    [step.bus_mapping_instance[4 + idx].as_usize()])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            (0..32)
                .map(|idx| {
                    (
                        RW::READ,
                        MemoryOp::new(
                            caller_id,
                            (call_data_offset + offset + idx).into(),
                            memory_a[offset + idx],
                        ),
                    )
                })
                .collect::<Vec<(RW, MemoryOp)>>(),
        );
    }

    fn test_root_ok(offset: u64, calldata: Vec<u8>, calldata_word: Word) {
        let code = bytecode! {
            PUSH32(offset)
            CALLDATALOAD
            STOP
        };

        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .input(calldata.clone().into());
            },
            |block, _tx| block,
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLDATALOAD))
            .unwrap();

        let call_id = builder.block.txs()[0].calls()[0].call_id;

        // 1 stack read, 2 call context reads and 1 stack write.
        assert_eq!(step.bus_mapping_instance.len(), 4);

        // stack read and write.
        assert_eq!(
            [0, 3]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(call_id, StackAddress::from(1023), Word::from(offset)),
                ),
                (
                    RW::WRITE,
                    &StackOp::new(call_id, StackAddress::from(1023), calldata_word),
                ),
            ]
        );

        // call context reads.
        assert_eq!(
            [1, 2]
                .map(|idx| &builder.block.container.call_context
                    [step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &CallContextOp {
                        call_id,
                        field: CallContextField::TxId,
                        value: Word::from(1),
                    }
                ),
                (
                    RW::READ,
                    &CallContextOp {
                        call_id,
                        field: CallContextField::CallDataLength,
                        value: Word::from(calldata.len()),
                    },
                )
            ],
        );
    }

    #[test]
    fn calldataload_opcode_root() {
        // 1. should be right padded
        test_root_ok(0u64, vec![1u8, 2u8], {
            let mut v = vec![0u8; 32];
            v[0] = 1u8;
            v[1] = 2u8;
            Word::from_big_endian(&v)
        });

        // 2. exactly 32 bytes
        let calldata = rand_bytes(32);
        test_root_ok(0u64, calldata.clone(), Word::from_big_endian(&calldata));

        // 3. out-of-bounds: take only 32 bytes
        let calldata = rand_bytes(64);
        test_root_ok(
            12u64,
            calldata.clone(),
            Word::from_big_endian(&calldata[12..44]),
        );
    }

    #[test]
    fn calldataload_opcode_internal() {
        let pushdata = rand_bytes(0x08);
        let expected = std::iter::repeat(0)
            .take(0x20 - pushdata.len())
            .chain(pushdata.clone())
            .collect::<Vec<u8>>();
        test_internal_ok(
            0x20, // call data length
            0x00, // call data offset
            0x00, // offset
            pushdata,
            Word::from_big_endian(&expected),
        );

        let pushdata = rand_bytes(0x10);
        let mut expected = pushdata.clone();
        expected.resize(0x20, 0);
        test_internal_ok(0x20, 0x10, 0x00, pushdata, Word::from_big_endian(&expected));
    }
}
