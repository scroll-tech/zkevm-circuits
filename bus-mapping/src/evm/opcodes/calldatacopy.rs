use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecState, ExecStep, StepAuxiliaryData};
use crate::operation::{CallContextField, CallContextOp, RW};
use crate::Error;
use eth_types::GethExecStep;

// The max number of bytes that can be copied in a step limited by the number
// of cells in a step
const MAX_COPY_BYTES: usize = 71;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Calldatacopy;

impl Opcode for Calldatacopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_calldatacopy_step(state, geth_step)?];
        let memory_copy_steps = gen_memory_copy_steps(state, geth_steps)?;
        exec_steps.extend(memory_copy_steps);
        Ok(exec_steps)
    }
}

fn gen_calldatacopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;
    let memory_offset = geth_step.stack.nth_last(0)?;
    let data_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?;

    state.push_stack_op(
        &mut exec_step,
        RW::READ,
        geth_step.stack.nth_last_filled(0),
        memory_offset,
    )?;
    state.push_stack_op(
        &mut exec_step,
        RW::READ,
        geth_step.stack.nth_last_filled(1),
        data_offset,
    )?;
    state.push_stack_op(
        &mut exec_step,
        RW::READ,
        geth_step.stack.nth_last_filled(2),
        length,
    )?;
    state.push_op(
        &mut exec_step,
        RW::READ,
        CallContextOp {
            call_id: state.call()?.call_id,
            field: CallContextField::TxId,
            value: state.tx_ctx.id().into(),
        },
    );

    if !state.call()?.is_root {
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CallDataLength,
                value: state.call()?.call_data_length.into(),
            },
        );
        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: state.call()?.call_id,
                field: CallContextField::CallDataOffset,
                value: state.call()?.call_data_offset.into(),
            },
        );
    };
    Ok(exec_step)
}

fn gen_memory_copy_step(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: u64,
    dst_addr: u64,
    src_addr_end: u64,
    bytes_left: usize,
    is_root: bool,
) -> Result<(), Error> {
    for idx in 0..std::cmp::min(bytes_left, MAX_COPY_BYTES) {
        let addr = src_addr + idx as u64;
        let byte = if addr < src_addr_end {
            if is_root {
                state.tx.input[addr as usize]
            } else {
                // TODO: read caller memory
                unimplemented!()
            }
        } else {
            0
        };
        state.push_memory_op(exec_step, RW::WRITE, (idx + dst_addr as usize).into(), byte)?;
    }

    exec_step.aux_data = Some(StepAuxiliaryData::CopyToMemory {
        src_addr,
        dst_addr,
        bytes_left: bytes_left as u64,
        src_addr_end,
        from_tx: is_root,
    });

    Ok(())
}

fn gen_memory_copy_steps(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let memory_offset = geth_steps[0].stack.nth_last(0)?.as_u64();
    let data_offset = geth_steps[0].stack.nth_last(1)?.as_u64();
    let length = geth_steps[0].stack.nth_last(2)?.as_usize();

    let call_data_offset = state.call()?.call_data_offset;
    let call_data_length = state.call()?.call_data_length;
    let (src_addr, buffer_addr_end) = (
        call_data_offset + data_offset,
        call_data_offset + call_data_length,
    );

    let mut copied = 0;
    let mut steps = vec![];
    while copied < length {
        let mut exec_step = state.new_step(&geth_steps[1])?;
        exec_step.exec_state = ExecState::CopyToMemory;
        gen_memory_copy_step(
            state,
            &mut exec_step,
            src_addr + copied as u64,
            memory_offset + copied as u64,
            buffer_addr_end,
            length - copied,
            state.call()?.is_root,
        )?;
        steps.push(exec_step);
        copied += MAX_COPY_BYTES;
    }

    Ok(steps)
}

#[cfg(test)]
mod calldatacopy_tests {
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        Word,
    };

    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn calldatacopy_opcode_impl() {
        let code = bytecode! {
            PUSH32(0)
            PUSH32(0)
            PUSH32(0x40)
            CALLDATACOPY
            STOP
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLDATACOPY))
            .unwrap();

        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|operation| (operation.rw(), operation.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1021), Word::from(0x40))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022), Word::from(0))
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(0))
                ),
            ]
        );

        assert_eq!(
            {
                let operation =
                    &builder.block.container.call_context[step.bus_mapping_instance[3].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id: builder.block.txs()[0].calls()[0].call_id,
                    field: CallContextField::TxId,
                    value: Word::from(1),
                }
            )
        );
    }
}
