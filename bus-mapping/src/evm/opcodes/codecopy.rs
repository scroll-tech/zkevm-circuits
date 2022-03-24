use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecState, ExecStep, StepAuxiliaryData},
    operation::RW,
    Error,
};
use eth_types::{Bytecode, GethExecStep};

use super::Opcode;

const MAX_COPY_BYTES: usize = 54;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Codecopy;

impl Opcode for Codecopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_steps = vec![gen_codecopy_step(state, geth_step)?];
        let memory_copy_steps = gen_memory_copy_steps(state, geth_steps)?;
        exec_steps.extend(memory_copy_steps);
        Ok(exec_steps)
    }
}

fn gen_codecopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;

    let memory_offset = geth_step.stack.nth_last(0)?;
    let code_offset = geth_step.stack.nth_last(1)?;
    let length = geth_step.stack.nth_last(2)?;

    // stack reads
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
        code_offset,
    )?;
    state.push_stack_op(
        &mut exec_step,
        RW::READ,
        geth_step.stack.nth_last_filled(2),
        length,
    )?;
    Ok(exec_step)
}

fn gen_memory_copy_step(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: usize,
    dst_addr: usize,
    src_addr_end: usize,
    bytes_left: usize,
    code: eth_types::Bytecode,
) -> Result<(), Error> {
    for idx in 0..std::cmp::min(bytes_left, MAX_COPY_BYTES) {
        let addr = src_addr + idx;
        let byte = if addr < src_addr_end {
            code.code()[addr]
        } else {
            0
        };
        state.push_memory_op(exec_step, RW::WRITE, (dst_addr + idx).into(), byte)?;
    }

    exec_step.aux_data = Some(StepAuxiliaryData::CopyCodeToMemory {
        src_addr: src_addr as u64,
        dst_addr: dst_addr as u64,
        bytes_left: bytes_left as u64,
        src_addr_end: src_addr_end as u64,
        code,
    });

    Ok(())
}

fn gen_memory_copy_steps(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let memory_offset = geth_steps[0].stack.nth_last(0)?.as_usize();
    let code_offset = geth_steps[0].stack.nth_last(1)?.as_usize();
    let length = geth_steps[0].stack.nth_last(2)?.as_usize();

    let code_hash = state.call()?.code_hash;
    let code = state.code_db.0.get(&code_hash).unwrap();
    let code = Bytecode::try_from(code.clone()).unwrap();
    let src_addr_end = code.code().len();

    let mut copied = 0;
    let mut steps = vec![];
    while copied < length {
        let mut exec_step = state.new_step(&geth_steps[1])?;
        exec_step.exec_state = ExecState::CopyCodeToMemory;
        gen_memory_copy_step(
            state,
            &mut exec_step,
            code_offset + copied,
            memory_offset + copied,
            src_addr_end,
            length - copied,
            code.clone(),
        )?;
        steps.push(exec_step);
        copied += MAX_COPY_BYTES;
    }

    Ok(steps)
}

#[cfg(test)]
mod codecopy_tests {
    use eth_types::{
        bytecode,
        evm_types::{MemoryAddress, OpcodeId, StackAddress},
        Word,
    };
    use mock::new_single_tx_trace_code;

    use crate::{
        mock::BlockData,
        operation::{MemoryOp, StackOp},
    };

    use super::*;

    #[test]
    fn codecopy_opcode_impl() {
        test_ok(0x00, 0x00, 0x40);
        test_ok(0x20, 0x40, 0xA0);
    }

    fn test_ok(memory_offset: usize, code_offset: usize, size: usize) {
        let code = bytecode! {
            PUSH32(size)
            PUSH32(code_offset)
            PUSH32(memory_offset)
            CODECOPY
            STOP
        };

        let block = BlockData::new_from_geth_data(new_single_tx_trace_code(&code).unwrap());

        let mut builder = block.new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CODECOPY))
            .unwrap();

        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1021), Word::from(memory_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1022), Word::from(code_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(1, StackAddress::from(1023), Word::from(size)),
                ),
            ]
        );
        assert_eq!(
            (0..size)
                .map(|idx| &builder.block.container.memory[idx])
                .map(|op| (op.rw(), op.op().clone()))
                .collect::<Vec<(RW, MemoryOp)>>(),
            (0..size)
                .map(|idx| {
                    (
                        RW::WRITE,
                        MemoryOp::new(
                            1,
                            MemoryAddress::from(memory_offset + idx),
                            if code_offset + idx < code.code().len() {
                                code.code()[code_offset + idx]
                            } else {
                                0
                            },
                        ),
                    )
                })
                .collect::<Vec<(RW, MemoryOp)>>(),
        );
    }
}
