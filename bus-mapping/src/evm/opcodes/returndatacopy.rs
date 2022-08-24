use crate::circuit_input_builder::CopyEvent;
use crate::circuit_input_builder::CopyStep;
use crate::circuit_input_builder::NumberOrHash;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::operation::MemoryOp;
use crate::operation::RW;
use crate::Error;
use eth_types::GethExecStep;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Returndatacopy;

impl Opcode for Returndatacopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        // TODO: complete `ExecStep` and circuit implementation
        let mut exec_step = state.new_step(&geth_steps[0])?;

        // reconstruction
        let geth_step = &geth_steps[0];
        let dest_offset = geth_step.stack.nth_last(0)?;
        let offset = geth_step.stack.nth_last(1)?;
        let size = geth_step.stack.nth_last(2)?;

        // can we reduce this clone?
        let return_data = state.call_ctx()?.return_data.clone();

        let call_id = state.call()?.call_id;
        let call_ctx = state.call_ctx_mut()?;
        let memory = &mut call_ctx.memory;
        let length = size.as_usize();
        if length != 0 {
            let mem_starts = dest_offset.as_usize();
            let mem_ends = mem_starts + length;
            let data_starts = offset.as_usize();
            let data_ends = data_starts + length;
            let minimal_length = dest_offset.as_usize() + length;
            if data_ends <= return_data.len() {
                memory.extend_at_least(minimal_length);
                memory[mem_starts..mem_ends].copy_from_slice(&return_data[data_starts..data_ends]);

                for i in 0..length {
                    state.push_op(
                        &mut exec_step,
                        RW::WRITE,
                        MemoryOp::new(
                            call_id,
                            (mem_starts + i).into(),
                            return_data[data_starts + i],
                        ),
                    );
                }
            } else {
                // if overflows this opcode would fails current context, so
                // there is no more steps.
                if !(geth_steps.len() == 1 || geth_steps[1].depth != geth_steps[0].depth) {
                    log::warn!("read return data overflow, step {:?}", geth_steps[0]);
                    memory.extend_at_least(minimal_length);
                    let mut return_data = return_data[data_starts..].to_vec();
                    return_data.resize(data_ends - data_starts, 0);
                    memory[mem_starts..mem_ends].copy_from_slice(&return_data);
                    // 
                    // for i in 0..length {
                    //     state.push_op(
                    //         &mut exec_step,
                    //         RW::WRITE,
                    //         MemoryOp::new(
                    //             call_id,
                    //             (mem_starts + i).into(),
                    //             return_data[data_starts + i],
                    //         ),
                    //     );
                    // }
                }
            }
        }
        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod return_tests {
    use crate::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, word};
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    #[test]
    fn test_ok() {
        // // deployed contract
        // PUSH1 0x20
        // PUSH1 0
        // PUSH1 0
        // CALLDATACOPY
        // PUSH1 0x20
        // PUSH1 0
        // RETURN
        //
        // bytecode: 0x6020600060003760206000F3
        //
        // // constructor
        // PUSH12 0x6020600060003760206000F3
        // PUSH1 0
        // MSTORE
        // PUSH1 0xC
        // PUSH1 0x14
        // RETURN
        //
        // bytecode: 0x6B6020600060003760206000F3600052600C6014F3
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL

            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0x40)
            RETURNDATACOPY

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
    }

    #[test]
    fn test_revert() {
        // // deployed contract
        // PUSH1 0x20
        // PUSH1 0
        // PUSH1 0
        // CALLDATACOPY
        // PUSH1 0x20
        // PUSH1 0
        // RETURN
        //
        // bytecode: 0x6020600060003760206000F3
        //
        // // constructor
        // PUSH12 0x6020600060003760206000F3
        // PUSH1 0
        // MSTORE
        // PUSH1 0xC
        // PUSH1 0x14
        // RETURN
        //
        // bytecode: 0x6B6020600060003760206000F3600052600C6014F3
        let code = bytecode! {
            PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
            PUSH1(0)
            MSTORE

            PUSH1 (0x15)
            PUSH1 (0xB)
            PUSH1 (0)
            CREATE

            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0x20)
            PUSH1 (0)
            PUSH1 (0)
            DUP6
            PUSH2 (0xFFFF)
            CALL

            PUSH1 (0x40)
            PUSH1 (0)
            PUSH1 (0x40)
            RETURNDATACOPY

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
    }
}
