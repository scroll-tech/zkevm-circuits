use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::SWAP*` `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Swap<const N: usize>;

impl<const N: usize> Opcode for Swap<N> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // Peek b and a
        let stack_b_value_read = geth_step.stack.nth_last(N)?;
        let stack_b_position = geth_step.stack.nth_last_filled(N);
        state.stack_read(&mut exec_step, stack_b_position, stack_b_value_read)?;

        let stack_a_value_read = geth_step.stack.last()?;
        let stack_a_position = geth_step.stack.last_filled();
        state.stack_read(&mut exec_step, stack_a_position, stack_a_value_read)?;

        // Write a into b_position, write b into a_position
        state.stack_write(&mut exec_step, stack_b_position, stack_a_value_read)?;
        state.stack_write(&mut exec_step, stack_a_position, stack_b_value_read)?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod swap_tests {
    use crate::{
        mock::BlockData,
        operation::{StackOp, RW},
    };
    use eth_types::{bytecode, evm_types::StackAddress, geth_types::GethData, Word};
    use itertools::Itertools;
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn swap_opcode_impl() {
        let code = bytecode! {
            PUSH1(0x1)
            PUSH1(0x2)
            PUSH1(0x3)
            PUSH1(0x4)
            PUSH1(0x5)
            PUSH1(0x6) // [1,2,3,4,5,6]
            SWAP1      // [1,2,3,4,6,5]
            SWAP3      // [1,2,5,4,6,3]
            SWAP5      // [3,2,5,4,6,1]
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

        // Generate steps corresponding to DUP1, DUP3, DUP5
        for (i, (a, b)) in [(6, 5), (5, 3), (3, 1)].iter().enumerate() {
            let step = builder.block.txs()[0]
                .steps()
                .iter()
                .filter(|step| step.exec_state.is_swap())
                .collect_vec()[i];

            let a_pos = StackAddress(1024 - 6);
            let b_pos = StackAddress(1024 - 5 + i * 2);
            let a_val = Word::from(*a);
            let b_val = Word::from(*b);

            assert_eq!(
                [0, 1, 2, 3]
                    .map(|idx| &builder.block.container.stack
                        [step.bus_mapping_instance[idx].as_usize()])
                    .map(|operation| (operation.rw(), operation.op())),
                [
                    (RW::READ, &StackOp::new(1, b_pos, b_val)),
                    (RW::READ, &StackOp::new(1, a_pos, a_val)),
                    (RW::WRITE, &StackOp::new(1, b_pos, a_val)),
                    (RW::WRITE, &StackOp::new(1, a_pos, b_val)),
                ]
            );
        }
    }
}
