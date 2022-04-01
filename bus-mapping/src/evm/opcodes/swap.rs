use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::{operation::RW, Error};
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
        state.push_stack_op(
            &mut exec_step,
            RW::READ,
            stack_b_position,
            stack_b_value_read,
        )?;
        let stack_a_value_read = geth_step.stack.last()?;
        let stack_a_position = geth_step.stack.last_filled();
        state.push_stack_op(
            &mut exec_step,
            RW::READ,
            stack_a_position,
            stack_a_value_read,
        )?;

        // Write a into b_position, write b into a_position
        state.push_stack_op(
            &mut exec_step,
            RW::WRITE,
            stack_b_position,
            stack_a_value_read,
        )?;
        state.push_stack_op(
            &mut exec_step,
            RW::WRITE,
            stack_a_position,
            stack_b_value_read,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod swap_tests {
    use super::*;
    use crate::evm::opcodes::test_util::TestCase;
    use crate::operation::StackOp;

    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, evm_types::StackAddress, Word};

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

        let test = TestCase::new_from_bytecode(code);

        // Generate steps corresponding to DUP1, DUP3, DUP5
        for (i, (op, a, b)) in [
            (OpcodeId::SWAP1, 6, 5),
            (OpcodeId::SWAP3, 5, 3),
            (OpcodeId::SWAP5, 3, 1),
        ]
        .iter()
        .enumerate()
        {
            let step = test.step_witness(*op, 0);

            let a_pos = StackAddress(1024 - 6);
            let b_pos = StackAddress(1024 - 5 + i * 2);
            let a_val = Word::from(*a);
            let b_val = Word::from(*b);

            assert_eq!(
                [0, 1, 2, 3]
                    .map(|idx| &step.rws.stack[idx])
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
