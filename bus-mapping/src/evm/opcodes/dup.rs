use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::{operation::RW, Error};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the `OpcodeId::DUP*` `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Dup<const N: usize>;

impl<const N: usize> Opcode for Dup<N> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let stack_value_read = geth_step.stack.nth_last(N - 1)?;
        let stack_position = geth_step.stack.nth_last_filled(N - 1);
        state.push_stack_op(&mut exec_step, RW::READ, stack_position, stack_value_read)?;

        state.push_stack_op(
            &mut exec_step,
            RW::WRITE,
            geth_step.stack.last_filled().map(|a| a - 1),
            stack_value_read,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod dup_tests {
    use super::*;
    use crate::{evm::opcodes::test_util::TestCase, operation::StackOp};
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        word,
    };

    use pretty_assertions::assert_eq;

    #[test]
    fn dup_opcode_impl() {
        let code = bytecode! {
            PUSH1(0x1)
            PUSH1(0x2)
            PUSH1(0x3) // [1,2,3]
            DUP1       // [1,2,3,3]
            DUP3       // [1,2,3,3,2]
            DUP5       // [1,2,3,3,2,1]
            STOP
        };

        let test = TestCase::new_from_bytecode(code);

        // Generate steps corresponding to DUP1, DUP3, DUP5
        for (i, (op, value)) in [
            (OpcodeId::DUP1, word!("0x3")),
            (OpcodeId::DUP3, word!("0x2")),
            (OpcodeId::DUP5, word!("0x1")),
        ]
        .iter()
        .enumerate()
        {
            let step = test.step_witness(*op, 0);
            assert_eq!(
                [0, 1]
                    .map(|idx| &step.rws.stack[idx])
                    .map(|operation| (operation.rw(), operation.op())),
                [
                    (
                        RW::READ,
                        &StackOp::new(1, StackAddress(1024 - 3 + i), *value)
                    ),
                    (
                        RW::WRITE,
                        &StackOp::new(1, StackAddress(1024 - 4 - i), *value)
                    )
                ]
            )
        }
    }
}
