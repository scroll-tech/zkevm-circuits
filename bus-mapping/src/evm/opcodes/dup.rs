use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
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
        state.stack_read(&mut exec_step, stack_position, stack_value_read)?;
        state.stack_write(
            &mut exec_step,
            geth_step.stack.last_filled().map(|a| a - 1),
            stack_value_read,
        )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod dup_tests {
    use crate::{
        mock::BlockData,
        operation::{StackOp, RW},
    };
    use eth_types::{bytecode, evm_types::StackAddress, geth_types::GethData, word};
    use itertools::Itertools;
    use mock::test_ctx::{helpers::*, TestContext};
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
        for (i, word) in [word!("0x3"), word!("0x2"), word!("0x1")]
            .iter()
            .enumerate()
        {
            let step = builder.block.txs()[0]
                .steps()
                .iter()
                .filter(|step| step.exec_state.is_dup())
                .collect_vec()[i];
            assert_eq!(
                [0, 1]
                    .map(|idx| &builder.block.container.stack
                        [step.bus_mapping_instance[idx].as_usize()])
                    .map(|operation| (operation.rw(), operation.op())),
                [
                    (
                        RW::READ,
                        &StackOp::new(1, StackAddress(1024 - 3 + i), *word)
                    ),
                    (
                        RW::WRITE,
                        &StackOp::new(1, StackAddress(1024 - 4 - i), *word)
                    )
                ]
            )
        }
    }
}
