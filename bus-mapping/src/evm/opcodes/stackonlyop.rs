use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::{operation::RW, Error};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to all the Stack only operations: take N words and return one.
/// The following cases exist in the EVM:
/// - N = 1: UnaryOpcode
/// - N = 2: BinaryOpcode
/// - N = 3: TernaryOpcode
#[derive(Debug, Copy, Clone)]
pub(crate) struct StackOnlyOpcode<const N_POP: usize, const N_PUSH: usize>;

impl<const N_POP: usize, const N_PUSH: usize> Opcode for StackOnlyOpcode<N_POP, N_PUSH> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        // N_POP stack reads
        for i in 0..N_POP {
            state.push_stack_op(
                &mut exec_step,
                RW::READ,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        // N_PUSH stack writes
        for i in 0..N_PUSH {
            state.push_stack_op(
                &mut exec_step,
                RW::WRITE,
                geth_steps[1].stack.nth_last_filled(N_PUSH - 1 - i),
                geth_steps[1].stack.nth_last(N_PUSH - 1 - i)?,
            )?;
        }

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod stackonlyop_tests {
    use super::*;
    use crate::{circuit_input_builder::ExecState, mock::BlockData, operation::StackOp};
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        word, Bytecode, Word,
    };
    use itertools::Itertools;
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    fn stack_only_opcode_impl<const N_POP: usize, const N_PUSH: usize>(
        opcode: OpcodeId,
        code: Bytecode,
        pops: Vec<StackOp>,
        pushes: Vec<StackOp>,
    ) {
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
            .find(|step| step.exec_state == ExecState::Op(opcode))
            .unwrap();

        assert_eq!(
            (0..N_POP)
                .map(|idx| {
                    &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()]
                })
                .map(|operation| (operation.rw(), operation.op().clone()))
                .collect_vec(),
            pops.into_iter().map(|pop| (RW::READ, pop)).collect_vec()
        );
        assert_eq!(
            (0..N_PUSH)
                .map(|idx| {
                    &builder.block.container.stack
                        [step.bus_mapping_instance[N_POP + idx].as_usize()]
                })
                .map(|operation| (operation.rw(), operation.op().clone()))
                .collect_vec(),
            pushes
                .into_iter()
                .map(|push| (RW::WRITE, push))
                .collect_vec()
        );
    }

    #[test]
    fn not_opcode_impl() {
        stack_only_opcode_impl::<1, 1>(
            OpcodeId::NOT,
            bytecode! {
                PUSH32(word!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
                NOT
                STOP
            },
            vec![StackOp::new(
                1,
                StackAddress(1023),
                word!("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            )],
            vec![StackOp::new(
                1,
                StackAddress(1023),
                word!("0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
            )],
        );
    }

    #[test]
    fn add_opcode_impl() {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::ADD,
            bytecode! {
                PUSH1(0x80u64)
                PUSH1(0x60u64)
                ADD
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(0x60)),
                StackOp::new(1, StackAddress(1023), Word::from(0x80)),
            ],
            vec![StackOp::new(
                1,
                StackAddress(1023),
                Word::from(0x60) + Word::from(0x80),
            )],
        );
    }

    #[test]
    fn addmod_opcode_impl() {
        stack_only_opcode_impl::<3, 1>(
            OpcodeId::ADDMOD,
            bytecode! {
                PUSH3(0xbcdef)
                PUSH3(0x6789a)
                PUSH3(0x12345)
                ADDMOD
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1021), Word::from(0x12345)),
                StackOp::new(1, StackAddress(1022), Word::from(0x6789a)),
                StackOp::new(1, StackAddress(1023), Word::from(0xbcdef)),
            ],
            vec![StackOp::new(1, StackAddress(1023), Word::from(0x79bdf))],
        );
    }
}
