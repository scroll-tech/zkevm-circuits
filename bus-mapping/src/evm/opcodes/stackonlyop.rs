use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to all the Stack only operations: take N words and return one.
/// The following cases exist in the EVM:
/// - N = 1: UnaryOpcode
/// - N = 2: BinaryOpcode
/// - N = 3: TernaryOpcode
#[derive(Debug, Copy, Clone)]
pub(crate) struct StackOnlyOpcode<
    const N_POP: usize,
    const N_PUSH: usize,
    const IS_ERR: bool = { false },
>;

impl<const N_POP: usize, const N_PUSH: usize, const IS_ERR: bool> Opcode
    for StackOnlyOpcode<N_POP, N_PUSH, IS_ERR>
{
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        // N_POP stack reads
        for i in 0..N_POP {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        // N_PUSH stack writes
        for i in 0..N_PUSH {
            state.stack_write(
                &mut exec_step,
                geth_steps[1].stack.nth_last_filled(N_PUSH - 1 - i),
                geth_steps[1].stack.nth_last(N_PUSH - 1 - i)?,
            )?;
        }

        if IS_ERR {
            let next_step = geth_steps.get(1);
            exec_step.error = state.get_step_err(geth_step, next_step).unwrap();

            state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
            state.handle_return(geth_step)?;
        }

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod stackonlyop_tests {
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        word, Bytecode, Word,
    };
    use itertools::Itertools;
    use mock::{
        test_ctx::{helpers::*, TestContext},
        MOCK_BASEFEE, MOCK_DIFFICULTY, MOCK_GASLIMIT,
    };
    use pretty_assertions::assert_eq;
    use std::ops::{BitOr, BitXor};

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
    fn sdiv_opcode_impl() {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::SDIV,
            bytecode! {
                PUSH1(0x80u64)
                PUSH1(0x60u64)
                SDIV
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(0x60)),
                StackOp::new(1, StackAddress(1023), Word::from(0x80)),
            ],
            vec![StackOp::new(
                1,
                StackAddress(1023),
                Word::from(0x60) / Word::from(0x80),
            )],
        );
    }

    #[test]
    fn mod_opcode_impl() {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::MOD,
            bytecode! {
                PUSH1(0x80u64)
                PUSH1(0x60u64)
                MOD
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(0x60)),
                StackOp::new(1, StackAddress(1023), Word::from(0x80)),
            ],
            vec![StackOp::new(
                1,
                StackAddress(1023),
                Word::from(0x60) % Word::from(0x80),
            )],
        );
    }

    #[test]
    fn smod_opcode_impl() {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::SMOD,
            bytecode! {
                PUSH1(0x80u64)
                PUSH1(0x60u64)
                SMOD
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(0x60)),
                StackOp::new(1, StackAddress(1023), Word::from(0x80)),
            ],
            vec![StackOp::new(
                1,
                StackAddress(1023),
                Word::from(0x60) % Word::from(0x80),
            )],
        );
    }

    fn lt_opcode_impl(a: usize, b: usize, result: usize) {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::LT,
            bytecode! {
                PUSH1(b)
                PUSH1(a)
                LT
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(a)),
                StackOp::new(1, StackAddress(1023), Word::from(b)),
            ],
            vec![StackOp::new(1, StackAddress(1023), Word::from(result))],
        );
    }

    #[test]
    fn test_lt_opcode() {
        lt_opcode_impl(0x01, 0x02, 0x01);
        lt_opcode_impl(0x01, 0x01, 0x00);
        lt_opcode_impl(0x02, 0x01, 0x00);
    }

    fn gt_opcode_impl(a: usize, b: usize, result: usize) {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::GT,
            bytecode! {
                PUSH1(b)
                PUSH1(a)
                GT
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(a)),
                StackOp::new(1, StackAddress(1023), Word::from(b)),
            ],
            vec![StackOp::new(1, StackAddress(1023), Word::from(result))],
        );
    }
    #[test]
    fn test_gt_opcode() {
        gt_opcode_impl(0x01, 0x02, 0x00);
        gt_opcode_impl(0x01, 0x01, 0x00);
        gt_opcode_impl(0x02, 0x01, 0x01);
    }

    fn slt_opcode_impl(a: usize, b: usize, result: usize) {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::SLT,
            bytecode! {
                PUSH1(b)
                PUSH1(a)
                SLT
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(a)),
                StackOp::new(1, StackAddress(1023), Word::from(b)),
            ],
            vec![StackOp::new(1, StackAddress(1023), Word::from(result))],
        );
    }

    #[test]
    fn test_slt_opcode() {
        slt_opcode_impl(0x01, 0x02, 0x01);
        slt_opcode_impl(0x01, 0x01, 0x00);
        slt_opcode_impl(0x02, 0x01, 0x00);
    }

    fn sgt_opcode_impl(a: usize, b: usize, result: usize) {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::SGT,
            bytecode! {
                PUSH1(b)
                PUSH1(a)
                SGT
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(a)),
                StackOp::new(1, StackAddress(1023), Word::from(b)),
            ],
            vec![StackOp::new(1, StackAddress(1023), Word::from(result))],
        );
    }
    #[test]
    fn test_sgt_opcode() {
        sgt_opcode_impl(0x01, 0x02, 0x00);
        sgt_opcode_impl(0x01, 0x01, 0x00);
        sgt_opcode_impl(0x02, 0x01, 0x01);
    }

    fn and_opcode_impl(a: usize, b: usize, result: usize) {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::AND,
            bytecode! {
                PUSH1(b)
                PUSH1(a)
                AND
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(a)),
                StackOp::new(1, StackAddress(1023), Word::from(b)),
            ],
            vec![StackOp::new(1, StackAddress(1023), Word::from(result))],
        );
    }
    #[test]
    fn test_and_operate() {
        and_opcode_impl(0x01, 0x01, 0x01);
        and_opcode_impl(0x01, 0x00, 0x00);
        and_opcode_impl(0x00, 0x00, 0x00);
    }

    fn or_opcode_impl(a: usize, b: usize, result: usize) {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::OR,
            bytecode! {
                PUSH1(b)
                PUSH1(a)
                OR
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(a)),
                StackOp::new(1, StackAddress(1023), Word::from(b)),
            ],
            vec![StackOp::new(1, StackAddress(1023), Word::from(result))],
        );
    }
    #[test]
    fn test_or_operate() {
        or_opcode_impl(0x01, 0x01, 0x01.bitor(0x01) as usize);
        or_opcode_impl(0x00, 0x01, 0x00.bitor(0x01) as usize);
        or_opcode_impl(0x00, 0x00, 0x00.bitor(0x00) as usize);
    }

    fn xor_opcode_impl(a: usize, b: usize, result: usize) {
        stack_only_opcode_impl::<2, 1>(
            OpcodeId::XOR,
            bytecode! {
                PUSH1(b)
                PUSH1(a)
                XOR
                STOP
            },
            vec![
                StackOp::new(1, StackAddress(1022), Word::from(a)),
                StackOp::new(1, StackAddress(1023), Word::from(b)),
            ],
            vec![StackOp::new(1, StackAddress(1023), Word::from(result))],
        );
    }
    #[test]
    fn test_xor_operate() {
        xor_opcode_impl(0x01, 0x01, 0x01.bitxor(0x01) as usize);
        xor_opcode_impl(0x01, 0x00, 0x00.bitxor(0x01) as usize);
        xor_opcode_impl(0x00, 0x00, 0x00.bitxor(0x00) as usize);
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
    fn difficulty_opcode_impl() {
        stack_only_opcode_impl::<0, 1>(
            OpcodeId::DIFFICULTY,
            bytecode! {
                DIFFICULTY
                STOP
            },
            vec![],
            vec![StackOp::new(1, StackAddress(1023), *MOCK_DIFFICULTY)],
        );
    }

    #[test]
    fn gas_limit_opcode_impl() {
        stack_only_opcode_impl::<0, 1>(
            OpcodeId::GASLIMIT,
            bytecode! {
                GASLIMIT
                STOP
            },
            vec![],
            vec![StackOp::new(1, StackAddress(1023), *MOCK_GASLIMIT)],
        );
    }

    #[test]
    fn basefee_opcode_impl() {
        stack_only_opcode_impl::<0, 1>(
            OpcodeId::BASEFEE,
            bytecode! {
                BASEFEE
                STOP
            },
            vec![],
            vec![StackOp::new(1, StackAddress(1023), *MOCK_BASEFEE)],
        );
    }
}
