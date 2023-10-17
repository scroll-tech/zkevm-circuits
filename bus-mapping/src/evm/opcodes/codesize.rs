use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};

use eth_types::GethExecStep;

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Codesize;

impl Opcode for Codesize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let code_hash = state.call()?.code_hash;
        let code = state.code(code_hash)?;
        let codesize = code.len();

        #[cfg(feature = "enable-stack")]
        assert_eq!(codesize, geth_steps[1].stack.last()?.as_usize());
        state.stack_push(&mut exec_step, codesize.into())?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod codesize_tests {
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
        Word,
    };
    use mock::{
        test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
        TestContext,
    };

    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{StackOp, RW},
    };

    fn test_ok(large: bool) {
        let mut code = bytecode! {};
        let mut st_addr = 1023;
        if large {
            for _ in 0..128 {
                code.push(1, Word::from(0));
            }
            st_addr -= 128;
        }
        let tail = bytecode! {
            CODESIZE
            STOP
        };
        code.append(&tail);
        let codesize = code.to_vec().len();

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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CODESIZE))
            .unwrap();

        assert_eq!(step.bus_mapping_instance.len(), 1);

        let op = &builder.block.container.stack[step.bus_mapping_instance[0].as_usize()];
        assert_eq!(op.rw(), RW::WRITE);
        assert_eq!(
            op.op(),
            &StackOp::new(1, StackAddress::from(st_addr), Word::from(codesize))
        );
    }

    #[test]
    fn codesize_opcode_impl() {
        test_ok(false);
        test_ok(true);
    }
}
