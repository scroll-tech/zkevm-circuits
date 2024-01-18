use super::Opcode;
use crate::{
    circuit_input_builder::{BlockHead, CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::{evm_types::OpcodeId, GethExecStep, ToWord, Word, U256};

#[derive(Clone, Copy, Debug)]
pub(crate) struct GetBlockHeaderField<const OP: OpcodeId>;

trait BlockHeaderToField {
    fn handle(block_head: &BlockHead) -> Word;
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::COINBASE }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.coinbase.to_word()
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::TIMESTAMP }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.timestamp
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::NUMBER }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.number
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::DIFFICULTY }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.difficulty
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::GASLIMIT }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.gas_limit.into()
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::CHAINID }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.chain_id.into()
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::BASEFEE }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.base_fee
    }
}

impl<const OP: OpcodeId> Opcode for GetBlockHeaderField<OP>
where
    Self: BlockHeaderToField,
{
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let block_head = state.block.headers.get(&state.tx.block_num).unwrap();
        let output = Self::handle(block_head);

        state.stack_write(&mut exec_step, geth_steps[1].stack.last_filled(), output)?;
        assert_eq!(output, geth_steps[1].stack.last()?);

        Ok(vec![exec_step])
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Pc;

impl Opcode for Pc {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let mut exec_step = state.new_step(&geth_steps[0])?;
        let output: U256 = geth_steps[0].pc.0.into();

        state.stack_write(&mut exec_step, geth_steps[1].stack.last_filled(), output)?;
        assert_eq!(output, geth_steps[1].stack.last()?);

        Ok(vec![exec_step])
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Msize;

impl Opcode for Msize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let mut exec_step = state.new_step(&geth_steps[0])?;
        let output: U256 = state.call_ctx()?.memory.len().into();

        state.stack_write(&mut exec_step, geth_steps[1].stack.last_filled(), output)?;
        assert_eq!(output, geth_steps[1].stack.last()?);

        Ok(vec![exec_step])
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Gas;

impl Opcode for Gas {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let mut exec_step = state.new_step(&geth_steps[0])?;
        let output: U256 = geth_steps[1].gas.0.into();

        state.stack_write(&mut exec_step, geth_steps[1].stack.last_filled(), output)?;
        assert_eq!(output, geth_steps[1].stack.last()?);

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod tests {
    use crate::mock::BlockData;
    use eth_types::{bytecode, geth_types::GethData, Bytecode};
    use mock::TestContext;

    fn test_trace(code: Bytecode) {
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::simple_ctx_with_bytecode(code)
            .unwrap()
            .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    #[test]
    fn test_difficulty() {
        test_trace(bytecode! {
            DIFFICULTY
            STOP
        });
    }

    #[test]
    fn gas_limit_opcode_impl() {
        test_trace(bytecode! {
            GASLIMIT
            STOP
        });
    }

    #[test]
    fn basefee_opcode_impl() {
        test_trace(bytecode! {
            BASEFEE
            STOP
        });
    }
}
