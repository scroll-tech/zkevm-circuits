use super::Opcode;
use crate::{
    circuit_input_builder::{BlockHead, CircuitInputStateRef, ExecStep},
    Error,
};
use eth_types::{evm_types::OpcodeId, GethExecStep, ToWord, Word};

#[derive(Clone, Copy, Debug)]
pub(crate) struct GetBlockHeaderField<const OP: u8>;

trait BlockHeaderToField {
    fn handle(block_head: &BlockHead) -> Word;
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::COINBASE.as_u8() }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.coinbase.to_word()
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::TIMESTAMP.as_u8() }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.timestamp
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::NUMBER.as_u8() }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.number
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::DIFFICULTY.as_u8() }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.difficulty
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::GASLIMIT.as_u8() }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.gas_limit.into()
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::CHAINID.as_u8() }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.chain_id.into()
    }
}

impl BlockHeaderToField for GetBlockHeaderField<{ OpcodeId::BASEFEE.as_u8() }> {
    fn handle(block_head: &BlockHead) -> Word {
        block_head.base_fee
    }
}

impl<const OP: u8> Opcode for GetBlockHeaderField<OP>
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
        assert_eq!(output, geth_steps[1].stack.last()?);

        // Stack write of coinbase
        state.stack_push(&mut exec_step, output)?;

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
        let output = geth_steps[0].pc.0.into();
        assert_eq!(output, geth_steps[1].stack.last()?);
        state.stack_push(&mut exec_step, output)?;

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
        let output = state.call_ctx()?.memory.len().into();
        assert_eq!(output, geth_steps[1].stack.last()?);
        state.stack_push(&mut exec_step, output)?;

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
        let output = geth_steps[1].gas.0.into();
        assert_eq!(output, geth_steps[1].stack.last()?);
        state.stack_push(&mut exec_step, output)?;

        Ok(vec![exec_step])
    }
}
