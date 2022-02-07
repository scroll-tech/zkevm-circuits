use crate::{circuit_input_builder::CircuitInputStateRef, operation::RW, Error};
use eth_types::GethExecStep;

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Gas;

impl Opcode for Gas {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        next_steps: &[GethExecStep],
    ) -> Result<(), Error> {
        let step = &next_steps[0];
        // Get value result from next step and do stack write
        let value = next_steps[1].stack.last()?;
        state.push_stack_op(RW::WRITE, step.stack.last_filled().map(|a| a - 1), value);
        Ok(())
    }
}

#[cfg(test)]
mod gas_tests {
    use crate::{
        circuit_input_builder::{ExecStep, TransactionContext},
        evm::OpcodeId,
        mock::BlockData,
        operation::StackAddress,
    };
    use eth_types::{bytecode, bytecode::Bytecode, Word};
    use mock::new_single_tx_trace_code_at_start;

    use super::*;

    fn test_ok(code: Bytecode, gas_left: u64) -> Result<(), Error> {
        let block = BlockData::new_from_geth_data(new_single_tx_trace_code_at_start(&code)?);

        let mut builder = block.new_circuit_input_builder();
        builder.handle_tx(&block.eth_tx, &block.geth_trace)?;

        let mut test_builder = block.new_circuit_input_builder();
        let mut tx = test_builder.new_tx(&block.eth_tx)?;
        let mut tx_ctx = TransactionContext::new(&block.eth_tx);

        let mut step = ExecStep::new(
            &block.geth_trace.struct_logs[0],
            0,
            test_builder.block_ctx.rwc,
            0,
        );
        let mut state_ref = test_builder.state_ref(&mut tx, &mut tx_ctx, &mut step);

        state_ref.push_stack_op(RW::WRITE, StackAddress::from(1022), Word::from(gas_left));

        tx.steps_mut().push(step);
        test_builder.block.txs_mut().push(tx);

        assert_eq!(
            builder.block.txs()[0].steps()[0].bus_mapping_instance,
            test_builder.block.txs()[0].steps()[0].bus_mapping_instance,
        );

        assert_eq!(builder.block.container, test_builder.block.container);

        Ok(())
    }

    #[test]
    fn gas_opcode_impl() -> Result<(), Error> {
        const GAS_LIMIT: u64 = 1_000_000;

        const GAS_COST: u64 = OpcodeId::PUSH1.constant_gas_cost().as_u64()
            + OpcodeId::PUSH1.constant_gas_cost().as_u64()
            + OpcodeId::GAS.constant_gas_cost().as_u64();

        let test_scenarios: [(Bytecode, u64); 4] = [
            (
                bytecode! {
                    PUSH1(0x1)
                    PUSH1(0x1)
                    POP
                    #[start]
                    GAS
                    STOP
                },
                GAS_LIMIT.saturating_sub(
                    GAS_COST + OpcodeId::POP.constant_gas_cost().as_u64(),
                ),
            ),
            (
                bytecode! {
                    PUSH1(0x1)
                    PUSH1(0x1)
                    ADD
                    #[start]
                    GAS
                    STOP
                },
                GAS_LIMIT.saturating_sub(
                    GAS_COST + OpcodeId::ADD.constant_gas_cost().as_u64(),
                ),
            ),
            (
                bytecode! {
                    PUSH1(0x1)
                    PUSH1(0x1)
                    DIV
                    #[start]
                    GAS
                    STOP
                },
                GAS_LIMIT.saturating_sub(
                    GAS_COST + OpcodeId::DIV.constant_gas_cost().as_u64(),
                ),
            ),
            (
                bytecode! {
                    PUSH1(0x1)
                    PUSH1(0x1)
                    EXP
                    #[start]
                    GAS
                    STOP
                },
                GAS_LIMIT.saturating_sub(
                    GAS_COST
                        + OpcodeId::EXP.constant_gas_cost().as_u64()
                        + 50u64, // dynamic gas cost
                ),
            ),
        ];

        for t in test_scenarios {
            test_ok(t.0, t.1)?;
        }

        Ok(())
    }
}
