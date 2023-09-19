use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{EVMConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::IsZeroGadget,
            rlc, select, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct PushGadget<F> {
    same_context: SameContextGadget<F>,
    is_push0: IsZeroGadget<F>,
    value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for PushGadget<F> {
    const NAME: &'static str = "PUSH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PUSH;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_push0 = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::PUSH0.expr());

        let value = cb.query_cell_phase2();
        cb.stack_push(value.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(opcode.expr() - (OpcodeId::PUSH0.as_u64() - 1).expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(select::expr(
                is_push0.expr(),
                -OpcodeId::PUSH0.constant_gas_cost().expr(),
                -OpcodeId::PUSH1.constant_gas_cost().expr(),
            )),
            ..Default::default()
        };
        let same_context =
            SameContextGadget::construct2(cb, opcode, step_state_transition, value.expr());

        Self {
            same_context,
            is_push0,
            value,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();
        self.is_push0.assign(
            region,
            offset,
            F::from(opcode.as_u64() - OpcodeId::PUSH0.as_u64()),
        )?;

        let value_rlc = if opcode.is_push_with_data() {
            let value = block.rws[step.rw_indices[0]].stack_value();
            region
                .challenges()
                .evm_word()
                .map(|challenge| rlc::value(&value.to_le_bytes(), challenge))
        } else {
            Value::known(F::zero())
        };
        self.value.assign(region, offset, value_rlc)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, evm_types::OpcodeId};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, bytes: &[u8]) {
        let mut bytecode = bytecode! {
            .write_op(opcode)
        };
        for b in bytes {
            bytecode.write(*b, false);
        }
        bytecode.op_stop();

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn push_gadget_simple() {
        #[cfg(feature = "shanghai")]
        test_ok(OpcodeId::PUSH0, &[]);
        test_ok(OpcodeId::PUSH1, &[1]);
        test_ok(OpcodeId::PUSH2, &[1, 2]);
        test_ok(
            OpcodeId::PUSH31,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31,
            ],
        );
        test_ok(
            OpcodeId::PUSH32,
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
        );

        // out of bounds
        test_ok(OpcodeId::PUSH2, &[1]);
        test_ok(OpcodeId::PUSH16, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn push_gadget_rand() {
        for (idx, opcode) in vec![
            OpcodeId::PUSH1,
            OpcodeId::PUSH2,
            OpcodeId::PUSH3,
            OpcodeId::PUSH4,
            OpcodeId::PUSH5,
            OpcodeId::PUSH6,
            OpcodeId::PUSH7,
            OpcodeId::PUSH8,
            OpcodeId::PUSH9,
            OpcodeId::PUSH10,
            OpcodeId::PUSH11,
            OpcodeId::PUSH12,
            OpcodeId::PUSH13,
            OpcodeId::PUSH14,
            OpcodeId::PUSH15,
            OpcodeId::PUSH16,
            OpcodeId::PUSH17,
            OpcodeId::PUSH18,
            OpcodeId::PUSH19,
            OpcodeId::PUSH20,
            OpcodeId::PUSH21,
            OpcodeId::PUSH22,
            OpcodeId::PUSH23,
            OpcodeId::PUSH24,
            OpcodeId::PUSH25,
            OpcodeId::PUSH26,
            OpcodeId::PUSH27,
            OpcodeId::PUSH28,
            OpcodeId::PUSH29,
            OpcodeId::PUSH30,
            OpcodeId::PUSH31,
            OpcodeId::PUSH32,
        ]
        .into_iter()
        .enumerate()
        {
            test_ok(opcode, &rand_bytes(idx + 1));
        }
    }
}
