use crate::util::Field;
use array_init::array_init;
use bus_mapping::evm::OpcodeId;
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        step::ExecutionState,
        util::{
            common_gadget::{BytecodeLengthGadget, SameContextGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition, Transition,
            },
            from_bytes, not, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CodesizeGadget<F> {
    same_context: SameContextGadget<F>,
    codesize_bytes: [Cell<F>; 8],
    code_len_gadget: BytecodeLengthGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for CodesizeGadget<F> {
    const NAME: &'static str = "CODESIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CODESIZE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let codesize_bytes = array_init(|_| cb.query_byte());

        let code_hash = cb.curr.state.code_hash.clone();

        cb.stack_push(cb.word_rlc(codesize_bytes.clone().map(|c| c.expr())));

        let step_state_transition = StepStateTransition {
            gas_left: Transition::Delta(-OpcodeId::CODESIZE.constant_gas_cost().expr()),
            rw_counter: Transition::Delta(1.expr()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta((-1).expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);
        let code_len_gadget = BytecodeLengthGadget::construct(
            cb,
            code_hash,
            #[cfg(feature = "dual_bytecode")]
            same_context.is_first_sub_bytecode(),
        );

        cb.require_equal(
            "Constraint: bytecode length lookup == codesize",
            from_bytes::expr(&codesize_bytes),
            code_len_gadget.code_length.expr(),
        );

        Self {
            same_context,
            codesize_bytes,
            code_len_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block,
        _transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context
            .assign_exec_step(region, offset, block, call, step)?;

        let codesize = block.rws[step.rw_indices[0]].stack_value().as_u64();

        for (c, b) in self
            .codesize_bytes
            .iter()
            .zip(codesize.to_le_bytes().iter())
        {
            c.assign(region, offset, Value::known(F::from(*b as u64)))?;
        }

        self.code_len_gadget
            .assign(region, offset, block, call, codesize)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(large: bool) {
        let mut code = bytecode! {};
        if large {
            for _ in 0..128 {
                code.push(1, Word::from(0));
            }
        }
        let tail = bytecode! {
            CODESIZE
            STOP
        };
        code.append(&tail);

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
        .run();
    }

    #[test]
    fn test_codesize_gadget() {
        test_ok(false);
    }

    #[test]
    fn test_codesize_gadget_large() {
        test_ok(true);
    }
}
