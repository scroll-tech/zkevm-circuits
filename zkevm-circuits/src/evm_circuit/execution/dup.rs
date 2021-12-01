use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            Cell, Word,
        },
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct DupGadget<F> {
    same_context: SameContextGadget<F>,
    value: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for DupGadget<F> {
    const NAME: &'static str = "DUP";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::DUP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let value = cb.query_cell();

        // The stack index we have to peek, deduced from the 'x' value of 'dupx'
        // The offset starts at 0 for DUP1
        let dup_offset = opcode.expr() - OpcodeId::DUP1.expr();

        // Peek the value at `dup_offset` and push the value on the stack
        cb.stack_lookup(false.expr(), dup_offset, value.expr());
        cb.stack_push(value.expr());

        // State transition
        let state_transition = StateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self {
            same_context,
            value,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let value = block.rws[step.rw_indices[0]].stack_value();
        self.value.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                value.to_le_bytes(),
                block.randomness,
            )),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::{bus_mapping_tmp::{
            Block, Bytecode, Call, ExecStep, Rw, Transaction,
        }, byte},
        step::ExecutionResult,
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination, bus_mapping_tmp_convert,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId, bytecode,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(opcode: OpcodeId, value: Word) {
        let n = (opcode.as_u8() - OpcodeId::DUP1.as_u8() + 1) as usize;
        let mut bytecode = bytecode!{
            PUSH32(value)
        };
        for _ in 0..n-1 {
            bytecode.write_op(OpcodeId::DUP1);
        }
        bytecode.append(&bytecode!{
            #[start]
            .write_op(opcode)
            STOP
        });
        let block = bus_mapping_tmp_convert::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn dup_gadget_simple() {
        test_ok(OpcodeId::DUP1, Word::max_value());
        test_ok(OpcodeId::DUP2, Word::max_value());
        test_ok(OpcodeId::DUP15, Word::max_value());
        test_ok(OpcodeId::DUP16, Word::max_value());
    }

    #[test]
    #[ignore]
    fn dup_gadget_rand() {
        for opcode in vec![
            OpcodeId::DUP1,
            OpcodeId::DUP2,
            OpcodeId::DUP3,
            OpcodeId::DUP4,
            OpcodeId::DUP5,
            OpcodeId::DUP6,
            OpcodeId::DUP7,
            OpcodeId::DUP8,
            OpcodeId::DUP9,
            OpcodeId::DUP10,
            OpcodeId::DUP11,
            OpcodeId::DUP12,
            OpcodeId::DUP13,
            OpcodeId::DUP14,
            OpcodeId::DUP15,
            OpcodeId::DUP16,
        ]
        .into_iter()
        {
            test_ok(opcode, rand_word());
        }
    }
}
