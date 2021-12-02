use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            Cell, Word,
        },
        witness::bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct SwapGadget<F> {
    same_context: SameContextGadget<F>,
    values: [Cell<F>; 2],
}

impl<F: FieldExt> ExecutionGadget<F> for SwapGadget<F> {
    const NAME: &'static str = "SWAP";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::SWAP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let values = [cb.query_cell(), cb.query_cell()];

        // The stack index we have to peek, deduced from the 'x' value of
        // 'swapx' The offset starts at 1 for SWAP1
        let swap_offset = opcode.expr() - (OpcodeId::SWAP1.as_u64() - 1).expr();

        // Peek the value at `swap_offset`
        cb.stack_lookup(false.expr(), swap_offset.clone(), values[0].expr());
        // Peek the value at the top of the stack
        cb.stack_lookup(false.expr(), 0.expr(), values[1].expr());
        // Write the value previously at the top of the stack to `swap_offset`
        cb.stack_lookup(true.expr(), swap_offset, values[1].expr());
        // Write the value previously at `swap_offset` to the top of the stack
        cb.stack_lookup(true.expr(), 0.expr(), values[0].expr());

        // State transition
        let state_transition = StateTransition {
            rw_counter: Delta(4.expr()),
            program_counter: Delta(1.expr()),
            ..Default::default()
        };
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self {
            same_context,
            values,
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

        for (cell, value) in self.values.iter().zip(
            [step.rw_indices[0], step.rw_indices[1]]
                .map(|idx| block.rws[idx].stack_value())
                .iter(),
        ) {
            cell.assign(
                region,
                offset,
                Some(Word::random_linear_combine(
                    value.to_le_bytes(),
                    block.randomness,
                )),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        witness::bus_mapping_tmp,
    };
    use bus_mapping::{bytecode, eth_types::Word, evm::OpcodeId};

    fn test_ok(opcode: OpcodeId, lhs: Word, rhs: Word) {
        let n = (opcode.as_u8() - OpcodeId::SWAP1.as_u8() + 1) as usize;

        let mut bytecode = bytecode! {
            PUSH32(lhs)
        };
        for _ in 0..n - 1 {
            bytecode.write_op(OpcodeId::DUP1);
        }
        bytecode.append(&bytecode! {
            PUSH32(rhs)
            #[start]
            .write_op(opcode)
            STOP
        });
        let block =
            bus_mapping_tmp::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn swap_gadget_simple() {
        test_ok(OpcodeId::SWAP1, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP2, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP15, Word::from(0x030201), Word::from(0x040506));
        test_ok(OpcodeId::SWAP16, Word::from(0x030201), Word::from(0x040506));
    }

    #[test]
    #[ignore]
    fn swap_gadget_rand() {
        for opcode in vec![
            OpcodeId::SWAP1,
            OpcodeId::SWAP2,
            OpcodeId::SWAP3,
            OpcodeId::SWAP4,
            OpcodeId::SWAP5,
            OpcodeId::SWAP6,
            OpcodeId::SWAP7,
            OpcodeId::SWAP8,
            OpcodeId::SWAP9,
            OpcodeId::SWAP10,
            OpcodeId::SWAP11,
            OpcodeId::SWAP12,
            OpcodeId::SWAP13,
            OpcodeId::SWAP14,
            OpcodeId::SWAP15,
            OpcodeId::SWAP16,
        ]
        .into_iter()
        {
            test_ok(opcode, rand_word(), rand_word());
        }
    }
}
