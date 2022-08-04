use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::Expr;
use halo2_proofs::plonk::Error;

use crate::evm_circuit::{
    param::N_BYTES_MEMORY_WORD_SIZE,
    step::ExecutionState,
    util::{
        common_gadget::SameContextGadget,
        constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
        memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
        rlc, CachedRegion, Cell, Word,
    },
    witness::{Block, Call, ExecStep, Transaction},
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct Sha3Gadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddressGadget<F>,
    sha3_rlc: Word<F>,
    copy_rwc_inc: Cell<F>,
    rlc_acc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY_SHA3 }>,
}

impl<F: Field> ExecutionGadget<F> for Sha3Gadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::SHA3;

    const NAME: &'static str = "SHA3";

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let offset = cb.query_cell();
        let size = cb.query_rlc();
        let sha3_rlc = cb.query_rlc();

        cb.stack_pop(offset.expr());
        cb.stack_pop(size.expr());
        cb.stack_push(sha3_rlc.expr());

        let memory_address = MemoryAddressGadget::construct(cb, offset, size);

        let copy_rwc_inc = cb.query_cell();
        let rlc_acc = cb.query_cell();
        cb.copy_table_lookup(
            cb.curr.state.call_id.expr(),
            CopyDataType::Memory.expr(),
            cb.curr.state.call_id.expr(),
            CopyDataType::RlcAcc.expr(),
            memory_address.offset(),
            memory_address.address(),
            0.expr(), // dst_addr for CopyDataType::RlcAcc is 0.
            memory_address.length(),
            rlc_acc.expr(),
            cb.curr.state.rw_counter.expr() + cb.rw_counter_offset(),
            copy_rwc_inc.expr(),
        );
        cb.keccak_table_lookup(rlc_acc.expr(), memory_address.length(), sha3_rlc.expr());

        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_word_size.expr(),
            [memory_address.address()],
        );
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset() + copy_rwc_inc.expr()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(1.expr()),
            memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),
            gas_left: Transition::Delta(
                -(OpcodeId::SHA3.constant_gas_cost().expr() + memory_copier_gas.gas_cost()),
            ),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            sha3_rlc,
            copy_rwc_inc,
            rlc_acc,
            memory_expansion,
            memory_copier_gas,
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

        let [memory_offset, size, sha3_output] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
                .map(|idx| block.rws[idx].stack_value());
        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, size, block.randomness)?;
        self.sha3_rlc
            .assign(region, offset, Some(sha3_output.to_le_bytes()))?;

        self.copy_rwc_inc.assign(region, offset, size.to_scalar())?;

        let values: Vec<_> = (3..3 + (size.low_u64() as usize))
            .map(|i| block.rws[step.rw_indices[i]].memory_value())
            .collect();
        let rlc_acc = rlc::value(&values, block.randomness);
        self.rlc_acc.assign(region, offset, Some(rlc_acc))?;

        // Memory expansion and dynamic gas cost for reading it.
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        self.memory_copier_gas.assign(
            region,
            offset,
            size.as_u64(),
            memory_expansion_gas_cost as u64,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use eth_types::bytecode;
    use mock::TestContext;

    use crate::test_util::run_test_circuits;

    #[test]
    fn sha3_gadget_simple() {
        let code = bytecode! {
            PUSH32(0x08) // size
            PUSH32(0x00) // offset
            SHA3
            STOP
        };
        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
                None
            ),
            Ok(())
        );
    }

    #[test]
    fn sha3_gadget_large() {
        let code = bytecode! {
            PUSH32(0x101)
            PUSH32(0x202)
            SHA3
            STOP
        };
        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
                None
            ),
            Ok(())
        );
    }
}
