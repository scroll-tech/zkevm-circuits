use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::{not, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

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

        let offset = cb.query_cell_phase2();
        let size = cb.query_word_rlc();
        let sha3_rlc = cb.query_word_rlc();

        cb.stack_pop(offset.expr());
        cb.stack_pop(size.expr());
        cb.stack_push(sha3_rlc.expr());

        let memory_address = MemoryAddressGadget::construct(cb, offset, size);

        let copy_rwc_inc = cb.query_cell();
        let rlc_acc = cb.query_cell_phase2();

        cb.condition(memory_address.has_length(), |cb| {
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
                copy_rwc_inc.expr(),
            );
        });

        cb.condition(not::expr(memory_address.has_length()), |cb| {
            cb.require_zero("copy_rwc_inc == 0 for size = 0", copy_rwc_inc.expr());
            cb.require_zero("rlc_acc == 0 for size = 0", rlc_acc.expr());
        });
        cb.keccak_table_lookup(rlc_acc.expr(), memory_address.length(), sha3_rlc.expr());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
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
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [memory_offset, size, sha3_output] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
                .map(|idx| block.rws[idx].stack_value());
        let memory_address = self
            .memory_address
            .assign(region, offset, memory_offset, size)?;
        self.sha3_rlc
            .assign(region, offset, Some(sha3_output.to_le_bytes()))?;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                size.to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let values: Vec<u8> = (3..3 + (size.low_u64() as usize))
            .map(|i| block.rws[step.rw_indices[i]].memory_value())
            .collect();

        let rlc_acc = region
            .challenges()
            .keccak_input()
            .map(|randomness| rlc::value(values.iter().rev(), randomness));
        self.rlc_acc.assign(region, offset, rlc_acc)?;

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
    use crate::test_util::run_test_circuits_with_params;
    use bus_mapping::{
        circuit_input_builder::CircuitsParams,
        evm::{gen_sha3_code, MemoryKind},
    };
    use mock::TestContext;

    fn test_ok(offset: usize, size: usize, mem_kind: MemoryKind) {
        let (code, _) = gen_sha3_code(offset, size, mem_kind);
        assert_eq!(
            run_test_circuits_with_params(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
                None,
                CircuitsParams {
                    max_rws: 5500,
                    ..Default::default()
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn sha3_gadget_zero_length() {
        test_ok(0x20, 0x00, MemoryKind::MoreThanSize);
    }

    #[test]
    fn sha3_gadget_simple() {
        test_ok(0x00, 0x08, MemoryKind::Empty);
        test_ok(0x10, 0x10, MemoryKind::LessThanSize);
        test_ok(0x24, 0x16, MemoryKind::EqualToSize);
        test_ok(0x32, 0x78, MemoryKind::MoreThanSize);
    }

    #[test]
    fn sha3_gadget_large() {
        test_ok(0x101, 0x202, MemoryKind::Empty);
        test_ok(0x202, 0x303, MemoryKind::LessThanSize);
        test_ok(0x303, 0x404, MemoryKind::EqualToSize);
        test_ok(0x404, 0x505, MemoryKind::MoreThanSize);
    }
}
