use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            from_bytes,
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            not, CachedRegion, Cell, MemoryAddress,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CodeCopyGadget<F> {
    same_context: SameContextGadget<F>,
    /// Holds the memory address for the offset in code from where we read.
    code_offset: MemoryAddress<F>,
    /// Holds the size of the current environment's bytecode.
    code_size: Cell<F>,
    /// The code from current environment is copied to memory. To verify this
    /// copy operation we need the MemoryAddressGadget.
    dst_memory_addr: MemoryAddressGadget<F>,
    /// Opcode CODECOPY has a dynamic gas cost:
    /// gas_code = static_gas * minimum_word_size + memory_expansion_cost
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    /// Opcode CODECOPY needs to copy code bytes into memory. We account for
    /// the copying costs using the memory copier gas gadget.
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
    /// RW inverse counter from the copy table at the start of related copy
    /// steps.
    copy_rwc_inc: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for CodeCopyGadget<F> {
    const NAME: &'static str = "CODECOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CODECOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Query elements to be popped from the stack.
        let dst_memory_offset = cb.query_cell_phase2();
        let code_offset = cb.query_word_rlc();
        let size = cb.query_word_rlc();

        // Pop items from stack.
        cb.stack_pop(dst_memory_offset.expr());
        cb.stack_pop(code_offset.expr());
        cb.stack_pop(size.expr());

        // Construct memory address in the destionation (memory) to which we copy code.
        let dst_memory_addr = MemoryAddressGadget::construct(cb, dst_memory_offset, size);

        // Fetch the hash of bytecode running in current environment.
        let code_hash = cb.curr.state.code_hash.clone();

        // Fetch the bytecode length from the bytecode table.
        let code_size = cb.query_cell();
        cb.bytecode_length(code_hash.expr(), code_size.expr());

        // Calculate the next memory size and the gas cost for this memory
        // access. This also accounts for the dynamic gas required to copy bytes to
        // memory.
        let memory_expansion = MemoryExpansionGadget::construct(cb, [dst_memory_addr.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            dst_memory_addr.length(),
            memory_expansion.gas_cost(),
        );

        let copy_rwc_inc = cb.query_cell();
        cb.condition(dst_memory_addr.has_length(), |cb| {
            cb.copy_table_lookup(
                code_hash.expr(),
                CopyDataType::Bytecode.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                from_bytes::expr(&code_offset.cells),
                code_size.expr(),
                dst_memory_addr.offset(),
                dst_memory_addr.length(),
                0.expr(), // for CODECOPY, rlc_acc is 0
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(dst_memory_addr.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        // Expected state transition.
        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(3.expr()),
            memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),
            gas_left: Transition::Delta(
                -OpcodeId::CODECOPY.constant_gas_cost().expr() - memory_copier_gas.gas_cost(),
            ),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            code_offset,
            code_size,
            dst_memory_addr,
            memory_expansion,
            memory_copier_gas,
            copy_rwc_inc,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // 1. `dest_offset` is the bytes offset in the memory where we start to
        // write.
        // 2. `code_offset` is the bytes offset in the current
        // context's code where we start to read.
        // 3. `size` is the number of
        // bytes to be read and written (0s to be copied for out of bounds).
        let [dest_offset, code_offset, size] =
            [0, 1, 2].map(|i| block.rws[step.rw_indices[i]].stack_value());

        // assign the code offset memory address.
        self.code_offset.assign(
            region,
            offset,
            Some(
                code_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        let code = block
            .bytecodes
            .get(&call.code_hash)
            .expect("could not find current environment's bytecode");
        self.code_size.assign(
            region,
            offset,
            Value::known(F::from(code.bytes.len() as u64)),
        )?;

        // assign the destination memory offset.
        let memory_address = self
            .dst_memory_addr
            .assign(region, offset, dest_offset, size)?;

        // assign to gadgets handling memory expansion cost and copying cost.
        let (_, memory_expansion_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        self.memory_copier_gas
            .assign(region, offset, size.as_u64(), memory_expansion_cost)?;
        // rw_counter increase from copy table lookup is number of bytes copied.
        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                size.to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    use crate::test_util::run_test_circuits;

    fn test_ok(memory_offset: usize, code_offset: usize, size: usize, large: bool) {
        let mut code = bytecode! {};
        if large {
            for _ in 0..0x101 {
                code.push(1, Word::from(123));
            }
        }
        let tail = bytecode! {
            PUSH32(Word::from(size))
            PUSH32(Word::from(code_offset))
            PUSH32(Word::from(memory_offset))
            CODECOPY
            STOP
        };
        code.append(&tail);

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
                None,
            ),
            Ok(()),
        );
    }

    #[test]
    fn codecopy_gadget_simple() {
        test_ok(0x00, 0x00, 0x20, false);
        test_ok(0x20, 0x30, 0x30, false);
        test_ok(0x10, 0x20, 0x42, false);
    }

    #[test]
    fn codecopy_gadget_large() {
        test_ok(0x103, 0x102, 0x101, true);
    }
}
