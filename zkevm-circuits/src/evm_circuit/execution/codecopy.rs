use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_WORD_SIZE, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::{SameContextGadget, WordByteCapGadget},
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            not, select, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CodeCopyGadget<F> {
    same_context: SameContextGadget<F>,
    /// Holds the memory address for the offset in code from where we
    /// read. It is valid if within range of Uint64 and less than code_size.
    code_offset: WordByteCapGadget<F, N_BYTES_U64>,
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

        let code_size = cb.query_cell();

        let size = cb.query_word_rlc();
        let dst_memory_offset = cb.query_cell_phase2();
        let code_offset = WordByteCapGadget::construct(cb, code_size.expr());

        // Pop items from stack.
        cb.stack_pop(dst_memory_offset.expr());
        cb.stack_pop(code_offset.original_word());
        cb.stack_pop(size.expr());

        // Construct memory address in the destionation (memory) to which we copy code.
        let dst_memory_addr = MemoryAddressGadget::construct(cb, dst_memory_offset, size);

        // Fetch the hash of bytecode running in current environment.
        let code_hash = cb.curr.state.code_hash.clone();

        // Fetch the bytecode length from the bytecode table.
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
            // Set source start to the minimun value of code offset and code size.
            let src_addr = select::expr(
                code_offset.lt_cap(),
                code_offset.valid_value(),
                code_size.expr(),
            );

            cb.copy_table_lookup(
                code_hash.expr(),
                CopyDataType::Bytecode.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                src_addr,
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

        let bytecode = block
            .bytecodes
            .get(&call.code_hash)
            .expect("could not find current environment's bytecode");

        let code_size = bytecode.bytes.len() as u64;
        self.code_size
            .assign(region, offset, Value::known(F::from(code_size)))?;

        self.code_offset
            .assign(region, offset, code_offset, F::from(code_size))?;

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
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(code_offset: Word, memory_offset: Word, size: usize, large: bool) {
        let mut code = bytecode! {};
        if large {
            for _ in 0..size {
                code.push(1, Word::from(123));
            }
        }
        let tail = bytecode! {
            PUSH32(Word::from(size))
            PUSH32(code_offset)
            PUSH32(memory_offset)
            CODECOPY
            STOP
        };
        code.append(&tail);

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
        .run();
    }

    #[test]
    fn codecopy_gadget_simple() {
        test_ok(0x00.into(), 0x00.into(), 0x20, false);
        test_ok(0x30.into(), 0x20.into(), 0x30, false);
        test_ok(0x20.into(), 0x10.into(), 0x42, false);
    }

    #[test]
    fn codecopy_gadget_large() {
        test_ok(0x102.into(), 0x103.into(), 0x101, true);
    }

    #[test]
    fn codecopy_gadget_code_offset_overflow() {
        test_ok(Word::MAX, 0x103.into(), 0x101, true);
    }

    #[test]
    fn codecopy_gadget_overflow_memory_offset_and_zero_size() {
        test_ok(0x102.into(), Word::MAX, 0, false);
    }
}
