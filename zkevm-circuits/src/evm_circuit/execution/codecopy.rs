use std::convert::TryInto;

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Region, plonk::Error};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            from_bytes,
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            Cell, MemoryAddress,
        },
        witness::{Block, Call, CodeSource, ExecStep, Transaction},
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
    memory_copier_gas: MemoryCopierGasGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for CodeCopyGadget<F> {
    const NAME: &'static str = "CODECOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CODECOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Query elements to be popped from the stack.
        let dest_memory_offset = cb.query_cell();
        let code_offset = cb.query_rlc();
        let size = cb.query_rlc();

        // Pop items from stack.
        cb.stack_pop(dest_memory_offset.expr());
        cb.stack_pop(code_offset.expr());
        cb.stack_pop(size.expr());

        // Construct memory address in the destionation (memory) to which we copy code.
        let dst_memory_addr = MemoryAddressGadget::construct(cb, dest_memory_offset, size.clone());

        // Fetch the source code running in current environment.
        let code_source = cb.curr.state.code_source.clone();

        // Fetch the bytecode length from the bytecode table.
        let code_size = cb.bytecode_length(code_source.expr());

        // Calculate the next memory size and the gas cost for this memory
        // access. This also accounts for the dynamic gas required to copy bytes to
        // memory.
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_word_size.expr(),
            [dst_memory_addr.address()],
        );
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            dst_memory_addr.length(),
            memory_expansion.gas_cost(),
        );

        // Constrain the next step to be the internal `CopyCodeToMemory` step and add
        // some preliminary checks on its auxiliary data.
        cb.constrain_next_step(
            ExecutionState::CopyCodeToMemory,
            Some(dst_memory_addr.has_length()),
            |cb| {
                let next_src_addr = cb.query_cell();
                let next_dst_addr = cb.query_cell();
                let next_bytes_left = cb.query_cell();
                let next_src_addr_end = cb.query_cell();
                let next_code_source = cb.query_word();

                cb.require_equal(
                    "next_src_addr == code_offset",
                    next_src_addr.expr(),
                    from_bytes::expr(&code_offset.cells),
                );
                cb.require_equal(
                    "next_dst_addr = memory_offset",
                    next_dst_addr.expr(),
                    dst_memory_addr.offset(),
                );
                cb.require_equal(
                    "next_bytes_left = length",
                    next_bytes_left.expr(),
                    size.expr(),
                );
                cb.require_equal(
                    "next_src_addr_end == code_size",
                    next_src_addr_end.expr(),
                    code_size.expr(),
                );
                cb.require_equal(
                    "next_code_source == code_source",
                    next_code_source.expr(),
                    code_source.expr(),
                );
            },
        );

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
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
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
            .iter()
            .find(|b| {
                let CodeSource::Account(code_source) = &call.code_source;
                b.hash == *code_source
            })
            .expect("could not find current environment's bytecode");
        self.code_size
            .assign(region, offset, Some(F::from(code.bytes.len() as u64)))?;

        // assign the destination memory offset.
        let memory_address =
            self.dst_memory_addr
                .assign(region, offset, dest_offset, size, block.randomness)?;

        // assign to gadgets handling memory expansion cost and copying cost.
        let (_, memory_expansion_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        self.memory_copier_gas
            .assign(region, offset, size.as_u64(), memory_expansion_cost)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    use crate::test_util::run_test_circuits;

    fn test_ok(memory_offset: usize, code_offset: usize, size: usize) {
        let code = bytecode! {
            PUSH32(Word::from(size))
            PUSH32(Word::from(code_offset))
            PUSH32(Word::from(memory_offset))
            CODECOPY
            STOP
        };
        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
                None,
            ),
            Ok(()),
        );
    }

    #[test]
    fn codecopy_gadget() {
        test_ok(0x00, 0x00, 0x20);
        test_ok(0x20, 0x30, 0x30);
        test_ok(0x10, 0x20, 0x42);
    }
}
