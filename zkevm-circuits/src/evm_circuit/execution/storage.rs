use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            from_bytes,
            math_gadget::IsEqualGadget,
            storage_gadget::StorageExpansionGadget,
            StorageAddress, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct StorageGadget<F> {
    same_context: SameContextGadget<F>,
    address: StorageAddress<F>,
    value: Word<F>,
    storage_expansion: StorageExpansionGadget<F>,
    is_sload: IsEqualGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for StorageGadget<F> {
    const NAME: &'static str = "STORAGE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::STORAGE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // In successful case the address must be in 32 bytes
        let address = StorageAddress::new(cb.query_bytes(), cb.randomness());
        let value = cb.query_word();

        // Check if this is an SLOAD
        let is_sload =
            IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::SLOAD.expr());
        // This is an SSTORE
        let is_sstore = 1.expr() - is_sload.expr();

        // Calculate the gas cost for this storage access
        let storage_expansion = StorageExpansionGadget::construct();
        let storage_gas_cost = storage_expansion.expr();

        /* Stack operations */
        // Pop the address from the stack
        cb.stack_pop(address.expr());
        // For SLOAD push the value to the stack
        // FOR SSTORE pop the value from the stack
        cb.stack_lookup(
            is_sload.expr(),
            cb.stack_pointer_offset().expr() - is_sload.expr(),
            value.expr(),
        );

        /* Storage operations */
        // Read/Write the value from memory at the specified address
        // We always read/write 32 bytes.
        for idx in 0..32 {
            // We read/write all the bytes of value at an increasing address
            // value.
            let byte = if idx == 31 {
                value.cells[0].expr()
            } else {
                value.cells[31 - idx].expr()
            };

            // We increase the offset for MLOAD and MSTORE.
            let offset = if idx == 0 { 0.expr() } else { idx.expr() };
            cb.memory_lookup_with_counter(
                cb.curr.state.rw_counter.expr()
                    + cb.rw_counter_offset().expr()
                    + offset.clone(),
                is_sstore.clone(),
                from_bytes::expr(&address.cells) + offset,
                byte,
            );
        }

        // State transition
        // - `rw_counter` needs to be increased by 34
        // - `program_counter` needs to be increased by 1
        // - `stack_pointer` needs to be increased by 2 when is_sstore,
        //   otherwise to be same
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(34.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(is_sstore * 2.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            Some(storage_gas_cost),
        );

        Self {
            same_context,
            address,
            value,
            storage_expansion,
            is_sload,
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

        let opcode = step.opcode.unwrap();

        // Inputs/Outputs
        let [address, value] = [step.rw_indices[0], step.rw_indices[1]]
            .map(|idx| block.rws[idx].stack_value());
        self.address.assign(
            region,
            offset,
            Some(address.to_le_bytes()[..5].try_into().unwrap()),
        )?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        // Check if this is an SLOAD
        self.is_sload.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::SLOAD.as_u64()),
        )?;

        Ok(())
    }
}
