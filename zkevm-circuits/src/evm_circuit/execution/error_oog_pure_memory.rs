use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        param::MAX_MEMORY_SIZE_IN_BYTES,
        step::ExecutionResult,
        util::{
            constraint_builder::ConstraintBuilder,
            math_gadget::{IsEqualGadget, IsZeroGadget, LtGadget},
            memory_gadget::{address_high, address_low, MemoryExpansionGadget},
            Cell, Word,
        },
    },
    util::Expr,
};
use bus_mapping::{
    eth_types::ToLittleEndian,
    evm::{GasCost, OpcodeId},
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone)]
pub(crate) struct ErrorOOGPureMemoryGadget<F> {
    opcode: Cell<F>,
    address: Word<F>,
    address_in_range: IsZeroGadget<F>,
    memory_expansion:
        MemoryExpansionGadget<F, { MAX_MEMORY_SIZE_IN_BYTES * 2 - 1 }>,
    insufficient_gas: LtGadget<F, { MAX_MEMORY_SIZE_IN_BYTES * 2 - 1 }>,
    is_mstore8: IsEqualGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for ErrorOOGPureMemoryGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasPureMemory";

    const EXECUTION_RESULT: ExecutionResult =
        ExecutionResult::ErrorOutOfGasPureMemory;

    // Support other OOG due to pure memory including CREATE, RETURN and REVERT
    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Query address by a full word
        let address = cb.query_word();

        // Check if this is an MSTORE8
        let is_mstore8 = IsEqualGadget::construct(
            cb,
            opcode.expr(),
            OpcodeId::MSTORE8.expr(),
        );
        let is_not_mstore8 = 1.expr() - is_mstore8.expr();

        // Get the next memory size and the gas cost for this memory access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_size.expr(),
            address_low::expr(&address)
                + 1.expr()
                + (is_not_mstore8 * 31.expr()),
        );

        // Check if the memory address is too large
        let address_in_range =
            IsZeroGadget::construct(cb, address_high::expr(&address));
        // Check if the amount of gas available is less than the amount of gas
        // required
        let (_, memory_gas_cost) = memory_expansion.expr();
        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            GasCost::FASTEST.expr() + memory_gas_cost,
        );

        // Make sure we are out of gas
        // Out of gas when either the address is too big and/or the amount of
        // gas available is lower than what is required.
        cb.require_zero(
            "Either the address is too big or insufficient gas",
            address_in_range.expr() * (1.expr() - insufficient_gas.expr()),
        );

        // Pop the address from the stack
        // We still have to do this to verify the correctness of `address`
        cb.stack_pop(address.expr());

        // TODO: Use ContextSwitchGadget to switch call context to caller's and
        // consume all gas_left.

        Self {
            opcode,
            address,
            address_in_range,
            memory_expansion,
            insufficient_gas,
            is_mstore8,
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
        let opcode = step.opcode.unwrap();

        // Inputs/Outputs
        let address = block.rws[step.rw_indices[0]].stack_value();
        self.address
            .assign(region, offset, Some(address.to_le_bytes()))?;

        // Check if this is an MSTORE8
        let is_mstore8 = self.is_mstore8.assign(
            region,
            offset,
            F::from_u64(opcode.as_u64()),
            F::from_u64(OpcodeId::MSTORE8.as_u64()),
        )?;

        // Address in range check
        self.address_in_range.assign(
            region,
            offset,
            address_high::value::<F>(address.to_le_bytes()),
        )?;

        // Memory expansion
        self.memory_expansion.assign(
            region,
            offset,
            step.memory_size,
            address_low::value::<F>(address.to_le_bytes())
                + 1
                + if is_mstore8 == F::one() { 0 } else { 31 },
        )?;

        // Gas insufficient check
        // Get `gas_available` variable here once it's available
        self.insufficient_gas.assign(
            region,
            offset,
            F::from_u64(step.gas_left),
            F::from_u64(step.gas_cost),
        )?;

        Ok(())
    }
}
