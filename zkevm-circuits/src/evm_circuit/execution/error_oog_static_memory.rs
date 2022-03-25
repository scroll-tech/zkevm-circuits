use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            constraint_builder::ConstraintBuilder,
            math_gadget::{IsEqualGadget, IsZeroGadget, RangeCheckGadget},
            memory_gadget::{address_high, address_low, MemoryExpansionGadget},
            Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGStaticMemoryGadget<F> {
    opcode: Cell<F>,
    address: Word<F>,
    address_in_range: IsZeroGadget<F>,
    // Allow memory size to expand to 5 bytes, because memory address could be
    // at most 2^40 - 1, after constant division by 32, the memory word size
    // then could be at most 2^35 - 1.
    // So generic N_BYTES_MEMORY_WORD_SIZE for MemoryExpansionGadget needs to
    // be larger by 1 than normal usage (to be 5), to be able to contain
    // number up to 2^35 - 1.
    memory_expansion: MemoryExpansionGadget<F, 1, { N_BYTES_MEMORY_WORD_SIZE + 1 }>,
    // Even memory size at most could be 2^35 - 1, the qudratic part of memory
    // expansion gas cost could be at most 2^61 - 2^27, due to the constant
    // division by 512, which still fits in 8 bytes.
    insufficient_gas: RangeCheckGadget<F, N_BYTES_GAS>,
    is_mstore8: IsEqualGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGStaticMemoryGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasStaticMemoryExpansion";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasStaticMemoryExpansion;

    // Support other OOG due to pure memory including CREATE, RETURN and REVERT
    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Query address by a full word
        let address = cb.query_word();

        // Check if this is an MSTORE8
        let is_mstore8 = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::MSTORE8.expr());
        let is_not_mstore8 = 1.expr() - is_mstore8.expr();

        // Get the next memory size and the gas cost for this memory access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_word_size.expr(),
            [address_low::expr(&address) + 1.expr() + (is_not_mstore8 * 31.expr())],
        );

        // Check if the memory address is too large
        let address_in_range = IsZeroGadget::construct(cb, address_high::expr(&address));
        // Check if the amount of gas available is less than the amount of gas
        // required
        let insufficient_gas = cb.condition(address_in_range.expr(), |cb| {
            RangeCheckGadget::construct(
                cb,
                OpcodeId::MLOAD.constant_gas_cost().expr() + memory_expansion.gas_cost()
                    - cb.curr.state.gas_left.expr(),
            )
        });

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
        _: &Transaction,
        _: &Call,
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
            F::from(opcode.as_u64()),
            F::from(OpcodeId::MSTORE8.as_u64()),
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
            step.memory_word_size(),
            [address_low::value(address.to_le_bytes())
                + if is_mstore8 == F::one() { 1 } else { 32 }],
        )?;

        // Gas insufficient check
        // Get `gas_available` variable here once it's available
        self.insufficient_gas
            .assign(region, offset, F::from(step.gas_cost - step.gas_left))?;

        Ok(())
    }
}
