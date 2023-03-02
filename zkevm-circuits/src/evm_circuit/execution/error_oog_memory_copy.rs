use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE};
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::CommonErrorGadget;
use crate::evm_circuit::util::constraint_builder::ConstraintBuilder;
use crate::evm_circuit::util::math_gadget::LtGadget;
use crate::evm_circuit::util::memory_gadget::{
    MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget,
};
use crate::evm_circuit::util::{CachedRegion, Cell, Word};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::util::Expr;
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::CALLDATACOPY`], [`OpcodeId::CODECOPY`] and
/// [`OpcodeId::RETURNDATACOPY`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGMemoryCopyGadget<F> {
    opcode: Cell<F>,
    /// Source offset (second stack pop value)
    src_offset: Word<F>,
    /// Destination offset and size to copy (first and third stack pop values)
    dst_memory_addr: MemoryAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGMemoryCopyGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasMemoryCopy";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasMemoryCopy;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_in_set(
            "ErrorOutOfGasMemoryCopy opcode must be CALLDATACOPY, CODECOPY or RETURNDATACOPY",
            opcode.expr(),
            vec![
                OpcodeId::CALLDATACOPY.expr(),
                OpcodeId::CODECOPY.expr(),
                OpcodeId::RETURNDATACOPY.expr(),
            ],
        );

        let dst_offset = cb.query_cell_phase2();
        let src_offset = cb.query_word_rlc();
        let copy_size = cb.query_word_rlc();

        cb.stack_pop(dst_offset.expr());
        cb.stack_pop(src_offset.expr());
        cb.stack_pop(copy_size.expr());

        let dst_memory_addr = MemoryAddressGadget::construct(cb, dst_offset, copy_size);
        let memory_expansion = MemoryExpansionGadget::construct(cb, [dst_memory_addr.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            dst_memory_addr.length(),
            memory_expansion.gas_cost(),
        );

        // Constant gas cost is same for CALLDATACOPY, CODECOPY and RETURNDATACOPY.
        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            OpcodeId::CALLDATACOPY.constant_gas_cost().expr() + memory_copier_gas.gas_cost(),
        );

        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 5.expr());

        Self {
            opcode,
            src_offset,
            dst_memory_addr,
            memory_expansion,
            memory_copier_gas,
            insufficient_gas,
            common_error_gadget,
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
        let opcode = step.opcode.unwrap();

        log::debug!(
            "ErrorOutOfGasMemoryCopy: opcode = {}, gas_left = {}, gas_cost = {}",
            opcode,
            step.gas_left,
            step.gas_cost,
        );

        let [dst_offset, src_offset, copy_size] =
            [0, 1, 2].map(|idx| block.rws[step.rw_indices[idx]].stack_value());

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.src_offset
            .assign(region, offset, Some(src_offset.to_le_bytes()))?;

        let memory_addr = self
            .dst_memory_addr
            .assign(region, offset, dst_offset, copy_size)?;
        let (_, memory_expansion_cost) =
            self.memory_expansion
                .assign(region, offset, step.memory_word_size(), [memory_addr])?;
        self.memory_copier_gas
            .assign(region, offset, copy_size.as_u64(), memory_expansion_cost)?;
        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(step.gas_cost)),
        )?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_circuit::test::{rand_bytes, rand_word};
    use crate::test_util::CircuitTestBuilder;
    use eth_types::evm_types::gas_utils::memory_copier_gas_cost;
    use eth_types::{bytecode, Bytecode, ToWord, U256};
    use itertools::Itertools;
    use mock::test_ctx::helpers::account_0_code_account_1_no_code;
    use mock::{eth, TestContext, MOCK_ACCOUNTS};

    const TESTING_OPCODES: &[OpcodeId] = &[
        OpcodeId::CALLDATACOPY,
        OpcodeId::CODECOPY,
        OpcodeId::RETURNDATACOPY,
    ];

    const TESTING_DST_OFFSET_COPY_SIZE_PAIRS: &[(u64, u64)] =
        &[(0x20, 0), (0x40, 20), (0x4000, 0x4000)];

    #[test]
    fn test_oog_memory_copy() {
        for (opcode, (dst_offset, copy_size)) in TESTING_OPCODES
            .iter()
            .cartesian_product(TESTING_DST_OFFSET_COPY_SIZE_PAIRS.iter())
        {
            let testing_data = TestingData::new(*opcode, *dst_offset, *copy_size);

            test_root(&testing_data);
            test_internal(&testing_data);
        }
    }

    struct TestingData {
        bytecode: Bytecode,
        gas_cost: u64,
    }

    impl TestingData {
        pub fn new(opcode: OpcodeId, dst_offset: u64, copy_size: u64) -> Self {
            let bytecode = bytecode! {
                PUSH32(copy_size)
                PUSH32(rand_word())
                PUSH32(dst_offset)
                .write_op(opcode)
            };

            // Current memory word size is zero, and next memory word size is calculated as
            // `(dst_offset + copy_size + 31) / 32`.
            let next_memory_word_size = (dst_offset + copy_size + 31) / 32;
            let gas_cost = OpcodeId::PUSH32.constant_gas_cost().0 * 3
                + opcode.constant_gas_cost().0
                + memory_copier_gas_cost(0, next_memory_word_size, copy_size);

            Self { bytecode, gas_cost }
        }
    }

    fn test_root(testing_data: &TestingData) {
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(testing_data.bytecode.clone()),
            |mut txs, accs| {
                // Decrease expected gas cost (by 1) to trigger out of gas error.
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas((GasCost::TX.0 + testing_data.gas_cost - 1).into());
            },
            |block, _tx| block.number(0xcafe_u64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_internal(testing_data: &TestingData) {
        let (addr_a, addr_b) = (MOCK_ACCOUNTS[0], MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = testing_data.bytecode.clone();
        let gas_cost_b = testing_data.gas_cost;

        // Code A calls code B.
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(U256::from_big_endian(&rand_bytes(8)))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(0x00) // argsLength
            PUSH32(0x20) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            // Decrease expected gas cost (by 1) to trigger out of gas error.
            PUSH32(gas_cost_b - 1) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2].address(MOCK_ACCOUNTS[2]).balance(eth(10));
            },
            |mut txs, accs| {
                txs[0].from(accs[2].address).to(accs[1].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
