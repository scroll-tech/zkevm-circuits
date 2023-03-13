use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::ConstraintBuilder,
            math_gadget::LtGadget,
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas error for
/// [`OpcodeId::SHA3`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGSha3Gadget<F> {
    opcode: Cell<F>,
    memory_address: MemoryAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY_SHA3 }>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGSha3Gadget<F> {
    const NAME: &'static str = "ErrorOutOfGasSHA3";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasSHA3;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_equal(
            "ErrorOutOfGasSHA3 opcode must be SHA3",
            opcode.expr(),
            OpcodeId::SHA3.expr(),
        );

        let memory_offset = cb.query_cell_phase2();
        let memory_size = cb.query_word_rlc();

        cb.stack_pop(memory_offset.expr());
        cb.stack_pop(memory_size.expr());

        let memory_address = MemoryAddressGadget::construct(cb, memory_offset, memory_size);
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            OpcodeId::SHA3.constant_gas_cost().expr() + memory_copier_gas.gas_cost(),
        );

        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 4.expr());

        Self {
            opcode,
            memory_address,
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
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();

        // gupeng
        println!(
            // log::debug!(
            "ErrorOutOfGasSHA3: gas_cost = {}, gas_left = {}",
            step.gas_cost, step.gas_left,
        );

        let [memory_offset, memory_size] =
            [0, 1].map(|idx| block.rws[step.rw_indices[idx]].stack_value());

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_size)?;
        let (_, memory_expansion_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        let memory_copier_gas = self.memory_copier_gas.assign(
            region,
            offset,
            memory_size.as_u64(),
            memory_expansion_cost,
        )?;
        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(
                OpcodeId::SHA3.constant_gas_cost().0 + memory_copier_gas,
            )),
        )?;
        self.common_error_gadget
            .assign(region, offset, block, call, step, 4)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{
        bytecode, evm_types::gas_utils::memory_copier_gas_cost, Bytecode, ToWord, U256,
    };
    use mock::{
        eth, test_ctx::helpers::account_0_code_account_1_no_code, TestContext, MOCK_ACCOUNTS,
    };

    #[test]
    fn test_oog_sha3_less_than_constant_gas() {
        let testing_data = TestingData::new(0x20, 0, OpcodeId::SHA3.constant_gas_cost().0);

        test_root(&testing_data);
        test_internal(&testing_data);
    }

    #[test]
    fn test_oog_sha3_less_than_dynamic_gas() {
        let testing_data = TestingData::new(
            0x40,
            20,
            OpcodeId::SHA3.constant_gas_cost().0 + dynamic_gas_cost(0x40, 20),
        );

        test_root(&testing_data);
        test_internal(&testing_data);
    }

    struct TestingData {
        bytecode: Bytecode,
        gas_cost: u64,
    }

    impl TestingData {
        pub fn new(memory_offset: u64, memory_size: u64, gas_cost: u64) -> Self {
            let bytecode = bytecode! {
                PUSH32(memory_size)
                PUSH32(memory_offset)
                SHA3
            };

            let gas_cost = gas_cost + OpcodeId::PUSH32.constant_gas_cost().0 * 2;

            Self { bytecode, gas_cost }
        }
    }

    fn dynamic_gas_cost(memory_offset: u64, memory_size: u64) -> u64 {
        let memory_word_size = (memory_offset + memory_size + 31) / 32;

        memory_copier_gas_cost(
            0,
            memory_word_size,
            memory_size,
            GasCost::COPY_SHA3.as_u64(),
        )
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
