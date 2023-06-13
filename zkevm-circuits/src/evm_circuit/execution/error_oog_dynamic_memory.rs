use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{LtGadget, PairSelectGadget},
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryExpandedAddressGadget, MemoryExpansionGadget,
            },
            or, CachedRegion, Cell,
        },
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::{evm_types::OpcodeId, Field};
use gadgets::util::{select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGDynamicMemoryGadget<F> {
    opcode: Cell<F>,
    is_return: PairSelectGadget<F>,
    memory_address: MemoryExpandedAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGDynamicMemoryGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasDynamicMemoryExpansion";
    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasDynamicMemoryExpansion;

    // Support other OOG due to pure memory including RETURN and REVERT
    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let is_return = PairSelectGadget::construct(
            cb,
            opcode.expr(),
            OpcodeId::RETURN.expr(),
            OpcodeId::REVERT.expr(),
        );

        let memory_address = MemoryExpandedAddressGadget::construct_self(cb);
        cb.stack_pop(memory_address.offset_rlc());
        cb.stack_pop(memory_address.length_rlc());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            select::expr(
                is_return.expr().0,
                OpcodeId::RETURN.constant_gas_cost().expr(),
                OpcodeId::REVERT.constant_gas_cost().expr(),
            ) + memory_expansion.gas_cost(),
        );

        cb.require_equal(
            "Memory address is overflow or gas left is less than cost",
            or::expr([memory_address.overflow(), insufficient_gas.expr()]),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 4.expr());

        Self {
            opcode,
            is_return,
            memory_address,
            memory_expansion,
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
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.is_return.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::RETURN.as_u64()),
            F::from(OpcodeId::REVERT.as_u64()),
        )?;

        let [memory_offset, memory_length] =
            [0, 1].map(|idx| block.rws[step.rw_indices[idx]].stack_value());
        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_length)?;

        let memory_expansion_gas = self
            .memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?
            .1;
        let constant_gas_cost = opcode.constant_gas_cost().0;
        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(memory_expansion_gas + constant_gas_cost),
        )?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 4)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, word, Bytecode, ToWord, U256};
    use mock::{
        eth, test_ctx::helpers::account_0_code_account_1_no_code, TestContext, MOCK_ACCOUNTS,
    };

    #[test]
    fn test_oog_dynamic_memory_simple() {
        for code in testing_bytecodes(0xffffffff_u64.into(), 0xff.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_dynamic_memory_max_expanded_address() {
        // 0xffffffff1 + 0xffffffff0 = 0x1fffffffe1
        // > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
        for code in testing_bytecodes(0xffffffff1_u64.into(), 0xffffffff0_u64.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_dynamic_memory_max_u64_address() {
        for code in testing_bytecodes(u64::MAX.into(), u64::MAX.into()).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    #[test]
    fn test_oog_dynamic_memory_max_word_address() {
        for code in testing_bytecodes(U256::MAX, U256::MAX).iter() {
            test_root(code);
            test_internal(code);
        }
    }

    fn test_root(code: &Bytecode) {
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code.clone()),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(word!("0xFFFF"));
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_internal(code: &Bytecode) {
        let code_a = bytecode! {
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(0x00) // argsLength
            PUSH32(0x00) // argsOffset
            PUSH1(0x00) // value
            PUSH32(MOCK_ACCOUNTS[1].to_word()) // addr
            PUSH32(0xFFFF) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).code(code_a);
                accs[1].address(MOCK_ACCOUNTS[1]).code(code.clone());
                accs[2].address(MOCK_ACCOUNTS[2]).balance(eth(1));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[2].address)
                    .to(accs[0].address)
                    .gas(word!("0xFFFFF"));
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn testing_bytecodes(offset: U256, size: U256) -> Vec<Bytecode> {
        vec![
            bytecode! {
                PUSH32(size)
                PUSH32(offset)
                RETURN
            },
            bytecode! {
                PUSH32(size)
                PUSH32(offset)
                REVERT
            },
        ]
    }
}
