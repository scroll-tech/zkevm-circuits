use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::LtGadget,
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryExpandedAddressGadget, MemoryExpansionGadget,
                MemoryWordSizeGadget,
            },
            or, CachedRegion, Cell, Word,
        },
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGCreate2Gadget<F> {
    opcode: Cell<F>,
    value: Word<F>,
    salt: Word<F>,
    minimum_word_size: MemoryWordSizeGadget<F>,
    memory_address: MemoryExpandedAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGCreate2Gadget<F> {
    const NAME: &'static str = "ErrorOutOfGasCREATE2";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasCREATE2;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        cb.require_equal(
            "ErrorOutOfGasCREATE2 opcode must be CREATE2",
            opcode.expr(),
            OpcodeId::CREATE2.expr(),
        );

        let value = cb.query_word_rlc();
        let salt = cb.query_word_rlc();

        let memory_address = MemoryExpandedAddressGadget::construct_self(cb);

        cb.stack_pop(value.expr());
        cb.stack_pop(memory_address.offset_rlc());
        cb.stack_pop(memory_address.length_rlc());
        cb.stack_pop(salt.expr());

        let minimum_word_size = MemoryWordSizeGadget::construct(cb, memory_address.length());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            OpcodeId::CREATE2.constant_gas_cost().expr()
                + memory_expansion.gas_cost()
                + 6.expr() * minimum_word_size.expr(),
        );

        cb.require_equal(
            "Memory address is overflow or gas left is less than cost",
            or::expr([memory_address.overflow(), insufficient_gas.expr()]),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 6.expr());

        Self {
            opcode,
            value,
            salt,
            minimum_word_size,
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

        self.value.assign(
            region,
            offset,
            Some(block.rws[step.rw_indices[0]].stack_value().to_le_bytes()),
        )?;

        let memory_offset = block.rws[step.rw_indices[1]].stack_value();
        let memory_length = block.rws[step.rw_indices[2]].stack_value();

        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_length)?;

        self.salt.assign(
            region,
            offset,
            Some(block.rws[step.rw_indices[3]].stack_value().to_le_bytes()),
        )?;

        let minimum_word_size = self.minimum_word_size.assign(
            region,
            offset,
            MemoryExpandedAddressGadget::<F>::length_value(memory_offset, memory_length),
        )?;
        let memory_expansion_gas = self
            .memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?
            .1;

        let constant_gas_cost = opcode.constant_gas_cost().0;

        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(6 * minimum_word_size + memory_expansion_gas + constant_gas_cost),
        )?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 6)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, word, Bytecode, ToWord, Word, U256};
    use mock::{
        eth,
        test_ctx::{helpers::account_0_code_account_1_no_code, LoggerConfig},
        TestContext, MOCK_ACCOUNTS, MOCK_BLOCK_GAS_LIMIT,
    };

    struct TestCase {
        bytecode: Bytecode,
        gas: Word,
    }

    #[test]
    fn test_oog_create2_simple() {
        let cases = [
            TestCase {
                bytecode: bytecode! {
                    PUSH8(0x0) // salt
                    PUSH8(0xFF) // size
                    PUSH32(word!("0xffffffff")) // offset
                    PUSH8(0x0) // value
                    CREATE2
                    STOP
                },
                gas: word!("0xFFFF"),
            },
            TestCase {
                bytecode: bytecode! {
                    PUSH1(2) // salt
                    PUSH1(4) // size
                    PUSH1(0x0) // offset
                    PUSH1(0x0) // value
                    CREATE2
                },
                gas: word!("0x7D0F"),
            },
        ];

        for case in cases.iter() {
            test_root(case);
            test_internal(case);
        }
    }

    #[test]
    fn test_oog_create2_max_expanded_address() {
        // 0xffffffff1 + 0xffffffff0 = 0x1fffffffe1
        // > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
        let case = TestCase {
            bytecode: bytecode! {
                PUSH8(0) // salt
                PUSH32(0xffffffff0_u64) // size
                PUSH32(0xffffffff1_u64) // offset
                PUSH8(0) // value
                CREATE2
                STOP
            },
            gas: MOCK_BLOCK_GAS_LIMIT.into(),
        };

        test_root(&case);
        test_internal(&case);
    }

    #[test]
    fn test_oog_create2_max_u64_address() {
        let case = TestCase {
            bytecode: bytecode! {
                PUSH8(0) // salt
                PUSH32(u64::MAX) // size
                PUSH32(u64::MAX) // offset
                PUSH8(0) // value
                CREATE2
                STOP
            },
            gas: MOCK_BLOCK_GAS_LIMIT.into(),
        };

        test_root(&case);
        test_internal(&case);
    }

    #[test]
    fn test_oog_create2_max_word_address() {
        let case = TestCase {
            bytecode: bytecode! {
                PUSH8(0) // salt
                PUSH32(U256::MAX) // size
                PUSH32(U256::MAX) // offset
                PUSH8(0) // value
                CREATE2
                STOP
            },
            gas: MOCK_BLOCK_GAS_LIMIT.into(),
        };

        test_root(&case);
        test_internal(&case);
    }

    fn test_root(case: &TestCase) {
        let ctx = TestContext::<2, 1>::new_with_logger_config(
            None,
            account_0_code_account_1_no_code(case.bytecode.clone()),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(case.gas);
            },
            |block, _tx| block,
            LoggerConfig {
                enable_memory: true,
                ..Default::default()
            },
        )
        .unwrap();

        log::debug!("{:?}", ctx.geth_traces[0]);

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_internal(case: &TestCase) {
        let code_a = bytecode! {
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(0x00) // argsLength
            PUSH32(0x00) // argsOffset
            PUSH1(0x00) // value
            PUSH32(MOCK_ACCOUNTS[1].to_word()) // addr
            PUSH32(case.gas) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new_with_logger_config(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).code(code_a);
                accs[1]
                    .address(MOCK_ACCOUNTS[1])
                    .code(case.bytecode.clone());
                accs[2].address(MOCK_ACCOUNTS[2]).balance(eth(1));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[2].address)
                    .to(accs[0].address)
                    .gas(word!("0xFFFFF"));
            },
            |block, _tx| block,
            LoggerConfig {
                enable_memory: true,
                ..Default::default()
            },
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
