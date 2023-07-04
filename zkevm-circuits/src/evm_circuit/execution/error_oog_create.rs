use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{LtGadget, PairSelectGadget},
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryExpandedAddressGadget, MemoryExpansionGadget,
                MemoryWordSizeGadget,
            },
            or, select, CachedRegion, Cell, Word,
        },
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::{
    evm_types::{
        GasCost, OpcodeId, CREATE2_GAS_PER_CODE_WORD, CREATE_GAS_PER_CODE_WORD, MAX_INIT_CODE_SIZE,
    },
    Field, ToLittleEndian, U256,
};
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGCreateGadget<F> {
    opcode: Cell<F>,
    value: Word<F>,
    salt: Word<F>,
    is_create2: PairSelectGadget<F>,
    minimum_word_size: MemoryWordSizeGadget<F>,
    memory_address: MemoryExpandedAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    // Init code size is overflow when it is greater than 49152
    // (maximum init code size) if Shanghai, otherwise when it is greater than
    // 0x1FFFFFFFE0 (maximum value of offset + size).
    // Uint64 overflow is checked in `memory_address` (offset + length).
    init_code_size_overflow: LtGadget<F, { N_BYTES_MEMORY_ADDRESS }>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGCreateGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasCREATE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasCREATE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_create2 = PairSelectGadget::construct(
            cb,
            opcode.expr(),
            OpcodeId::CREATE2.expr(),
            OpcodeId::CREATE.expr(),
        );

        let value = cb.query_word_rlc();
        let salt = cb.query_word_rlc();

        let memory_address = MemoryExpandedAddressGadget::construct_self(cb);

        cb.stack_pop(value.expr());
        cb.stack_pop(memory_address.offset_rlc());
        cb.stack_pop(memory_address.length_rlc());
        cb.condition(is_create2.expr().0, |cb| cb.stack_pop(salt.expr()));

        let init_code_size_overflow =
            LtGadget::construct(cb, MAX_INIT_CODE_SIZE.expr(), memory_address.length());

        let minimum_word_size = MemoryWordSizeGadget::construct(cb, memory_address.length());
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        let keccak_gas_cost = minimum_word_size.expr()
            * select::expr(
                is_create2.expr().0,
                CREATE2_GAS_PER_CODE_WORD.expr(),
                CREATE_GAS_PER_CODE_WORD.expr(),
            );
        let gas_cost = GasCost::CREATE.expr() + memory_expansion.gas_cost() + keccak_gas_cost;
        let insufficient_gas = LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);

        cb.require_equal(
            "Memory address is overflow, init code size is overflow, or gas left is less than cost",
            or::expr([
                memory_address.overflow(),
                init_code_size_overflow.expr(),
                insufficient_gas.expr(),
            ]),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(
            cb,
            opcode.expr(),
            select::expr(is_create2.expr().0, 6.expr(), 5.expr()),
        );

        Self {
            opcode,
            value,
            salt,
            is_create2,
            minimum_word_size,
            memory_address,
            memory_expansion,
            init_code_size_overflow,
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
        log::debug!(
            "ErrorOutOfGasCREATE: gas_cost = {}, gas_left = {}",
            step.gas_cost,
            step.gas_left,
        );

        let opcode = step.opcode.unwrap();
        let is_create2 = opcode == OpcodeId::CREATE2;
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.is_create2.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::CREATE2.as_u64()),
            F::from(OpcodeId::CREATE.as_u64()),
        )?;

        let [value, memory_offset, memory_length] =
            [0, 1, 2].map(|idx| block.rws[step.rw_indices[idx]].stack_value());
        let salt = if is_create2 {
            block.rws[step.rw_indices[3]].stack_value()
        } else {
            U256::zero()
        };

        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        self.salt.assign(region, offset, Some(salt.to_le_bytes()))?;

        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_length)?;

        let init_code_size =
            MemoryExpandedAddressGadget::<F>::length_value(memory_offset, memory_length);
        let minimum_word_size = self
            .minimum_word_size
            .assign(region, offset, init_code_size)?;
        let memory_expansion_gas = self
            .memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?
            .1;

        self.init_code_size_overflow.assign(
            region,
            offset,
            F::from(MAX_INIT_CODE_SIZE),
            F::from(init_code_size),
        )?;

        let keccak_gas_cost = minimum_word_size
            * if is_create2 {
                CREATE2_GAS_PER_CODE_WORD
            } else {
                CREATE_GAS_PER_CODE_WORD
            };
        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(GasCost::CREATE.as_u64() + memory_expansion_gas + keccak_gas_cost),
        )?;

        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            if is_create2 { 6 } else { 5 },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, word, Bytecode, ToWord};
    use mock::{
        eth,
        test_ctx::{helpers::account_0_code_account_1_no_code, LoggerConfig},
        TestContext, MOCK_ACCOUNTS, MOCK_BLOCK_GAS_LIMIT,
    };

    struct TestCase {
        bytecode: Bytecode,
        gas: u64,
    }

    impl TestCase {
        pub fn new(is_create2: bool, offset: U256, size: U256, gas: u64) -> Self {
            let mut bytecode = Bytecode::default();
            if is_create2 {
                bytecode.append(&bytecode! {PUSH1(0)}); // salt;
            }
            bytecode.append(&bytecode! {
                PUSH32(size) // size
                PUSH32(offset) // offset
                PUSH1(0) // value
            });
            bytecode.write_op(if is_create2 {
                OpcodeId::CREATE2
            } else {
                OpcodeId::CREATE
            });

            Self { bytecode, gas }
        }
    }

    #[test]
    fn test_oog_create_simple() {
        let mut cases = vec![];
        for is_create2 in [true, false] {
            cases.push(TestCase::new(
                is_create2,
                0xffffffff_u64.into(),
                0xff.into(),
                0xffff,
            ));

            cases.push(TestCase::new(is_create2, U256::zero(), 4.into(), 0x7d08));
        }

        for case in cases.iter() {
            test_root(case);
            test_internal(case);
        }
    }

    #[test]
    fn test_oog_create_max_expanded_address() {
        for is_create2 in [true, false] {
            // 0xffffffff1 + 0xffffffff0 = 0x1fffffffe1
            // > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
            let case = TestCase::new(
                is_create2,
                0xffffffff1_u64.into(),
                0xffffffff0_u64.into(),
                MOCK_BLOCK_GAS_LIMIT,
            );

            test_root(&case);
            test_internal(&case);
        }
    }

    #[test]
    fn test_oog_create_max_u64_address() {
        for is_create2 in [true, false] {
            let case = TestCase::new(
                is_create2,
                u64::MAX.into(),
                u64::MAX.into(),
                MOCK_BLOCK_GAS_LIMIT,
            );

            test_root(&case);
            test_internal(&case);
        }
    }

    #[test]
    fn test_oog_create_max_word_address() {
        for is_create2 in [true, false] {
            let case = TestCase::new(is_create2, U256::MAX, U256::MAX, MOCK_BLOCK_GAS_LIMIT);

            test_root(&case);
            test_internal(&case);
        }
    }

    #[test]
    fn test_oog_create_max_init_code_size() {
        for is_create2 in [true, false] {
            // For Shanghai, MAX_INIT_CODE_SIZE is 49152, it is constrained by
            // `init_code_size_overflow`.
            // For not Shanghai, MAX_INIT_CODE_SIZE is 0x1FFFFFFFE0, it is
            // constrained by `memory_address.overflow()`
            // (and `init_code_size_overflow`).
            let case = TestCase::new(
                is_create2,
                U256::zero(),
                (MAX_INIT_CODE_SIZE + 1).into(),
                MOCK_BLOCK_GAS_LIMIT,
            );

            test_root(&case);
            test_internal(&case);
        }
    }

    fn test_root(case: &TestCase) {
        let ctx = TestContext::<2, 1>::new_with_logger_config(
            None,
            account_0_code_account_1_no_code(case.bytecode.clone()),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas(case.gas.into());
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
