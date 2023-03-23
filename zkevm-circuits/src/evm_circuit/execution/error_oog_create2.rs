use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS},
        step::ExecutionState,
        util::{
            and,
            common_gadget::CommonErrorGadget,
            constraint_builder::ConstraintBuilder,
            math_gadget::{IsZeroGadget, LtGadget},
            memory_gadget::{
                address_high, address_low, MemoryExpansionGadget, MemoryWordSizeGadget,
            },
            CachedRegion, Cell, Word,
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
    address: Word<F>,
    size: Word<F>,
    salt: Word<F>,
    address_in_range_high: IsZeroGadget<F>,
    size_in_range_high: IsZeroGadget<F>,
    expanded_address_in_range: LtGadget<F, { N_BYTES_MEMORY_ADDRESS + 1 }>,
    minimum_word_size: MemoryWordSizeGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_ADDRESS>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    // gupeng
    // rw_counter_end_of_reversion: Cell<F>,
    // restore_context: RestoreContextGadget<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGCreate2Gadget<F> {
    const NAME: &'static str = "ErrorOutOfGasCREATE2";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasCREATE2;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        cb.require_equal(
            "ErrorOutOfGasCREATE2 opcode must be CREATE2",
            opcode.expr(),
            OpcodeId::CREATE2.expr(),
        );

        let value = cb.query_word_rlc();
        cb.stack_pop(value.expr());
        let address = cb.query_word_rlc();
        cb.stack_pop(address.expr());
        let size = cb.query_word_rlc();
        cb.stack_pop(size.expr());
        let salt = cb.query_word_rlc();
        cb.stack_pop(salt.expr());

        let address_high = address_high::expr(&address);
        let address_in_range_high = IsZeroGadget::construct(cb, address_high);
        let size_high = address_high::expr(&size);
        let size_in_range_high = IsZeroGadget::construct(cb, size_high);
        let address_low = address_low::expr(&address);
        let size_low = address_low::expr(&size);
        let expanded_address = address_low.expr() + size_low.expr();
        let expanded_address_in_range = LtGadget::construct(
            cb,
            expanded_address.expr(),
            (1u64 << (N_BYTES_MEMORY_ADDRESS * 8)).expr(),
        );

        cb.require_equal(
            "address and size must less than 5 bytes",
            and::expr([
                address_in_range_high.expr(),
                size_in_range_high.expr(),
                expanded_address_in_range.expr(),
            ]),
            true.expr(),
        );

        let minimum_word_size = MemoryWordSizeGadget::construct(cb, size_low.expr());

        let memory_expansion =
            MemoryExpansionGadget::construct(cb, [address_low::expr(&address) + size_low.expr()]);

        let insufficient_gas = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            OpcodeId::CREATE2.constant_gas_cost().expr()
                + memory_expansion.gas_cost()
                + 6.expr() * minimum_word_size.expr(),
        );

        cb.require_equal(
            "gas_left must less than gas_cost",
            insufficient_gas.expr(),
            true.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 6.expr());

        Self {
            opcode,
            value,
            address,
            size,
            salt,
            address_in_range_high,
            size_in_range_high,
            expanded_address_in_range,
            minimum_word_size,
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

        let address = block.rws[step.rw_indices[1]].stack_value();
        let size = block.rws[step.rw_indices[2]].stack_value();
        self.address
            .assign(region, offset, Some(address.to_le_bytes()))?;
        self.size.assign(region, offset, Some(size.to_le_bytes()))?;

        self.salt.assign(
            region,
            offset,
            Some(block.rws[step.rw_indices[3]].stack_value().to_le_bytes()),
        )?;

        let address_high = address_high::value::<F>(address.to_le_bytes());
        assert_eq!(
            address_high,
            F::zero(),
            "address overflow {} bytes",
            N_BYTES_MEMORY_ADDRESS
        );
        self.address_in_range_high
            .assign(region, offset, address_high)?;
        let size_high = address_high::value::<F>(size.to_le_bytes());
        assert_eq!(
            size_high,
            F::zero(),
            "size overflow {} bytes",
            N_BYTES_MEMORY_ADDRESS
        );
        self.size_in_range_high.assign(region, offset, size_high)?;

        let address_value = address_low::value(address.to_le_bytes());
        let size_value = address_low::value(size.to_le_bytes());
        let expanded_address = address_value
            .checked_add(size_value)
            .expect("address overflow u64");
        assert!(
            expanded_address < (1u64 << (N_BYTES_MEMORY_ADDRESS * 8)),
            "expanded address overflow {} bytes",
            N_BYTES_MEMORY_ADDRESS
        );
        self.expanded_address_in_range.assign(
            region,
            offset,
            F::from(expanded_address),
            F::from(1u64 << (N_BYTES_MEMORY_ADDRESS * 8)),
        )?;

        let minimum_word_size = self.minimum_word_size.assign(region, offset, size_value)?;
        let memory_expansion_gas = self
            .memory_expansion
            .assign(region, offset, step.memory_word_size(), [expanded_address])?
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
    use eth_types::{bytecode, word, Bytecode, ToWord, Word};
    use mock::{
        eth,
        test_ctx::{helpers::account_0_code_account_1_no_code, LoggerConfig},
        TestContext, MOCK_ACCOUNTS,
    };

    struct TestCase {
        bytecode: Bytecode,
        gas: Word,
    }

    #[test]
    fn test_oog_create2() {
        let cases = [
            // memory expansion
            TestCase {
                bytecode: bytecode! {
                    PUSH8(0x0)
                    PUSH8(0xFF)
                    PUSH32(word!("0xffffffff")) // offset
                    PUSH8(0x0) // value
                    CREATE2
                    STOP
                },
                gas: word!("0xFFFF"),
            },
            // simple
            TestCase {
                bytecode: bytecode! {
                    PUSH1(2)
                    PUSH1(4)
                    PUSH1(0x0)
                    PUSH1(0x0)
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

        println!("{:?}", ctx.geth_traces[0]);

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
