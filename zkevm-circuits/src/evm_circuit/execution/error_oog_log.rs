use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::ConstraintBuilder,
            math_gadget::LtGadget,
            memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::Field;
use eth_types::{evm_types::GasCost, evm_types::OpcodeId};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGLogGadget<F> {
    opcode: Cell<F>,
    // memory address
    memory_address: MemoryAddressGadget<F>,
    is_static_call: Cell<F>,
    is_opcode_logn: LtGadget<F, 1>,
    // constrain gas left is less than gas cost
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGLogGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasLOG";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasLOG;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let mstart = cb.query_cell_phase2();
        let msize = cb.query_word_rlc();

        // Pop mstart_address, msize from stack
        cb.stack_pop(mstart.expr());
        cb.stack_pop(msize.expr());

        // constrain not in static call
        let is_static_call = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static_call is false in LOGN", is_static_call.expr());

        let topic_count = opcode.expr() - OpcodeId::LOG0.as_u8().expr();
        let is_opcode_logn = LtGadget::construct(cb, topic_count.clone(), 5.expr());
        cb.require_equal(
            "topic count in [0..5) which means opcode is Log0...Log4 ",
            is_opcode_logn.expr(),
            1.expr(),
        );

        // check memory
        let memory_address = MemoryAddressGadget::construct(cb, mstart, msize);

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        let gas_cost = GasCost::LOG.as_u64().expr()
            + GasCost::LOG.as_u64().expr() * topic_count
            + 8.expr() * memory_address.length()
            + memory_expansion.gas_cost();

        // Check if the amount of gas available is less than the amount of gas
        // required
        let insufficient_gas = LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);
        cb.require_equal(
            "gas left is less than gas required ",
            insufficient_gas.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 5.expr());

        Self {
            opcode,
            is_static_call,
            is_opcode_logn,
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
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let [memory_start, msize] =
            [step.rw_indices[0], step.rw_indices[1]].map(|idx| block.rws[idx].stack_value());

        let memory_address = self
            .memory_address
            .assign(region, offset, memory_start, msize)?;

        // Memory expansion
        self.memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?;

        let topic_count = opcode.postfix().expect("opcode with postfix") as u64;
        assert!(topic_count <= 4);
        self.is_static_call
            .assign(region, offset, Value::known(F::from(call.is_static as u64)))?;

        self.is_opcode_logn
            .assign(region, offset, F::from(topic_count), F::from(5u64))?;

        // Gas insufficient check
        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(step.gas_cost),
        )?;
        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;

    use bus_mapping::evm::OpcodeId;
    use eth_types::{
        self, address, bytecode, bytecode::Bytecode, evm_types::GasCost, geth_types::Account,
        Address, ToWord, Word,
    };

    use mock::{
        eth, gwei, test_ctx::helpers::account_0_code_account_1_no_code, TestContext, MOCK_ACCOUNTS,
    };

    fn gas(call_data: &[u8]) -> Word {
        Word::from(
            GasCost::TX.as_u64()
                + 2 * OpcodeId::PUSH32.constant_gas_cost().as_u64()
                + call_data
                    .iter()
                    .map(|&x| if x == 0 { 4 } else { 16 })
                    .sum::<u64>(),
        )
    }

    fn test_oog_log(tx: eth_types::Transaction) {
        let code = bytecode! {
                PUSH1(0)
                PUSH1(0)
                PUSH1(100)
                LOG0
        };

        // Get the execution steps from the external tracer
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, _accs| {
                txs[0]
                    .to(tx.to.unwrap())
                    .from(tx.from)
                    .gas_price(tx.gas_price.unwrap())
                    .gas(tx.gas + 5)
                    .input(tx.input)
                    .value(tx.value);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn mock_tx(value: Word, gas_price: Word, calldata: Vec<u8>) -> eth_types::Transaction {
        let from = MOCK_ACCOUNTS[1];
        let to = MOCK_ACCOUNTS[0];
        eth_types::Transaction {
            from,
            to: Some(to),
            value,
            gas: gas(&calldata),
            gas_price: Some(gas_price),
            input: calldata.into(),
            ..Default::default()
        }
    }

    #[test]
    // test oog log in root call
    fn test_oog_log_root() {
        test_oog_log(mock_tx(eth(1), gwei(2), vec![]));
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Stack {
        gas: u64,
        value: Word,
        cd_offset: u64,
        cd_length: u64,
        rd_offset: u64,
        rd_length: u64,
    }

    fn caller() -> Account {
        let terminator = OpcodeId::REVERT;

        let stack = Stack {
            gas: 100,
            cd_offset: 64,
            cd_length: 320,
            rd_offset: 0,
            rd_length: 32,
            ..Default::default()
        };
        let bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
            PUSH32(stack.value)
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            CALL
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
            PUSH32(stack.value)
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            CALL
            .write_op(terminator)
        };

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(20.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
    }

    fn oog_log_internal_call(caller: Account, callee: Account) {
        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(10u64.pow(19)));
                accs[1]
                    .address(caller.address)
                    .code(caller.code)
                    .nonce(caller.nonce)
                    .balance(caller.balance);
                accs[2]
                    .address(callee.address)
                    .code(callee.code)
                    .nonce(callee.nonce)
                    .balance(callee.balance);
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(accs[1].address)
                    .gas(24000.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn callee(code: Bytecode) -> Account {
        let code = code.to_vec();
        let is_empty = code.is_empty();
        Account {
            address: Address::repeat_byte(0xff),
            code: code.into(),
            nonce: if is_empty { 0 } else { 1 }.into(),
            balance: if is_empty { 0 } else { 0xdeadbeefu64 }.into(),
            ..Default::default()
        }
    }

    #[test]
    // test oog log in internal call
    fn test_oog_log_internal() {
        let bytecode = bytecode! {
            PUSH32(Word::from(0))
            PUSH32(Word::from(10))
            PUSH32(Word::from(224))
            PUSH32(Word::from(1025))
            PUSH32(Word::from(5089))
            LOG2
            STOP
        };
        let callee = callee(bytecode);
        oog_log_internal_call(caller(), callee);
    }
}
