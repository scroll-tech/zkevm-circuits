use crate::evm_circuit::{
    execution::ExecutionGadget,
    param::N_BYTES_GAS,
    step::ExecutionState,
    util::{
        common_gadget::CommonErrorGadget, constraint_builder::ConstraintBuilder,
        math_gadget::LtGadget, CachedRegion, Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGConstantGadget<F> {
    opcode: Cell<F>,
    // constrain gas left is less than required
    gas_required: Cell<F>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGConstantGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasConstant";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasConstant;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let gas_required = cb.query_cell();

        cb.constant_gas_lookup(opcode.expr(), gas_required.expr());
        // Check if the amount of gas available is less than the amount of gas
        // required
        let insufficient_gas =
            LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_required.expr());
        cb.require_equal(
            "constant gas left is less than gas required ",
            insufficient_gas.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 2.expr());

        Self {
            opcode,
            gas_required,
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
        // Inputs/Outputs
        self.gas_required
            .assign(region, offset, Value::known(F::from(step.gas_cost)))?;
        // Gas insufficient check
        // Get `gas_available` variable here once it's available
        self.insufficient_gas.assign(
            region,
            offset,
            F::from(step.gas_left),
            F::from(step.gas_cost),
        )?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 2)?;
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

    fn test_oog_constant(tx: eth_types::Transaction, is_success: bool) {
        let code = if is_success {
            bytecode! {
                PUSH1(0)
                PUSH1(0)
                RETURN
            }
        } else {
            bytecode! {
                PUSH1(0)
                PUSH1(0)
            }
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
                    .gas(tx.gas - 1)
                    .input(tx.input)
                    .value(tx.value);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    // TODO: Use `mock` crate
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
    fn test_oog_constant_root() {
        // in root call , out of gas constant happens
        test_oog_constant(mock_tx(eth(1), gwei(2), vec![]), false);
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
            gas: 10,
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
            //PUSH1(0)
            //PUSH1(0)
            .write_op(terminator)
        };

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(20.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
    }

    fn oog_constant_internal_call(caller: Account, callee: Account) {
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
                    .gas(23800.into());
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
    fn test_oog_constant_internal() {
        let bytecode = bytecode! {
            PUSH32(Word::from(0))
            PUSH32(Word::from(1))
            PUSH32(Word::from(2))
            PUSH32(Word::from(10))
            PUSH32(Word::from(224))
            PUSH32(Word::from(1025))
            PUSH32(Word::from(5089))
            STOP
        };
        let callee = callee(bytecode);
        oog_constant_internal_call(caller(), callee);
    }
}
