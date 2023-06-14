use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes,
            math_gadget::LtGadget,
            select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field, ToLittleEndian,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::EXP`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGAccountAccessGadget<F> {
    opcode: Cell<F>,
    address_word: Word<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    insufficient_gas_cost: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGAccountAccessGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasAccountAccess";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasAccountAccess;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.require_in_set(
            "ErrorOutOfGasAccountAccess happens for BALANCE | EXTCODESIZE | EXTCODEHASH ",
            opcode.expr(),
            vec![
                OpcodeId::BALANCE.expr(),
                OpcodeId::EXTCODESIZE.expr(),
                OpcodeId::EXTCODEHASH.expr(),
            ],
        );

        let address_word = cb.query_word_rlc();
        let address = from_bytes::expr(&address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);
        cb.stack_pop(address_word.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_warm = cb.query_bool();
        // read is_warm
        cb.account_access_list_read(tx_id.expr(), address.expr(), is_warm.expr());

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let insufficient_gas_cost =
            LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);

        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas_cost.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 5.expr());
        Self {
            opcode,
            address_word,
            tx_id,
            is_warm,
            insufficient_gas_cost,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let address = block.rws[step.rw_indices[0]].stack_value();
        self.address_word
            .assign(region, offset, Some(address.to_le_bytes()))?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;

        let (_, is_warm) = block.rws[step.rw_indices[2]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm)))?;

        // BALANCE EXTCODESIZE EXTCODEHASH shares same gas cost model
        let gas_cost = if is_warm {
            GasCost::WARM_ACCESS
        } else {
            GasCost::COLD_ACCOUNT_ACCESS
        };

        self.insufficient_gas_cost.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(gas_cost.as_u64())),
        )?;
        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{
        address, bytecode,
        evm_types::{GasCost, OpcodeId},
        geth_types::Account,
        Address, Bytecode, ToWord, Word, U256,
    };
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use mock::TestContext;

    lazy_static! {
        static ref TEST_ADDRESS: Address = address!("0xaabbccddee000000000000000000000000000000");
    }

    #[test]
    fn oog_account_access_root() {
        let account = Some(Account {
            address: *TEST_ADDRESS,
            balance: U256::from(900),
            ..Default::default()
        });

        for (opcode, is_warm) in [
            OpcodeId::BALANCE,
            OpcodeId::EXTCODESIZE,
            OpcodeId::EXTCODEHASH,
        ]
        .iter()
        .cartesian_product([true, false])
        {
            test_root_ok(&account, *opcode, is_warm);
        }
    }

    #[test]
    fn oog_account_internal() {
        let account = Some(Account {
            address: *TEST_ADDRESS,
            balance: U256::from(900),
            ..Default::default()
        });

        for (opcode, is_warm) in [
            OpcodeId::BALANCE,
            OpcodeId::EXTCODESIZE,
            OpcodeId::EXTCODEHASH,
        ]
        .iter()
        .cartesian_product([false, true])
        {
            test_internal_ok(0x20, 0x20, &account, *opcode, is_warm);
            test_internal_ok(0x1010, 0xff, &account, *opcode, is_warm);
        }
    }

    fn test_root_ok(account: &Option<Account>, opcode: OpcodeId, is_warm: bool) {
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);

        let mut code = Bytecode::default();
        if is_warm {
            code.push(20, address.to_word());
            code.write_op(opcode);
            code.write_op(OpcodeId::POP);
        }

        code.push(20, address.to_word());
        code.write_op(opcode);
        code.write_op(OpcodeId::STOP);

        let gas = GasCost::TX.0
            + if is_warm {
                GasCost::WARM_ACCESS.as_u64()
                    + OpcodeId::PUSH32.constant_gas_cost().0
                    + OpcodeId::POP.constant_gas_cost().0
                    + GasCost::COLD_ACCOUNT_ACCESS.as_u64()
            } else {
                GasCost::COLD_ACCOUNT_ACCESS.as_u64()
            }
            + OpcodeId::PUSH32.constant_gas_cost().0
            - 1;
        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(1_u64 << 20))
                    .code(code);
                // Set balance if account exists.
                if let Some(account) = account {
                    accs[1].address(address).balance(account.balance);
                } else {
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000010"))
                        .balance(Word::from(1_u64 << 20));
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000000020"))
                    .balance(Word::from(1_u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[2].address)
                    .gas(gas.into());
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_internal_ok(
        call_data_offset: usize,
        call_data_length: usize,
        account: &Option<Account>,
        opcode: OpcodeId,
        is_warm: bool,
    ) {
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let mut code_b = Bytecode::default();
        if is_warm {
            code_b.push(20, address.to_word());

            code_b.write_op(opcode);
            code_b.write_op(OpcodeId::POP);
        }

        code_b.push(20, address.to_word());
        code_b.write_op(opcode);
        code_b.write_op(OpcodeId::STOP);

        // code A calls code B.
        let pushdata = rand_bytes(8);
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(Word::from(2599u64)) // gas insufficient
            CALL
            STOP
        };

        let ctx = TestContext::<4, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                // Set balance if account exists.
                if let Some(account) = account {
                    accs[2].address(address).balance(account.balance);
                } else {
                    accs[2]
                        .address(mock::MOCK_ACCOUNTS[2])
                        .balance(Word::from(1_u64 << 20));
                }
                accs[3]
                    .address(mock::MOCK_ACCOUNTS[3])
                    .balance(Word::from(1_u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[3].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
