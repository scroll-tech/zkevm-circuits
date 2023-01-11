use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_ACCOUNT_ADDRESS;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::SameContextGadget;
use crate::evm_circuit::util::constraint_builder::Transition::Delta;
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, ReversionInfo, StepStateTransition,
};
use crate::evm_circuit::util::{
    from_bytes, select, CachedRegion, Cell, RandomLinearCombination, Word,
};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Rw, Transaction};
use crate::table::{AccountFieldTag, CallContextFieldTag};
use crate::util::Expr;
use eth_types::evm_types::GasCost;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct BalanceGadget<F> {
    same_context: SameContextGadget<F>,
    address_word: Word<F>,
    reversion_info: ReversionInfo<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    balance: Cell<F>,
    exists: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for BalanceGadget<F> {
    const NAME: &'static str = "BALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BALANCE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let address_word = cb.query_word();
        let address = from_bytes::expr(&address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);
        cb.stack_pop(address_word.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let is_warm = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            address.expr(),
            1.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        let balance = cb.query_cell();
        let exists = cb.query_bool();
        cb.condition(exists.expr(), |cb| {
            cb.account_read(address.expr(), AccountFieldTag::Balance, balance.expr());
        });
        cb.condition(1.expr() - exists.expr(), |cb| {
            cb.account_read(address, AccountFieldTag::NonExisting, 0.expr());
        });

        cb.stack_push(select::expr(exists.expr(), balance.expr(), 0.expr()));

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(7.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-gas_cost),
            reversible_write_counter: Delta(1.expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address_word,
            reversion_info,
            tx_id,
            is_warm,
            balance,
            exists,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        let address = block.rws[step.rw_indices[0]].stack_value();
        self.address_word
            .assign(region, offset, Some(address.to_le_bytes()))?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;

        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;

        let (_, is_warm) = block.rws[step.rw_indices[4]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm)))?;

        let (balance, exists) = match block.rws[step.rw_indices[5]] {
            Rw::Account {
                field_tag: AccountFieldTag::Balance,
                value,
                ..
            } => (value, true),
            Rw::Account {
                field_tag: AccountFieldTag::NonExisting,
                ..
            } => (0.into(), false),
            _ => unreachable!(),
        };
        self.balance.assign(
            region,
            offset,
            Value::known(RandomLinearCombination::random_linear_combine(
                balance.to_le_bytes(),
                block.randomness,
            )),
        )?;
        self.exists
            .assign(region, offset, Value::known(F::from(exists)))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::run_test_circuits;
    use eth_types::geth_types::Account;
    use eth_types::{address, bytecode, Address, Bytecode, ToWord, Word, U256};
    use lazy_static::lazy_static;
    use mock::TestContext;

    lazy_static! {
        static ref TEST_ADDRESS: Address = address!("0xaabbccddee000000000000000000000000000000");
    }

    #[test]
    fn balance_gadget_non_existing_account() {
        test_root_ok(&None, false);
        test_internal_ok(0x20, 0x00, &None, false);
        test_internal_ok(0x1010, 0xff, &None, false);
    }

    #[test]
    fn balance_gadget_empty_account() {
        let account = Some(Account::default());

        test_root_ok(&account, false);
        test_internal_ok(0x20, 0x00, &account, false);
        test_internal_ok(0x1010, 0xff, &account, false);
    }

    #[test]
    fn balance_gadget_cold_account() {
        let account = Some(Account {
            address: *TEST_ADDRESS,
            balance: U256::from(900),
            ..Default::default()
        });

        test_root_ok(&account, false);
        test_internal_ok(0x20, 0x00, &account, false);
        test_internal_ok(0x1010, 0xff, &account, false);
    }

    #[test]
    fn balance_gadget_warm_account() {
        let account = Some(Account {
            address: *TEST_ADDRESS,
            balance: U256::from(900),
            ..Default::default()
        });

        test_root_ok(&account, true);
        test_internal_ok(0x20, 0x00, &account, true);
        test_internal_ok(0x1010, 0xff, &account, true);
    }

    fn test_root_ok(account: &Option<Account>, is_warm: bool) {
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);

        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                PUSH20(address.to_word())
                BALANCE
                POP
            });
        }
        code.append(&bytecode! {
            PUSH20(address.to_word())
            BALANCE
            STOP
        });

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
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }

    fn test_internal_ok(
        call_data_offset: usize,
        call_data_length: usize,
        account: &Option<Account>,
        is_warm: bool,
    ) {
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let mut code_b = Bytecode::default();
        if is_warm {
            code_b.append(&bytecode! {
                PUSH20(address.to_word())
                BALANCE
                POP
            });
        }
        code_b.append(&bytecode! {
            PUSH20(address.to_word())
            BALANCE
            STOP
        });

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
            PUSH32(0x1_0000) // gas
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

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }
}
