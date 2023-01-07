use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_ACCOUNT_ADDRESS;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::SameContextGadget;
use crate::evm_circuit::util::constraint_builder::Transition::Delta;
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, ReversionInfo, StepStateTransition,
};
use crate::evm_circuit::util::{from_bytes, select, CachedRegion, Cell, RandomLinearCombination};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Rw, Transaction};
use crate::table::{AccountFieldTag, CallContextFieldTag};
use crate::util::Expr;
use eth_types::evm_types::GasCost;
use eth_types::{Field, ToAddress, ToLittleEndian};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ExtcodesizeGadget<F> {
    same_context: SameContextGadget<F>,
    address: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    reversion_info: ReversionInfo<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    exists: Cell<F>,
    code_hash: Cell<F>,
    code_size: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for ExtcodesizeGadget<F> {
    const NAME: &'static str = "EXTCODESIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODESIZE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let address = cb.query_rlc();
        cb.stack_pop(address.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let is_warm = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            from_bytes::expr(&address.cells),
            1.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        let exists = cb.query_bool();
        let code_hash = cb.query_cell();
        let code_size = cb.condition(exists.expr(), |cb| {
            cb.account_read(
                from_bytes::expr(&address.cells),
                AccountFieldTag::CodeHash,
                code_hash.expr(),
            );
            cb.bytecode_length(code_hash.expr())
        });
        cb.condition(1.expr() - exists.expr(), |cb| {
            cb.account_read(
                from_bytes::expr(&address.cells),
                AccountFieldTag::NonExisting,
                0.expr(),
            );
        });

        cb.stack_push(select::expr(exists.expr(), code_size.expr(), 0.expr()));

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
            address,
            tx_id,
            reversion_info,
            is_warm,
            exists,
            code_hash,
            code_size,
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

        let address = block.rws[step.rw_indices[0]].stack_value().to_address();
        let mut address_bytes = address.0;
        address_bytes.reverse();
        self.address.assign(region, offset, Some(address_bytes))?;

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

        let (exists, code_hash) = match block.rws[step.rw_indices[5]] {
            Rw::Account {
                field_tag: AccountFieldTag::CodeHash,
                value,
                ..
            } => (true, value),
            Rw::Account {
                field_tag: AccountFieldTag::NonExisting,
                ..
            } => (false, 0.into()),
            _ => unreachable!(),
        };

        let code_size = block.rws[step.rw_indices[6]].stack_value().as_u64();

        self.exists
            .assign(region, offset, Value::known(F::from(exists)))?;
        self.code_hash.assign(
            region,
            offset,
            Value::known(RandomLinearCombination::random_linear_combine(
                code_hash.to_le_bytes(),
                block.randomness,
            )),
        )?;
        self.code_size
            .assign(region, offset, Value::known(F::from(code_size)))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::run_test_circuits;
    use eth_types::geth_types::Account;
    use eth_types::{bytecode, Bytecode, ToWord, Word};
    use mock::{TestContext, MOCK_1_ETH, MOCK_ACCOUNTS, MOCK_CODES};

    #[test]
    fn test_extcodesize_gadget() {
        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[4].clone(),
            ..Default::default()
        };

        // Test for empty account.
        test_ok(&Account::default(), false);
        // Test for cold account.
        test_ok(&account, false);
        // Test for warm account.
        test_ok(&account, true);
    }

    fn test_ok(account: &Account, is_warm: bool) {
        let account_exists = !account.is_empty();

        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let mut bytecode_b = Bytecode::default();
        if is_warm {
            bytecode_b.append(&bytecode! {
                PUSH20(account.address.to_word())
                EXTCODESIZE
                POP
            });
        }
        bytecode_b.append(&bytecode! {
            PUSH20(account.address.to_word())
            EXTCODESIZE
            POP
        });

        // code A calls code B.
        let pushdata = rand_bytes(8);
        let bytecode_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(0xff) // argsLength
            PUSH32(0x1010) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<4, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(bytecode_b);
                accs[1].address(addr_a).code(bytecode_a);
                // Set code if account exists.
                if account_exists {
                    accs[2].address(account.address).code(account.code.clone());
                } else {
                    accs[2].address(mock::MOCK_ACCOUNTS[2]).balance(*MOCK_1_ETH);
                }
                accs[3].address(mock::MOCK_ACCOUNTS[3]).balance(*MOCK_1_ETH);
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
