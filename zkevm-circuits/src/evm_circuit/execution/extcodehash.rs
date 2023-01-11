use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition, Transition::Delta,
            },
            from_bytes,
            math_gadget::BatchedIsZeroGadget,
            CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian};
use halo2_proofs::{circuit::Value, plonk::Error};
use keccak256::EMPTY_HASH_LE;

#[derive(Clone, Debug)]
pub(crate) struct ExtcodehashGadget<F> {
    same_context: SameContextGadget<F>,
    address_word: Word<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    is_warm: Cell<F>,
    nonce: Cell<F>,
    balance: Cell<F>,
    code_hash: Cell<F>,
    is_empty: BatchedIsZeroGadget<F, 3>, // boolean for if the external account is empty
}

impl<F: Field> ExecutionGadget<F> for ExtcodehashGadget<F> {
    const NAME: &'static str = "EXTCODEHASH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODEHASH;

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

        let nonce = cb.query_cell();
        cb.account_read(address.expr(), AccountFieldTag::Nonce, nonce.expr());
        let balance = cb.query_cell();
        cb.account_read(address.expr(), AccountFieldTag::Balance, balance.expr());
        let code_hash = cb.query_cell();
        cb.account_read(address, AccountFieldTag::CodeHash, code_hash.expr());

        let empty_code_hash_rlc = Word::random_linear_combine_expr(
            (*EMPTY_HASH_LE).map(|byte| byte.expr()),
            cb.power_of_randomness(),
        );
        // Note that balance is RLC encoded, but RLC(x) = 0 iff x = 0, so we don't need
        // go to the work of writing out the RLC expression
        let is_empty = BatchedIsZeroGadget::construct(
            cb,
            [
                nonce.expr(),
                balance.expr(),
                code_hash.expr() - empty_code_hash_rlc,
            ],
        );

        // The stack push is 0 if the external account is empty. Otherwise, it's the
        // code hash
        cb.stack_push((1.expr() - is_empty.expr()) * code_hash.expr());

        let gas_cost = is_warm.expr() * GasCost::WARM_ACCESS.expr()
            + (1.expr() - is_warm.expr()) * GasCost::COLD_ACCOUNT_ACCESS.expr();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
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
            tx_id,
            reversion_info,
            is_warm,
            nonce,
            balance,
            code_hash,
            is_empty,
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

        let is_warm = match GasCost::from(step.gas_cost) {
            GasCost::COLD_ACCOUNT_ACCESS => 0,
            GasCost::WARM_ACCESS => 1,
            _ => unreachable!(),
        };
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm)))?;

        let [nonce, balance, code_hash] = [5, 6, 7].map(|i| {
            block.rws[step.rw_indices[i]]
                .table_assignment_aux(block.randomness)
                .value
        });

        self.nonce.assign(region, offset, Value::known(nonce))?;
        self.balance.assign(region, offset, Value::known(balance))?;
        self.code_hash
            .assign(region, offset, Value::known(code_hash))?;

        let empty_code_hash_rlc = Word::random_linear_combine(*EMPTY_HASH_LE, block.randomness);
        self.is_empty.assign(
            region,
            offset,
            [nonce, balance, code_hash - empty_code_hash_rlc],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::test_circuits_block_geth_data_default;
    use eth_types::{
        address, bytecode,
        geth_types::{Account, GethData},
        Address, Bytecode, Bytes, ToWord, Word, U256,
    };
    use lazy_static::lazy_static;
    use mock::TestContext;

    lazy_static! {
        static ref EXTERNAL_ADDRESS: Address =
            address!("0xaabbccddee000000000000000000000000000000");
    }

    fn test_ok(external_account: Option<Account>, is_warm: bool) {
        let external_address = external_account
            .as_ref()
            .map(|a| a.address)
            .unwrap_or(*EXTERNAL_ADDRESS);

        // Make the external account warm, if needed, by first getting its external code
        // hash.
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                PUSH20(external_address.to_word())
                EXTCODEHASH // TODO: Change this to BALANCE once is implemented
                POP
            });
        }
        code.append(&bytecode! {
            PUSH20(external_address.to_word())
            #[start]
            EXTCODEHASH
            STOP
        });

        // Execute the bytecode and get trace
        let block: GethData = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(1u64 << 20))
                    .code(code);

                accs[1].address(external_address);
                if let Some(external_account) = external_account {
                    accs[1]
                        .balance(external_account.balance)
                        .nonce(external_account.nonce)
                        .code(external_account.code);
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        test_circuits_block_geth_data_default(block).unwrap();
    }

    #[test]
    fn extcodehash_warm_empty_account() {
        test_ok(None, true);
    }

    #[test]
    fn extcodehash_cold_empty_account() {
        test_ok(None, false);
    }

    #[test]
    fn extcodehash_warm_existing_account() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                nonce: U256::from(259),
                code: Bytes::from([3]),
                ..Default::default()
            }),
            true,
        );
    }

    #[test]
    fn extcodehash_cold_existing_account() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                balance: U256::from(900),
                code: Bytes::from([32, 59]),
                ..Default::default()
            }),
            false,
        );
    }

    #[test]
    fn extcodehash_nonempty_account_edge_cases() {
        // EIP-158 defines empty accounts to be those with balance = 0, nonce = 0, and
        // code = [].
        let nonce_only_account = Account {
            address: *EXTERNAL_ADDRESS,
            nonce: U256::from(200),
            ..Default::default()
        };
        // This account state is possible if another account sends ETH to a previously
        // empty account.
        let balance_only_account = Account {
            address: *EXTERNAL_ADDRESS,
            balance: U256::from(200),
            ..Default::default()
        };
        // This account state should no longer be possible because contract nonces start
        // at 1, per EIP-161. However, the requirement that the code be emtpy is still
        // in the yellow paper and our constraints, so we test this case
        // anyways.
        let contract_only_account = Account {
            address: *EXTERNAL_ADDRESS,
            code: Bytes::from([32, 59]),
            ..Default::default()
        };

        for account in [
            nonce_only_account,
            balance_only_account,
            contract_only_account,
        ] {
            test_ok(Some(account), false);
        }
    }
}
