use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::ToLittleEndian;
use eth_types::{evm_types::GasCost, Field, ToAddress, ToScalar, U256};
use ethers_core::utils::keccak256;
use halo2_proofs::{circuit::Region, plonk::Error};
use lazy_static::lazy_static;

lazy_static! {
    static ref EMPTY_CODE_HASH_LE_BYTES: [u8; 32] = U256::from(keccak256(&[])).to_le_bytes();
}

#[derive(Clone, Debug)]
pub(crate) struct ExtcodehashGadget<F> {
    same_context: SameContextGadget<F>,
    external_address: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    tx_id: Cell<F>,
    is_persistent: Cell<F>,
    rw_counter_end_of_reversion: Cell<F>,
    is_warm: Cell<F>,
    nonce: Cell<F>,
    balance: Cell<F>,
    code_hash: Cell<F>,
    is_empty: Cell<F>, // boolean for if the external account is empty
    nonempty_witness: Cell<F>, /* if the account isn't empty, will witness that by holding
                        * inverse of one of balance, nonce, or RLC(code hash) -
                        * RLC(EMPTY_CODE_HASH_LE_BYTES) */
}

impl<F: Field> ExecutionGadget<F> for ExtcodehashGadget<F> {
    const NAME: &'static str = "EXTCODEHASH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODEHASH;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let external_address = cb.query_rlc();
        cb.stack_pop(external_address.expr());

        let [tx_id, rw_counter_end_of_reversion, is_persistent] = [
            CallContextFieldTag::TxId,
            CallContextFieldTag::RwCounterEndOfReversion,
            CallContextFieldTag::IsPersistent,
        ]
        .map(|tag| cb.call_context(None, tag));

        let is_warm = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            from_bytes::expr(&external_address.cells),
            1.expr(),
            is_warm.expr(),
            Some(
                (
                    &is_persistent,
                    rw_counter_end_of_reversion.expr() - cb.curr.state.state_write_counter.expr(),
                )
                    .into(),
            ),
        );

        let nonce = cb.query_cell();
        cb.account_read(
            from_bytes::expr(&external_address.cells),
            AccountFieldTag::Nonce,
            nonce.expr(),
        );
        let balance = cb.query_cell();
        cb.account_read(
            from_bytes::expr(&external_address.cells),
            AccountFieldTag::Balance,
            balance.expr(),
        );
        let code_hash = cb.query_cell();
        cb.account_read(
            from_bytes::expr(&external_address.cells),
            AccountFieldTag::CodeHash,
            code_hash.expr(),
        );

        let is_empty = cb.query_bool();
        cb.require_zero(
            "is_empty is 0 when nonce is non-zero",
            is_empty.expr() * nonce.expr(),
        );
        // Note that balance is RLC encoded, but RLC(x) = 0 iff x = 0, so we don't need
        // go to the work of writing out the RLC expression
        cb.require_zero(
            "is_empty is 0 when balance is non-zero",
            is_empty.expr() * balance.expr(),
        );
        let empty_code_hash_rlc = Word::random_linear_combine_expr(
            EMPTY_CODE_HASH_LE_BYTES.map(|x| x.expr()),
            cb.power_of_randomness(),
        );
        cb.require_zero(
            "is_empty is 0 when code_hash is non-zero",
            is_empty.expr() * (code_hash.expr() - empty_code_hash_rlc.clone()),
        );

        let nonempty_witness = cb.query_cell();
        cb.require_zero(
            "is_empty is 1 if nonce, balance, and (code_hash - empty_code_hash_rlc) are all zero",
            (1.expr() - is_empty.expr())
                * (1.expr() - nonce.expr() * nonempty_witness.expr())
                * (1.expr() - balance.expr() * nonempty_witness.expr())
                * (1.expr() - (code_hash.expr() - empty_code_hash_rlc) * nonempty_witness.expr()),
        );

        // The stack push is 0 if the external account is empty. Otherwise, it's the
        // code hash
        cb.stack_push((1.expr() - is_empty.expr()) * code_hash.expr());

        let gas_cost = is_warm.expr() * GasCost::WARM_STORAGE_READ_COST.expr()
            + (1.expr() - is_warm.expr()) * GasCost::COLD_ACCOUNT_ACCESS_COST.expr();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-gas_cost),
            state_write_counter: Delta(1.expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            external_address,
            tx_id,
            is_persistent,
            rw_counter_end_of_reversion,
            is_warm,
            nonce,
            balance,
            code_hash,
            is_empty,
            nonempty_witness,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let external_address = block.rws[step.rw_indices[0]].stack_value().to_address();
        let mut le_bytes = external_address.0;
        le_bytes.reverse();
        self.external_address
            .assign(region, offset, Some(le_bytes))?;

        self.tx_id
            .assign(region, offset, U256::from(tx.id).to_scalar())?;
        self.is_persistent
            .assign(region, offset, Some(F::from(call.is_persistent as u64)))?;
        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Some(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;

        let is_warm = match GasCost::from(step.gas_cost) {
            GasCost::COLD_ACCOUNT_ACCESS_COST => 0,
            GasCost::WARM_STORAGE_READ_COST => 1,
            _ => unreachable!(),
        };
        self.is_warm
            .assign(region, offset, Some(F::from(is_warm)))?;

        let [nonce, balance, code_hash] = [5, 6, 7].map(|i| {
            block.rws[step.rw_indices[i]]
                .table_assignment(block.randomness)
                .value
        });
        self.nonce.assign(region, offset, Some(nonce))?;
        self.balance.assign(region, offset, Some(balance))?;
        self.code_hash.assign(region, offset, Some(code_hash))?;

        let empty_code_hash_rlc =
            Word::random_linear_combine(*EMPTY_CODE_HASH_LE_BYTES, block.randomness);

        if let Some(inverse) = Option::from(nonce.invert())
            .or_else(|| balance.invert().into())
            .or_else(|| (code_hash - empty_code_hash_rlc).invert().into())
        {
            self.nonempty_witness
                .assign(region, offset, Some(inverse))?;
        } else {
            self.is_empty.assign(region, offset, Some(F::one()))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        evm_circuit::witness::block_convert,
        test_util::{test_circuits_using_witness_block, BytecodeTestConfig},
    };
    use bus_mapping::mock::BlockData;
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

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .expect("could not handle block tx");

        test_circuits_using_witness_block(
            block_convert(&builder.block, &builder.code_db),
            BytecodeTestConfig::default(),
        )
        .unwrap();
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
