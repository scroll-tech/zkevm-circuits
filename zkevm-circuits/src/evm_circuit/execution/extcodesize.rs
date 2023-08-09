use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::Delta,
            },
            from_bytes,
            math_gadget::IsZeroGadget,
            not, select, CachedRegion, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ExtcodesizeGadget<F> {
    same_context: SameContextGadget<F>,
    address_word: Word<F>,
    reversion_info: ReversionInfo<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    code_hash: Cell<F>,
    not_exists: IsZeroGadget<F>,
    code_size: RandomLinearCombination<F, N_BYTES_U64>,
}

impl<F: Field> ExecutionGadget<F> for ExtcodesizeGadget<F> {
    const NAME: &'static str = "EXTCODESIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODESIZE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let address_word = cb.query_word_rlc();
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

        let code_hash = cb.query_cell_phase2();
        // For non-existing accounts the code_hash must be 0 in the rw_table.
        cb.account_read(address.expr(), AccountFieldTag::CodeHash, code_hash.expr());
        let not_exists = IsZeroGadget::construct(cb, "", code_hash.expr());
        let exists = not::expr(not_exists.expr());

        let code_size = cb.query_word_rlc();
        cb.condition(exists.expr(), |cb| {
            #[cfg(feature = "scroll")]
            cb.account_read(
                address.expr(),
                AccountFieldTag::CodeSize,
                from_bytes::expr(&code_size.cells),
            );
            #[cfg(not(feature = "scroll"))]
            cb.bytecode_length(code_hash.expr(), from_bytes::expr(&code_size.cells));
        });

        cb.condition(not_exists.expr(), |cb| {
            cb.require_zero("code_size is zero when non_exists", code_size.expr());
        });

        cb.stack_push(code_size.expr());

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let rw_counter_delta = 7.expr();
        #[cfg(feature = "scroll")]
        let rw_counter_delta = rw_counter_delta + exists;
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(rw_counter_delta),
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
            code_hash,
            not_exists,
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

        let code_hash = block.rws[step.rw_indices[5]].account_value_pair().0;
        self.code_hash
            .assign(region, offset, region.code_hash(code_hash))?;
        self.not_exists
            .assign_value(region, offset, region.code_hash(code_hash))?;

        let rw_offset = 6;
        #[cfg(feature = "scroll")]
        let rw_offset = if code_hash.is_zero() {
            rw_offset
        } else {
            rw_offset + 1
        };
        let code_size = block.rws[step.rw_indices[rw_offset]].stack_value().as_u64();
        self.code_size
            .assign(region, offset, Some(code_size.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, geth_types::Account, Bytecode, ToWord};
    use mock::{
        generate_mock_call_bytecode, MockCallBytecodeParams, TestContext, MOCK_1_ETH,
        MOCK_ACCOUNTS, MOCK_CODES,
    };

    #[test]
    fn test_extcodesize_gadget_simple() {
        // Test for empty account.
        let mut empty_address_bytes = [0; 20];
        empty_address_bytes[12] = 234;
        assert!(Account::default().is_empty());
        test_ok(
            &Account {
                address: empty_address_bytes.into(),
                ..Default::default()
            },
            false,
        );

        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[4].clone(),
            ..Default::default()
        };
        // Test for cold account.
        test_ok(&account, false);
        // Test for warm account.
        test_ok(&account, true);
    }

    #[test]
    fn test_extcodesize_gadget_with_long_code() {
        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[5].clone(), // ADDRESS * 256
            ..Default::default()
        };

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
        let code_a = generate_mock_call_bytecode(MockCallBytecodeParams {
            address: addr_b,
            pushdata: rand_bytes(32),
            call_data_length: 0xffusize,
            call_data_offset: 0x1010usize,
            ..MockCallBytecodeParams::default()
        });

        let ctx = TestContext::<4, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(bytecode_b);
                accs[1].address(addr_a).code(code_a);
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

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
