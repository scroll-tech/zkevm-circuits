use crate::evm_circuit::{
    execution::ExecutionGadget,
    param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
    step::ExecutionState,
    util::{
        common_gadget::RestoreContextGadget,
        constraint_builder::{
            ConstraintBuilder, StepStateTransition,
            Transition::{Delta, Same},
        },
        from_bytes,
        math_gadget::{BatchedIsZeroGadget, IsEqualGadget, IsZeroGadget, LtGadget},
        memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget},
        select, sum, CachedRegion, Cell, Word,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use crate::table::{AccountFieldTag, CallContextFieldTag};
use crate::util::Expr;
use bus_mapping::evm::OpcodeId;
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};
use keccak256::EMPTY_HASH_LE;

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGCallGadget<F> {
    opcode: Cell<F>,
    tx_id: Cell<F>,
    is_static: Cell<F>,
    gas: Word<F>,
    callee_address: Word<F>,
    value: Word<F>,
    is_warm: Cell<F>,
    value_is_zero: IsZeroGadget<F>,
    cd_address: MemoryAddressGadget<F>,
    rd_address: MemoryAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 2, N_BYTES_MEMORY_WORD_SIZE>,
    balance: Word<F>,
    callee_nonce: Cell<F>,
    callee_code_hash: Cell<F>,
    is_empty_nonce_and_balance: BatchedIsZeroGadget<F, 2>,
    is_empty_code_hash: IsEqualGadget<F>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGCallGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasCall";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasCALL;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());
        // TODO: add CallCode etc. when handle ErrorOutOfGasCALLCODE in furture
        // implementation
        cb.require_equal(
            "ErrorOutOfGasCall opcode is Call",
            opcode.expr(),
            OpcodeId::CALL.expr(),
        );

        let gas_word = cb.query_word();
        let callee_address_word = cb.query_word();
        let value = cb.query_word();
        let cd_offset = cb.query_cell();
        let cd_length = cb.query_rlc();
        let rd_offset = cb.query_cell();
        let rd_length = cb.query_rlc();
        let balance = cb.query_word();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);

        // Lookup values from stack
        cb.stack_pop(gas_word.expr());
        cb.stack_pop(callee_address_word.expr());
        cb.stack_pop(value.expr());
        cb.stack_pop(cd_offset.expr());
        cb.stack_pop(cd_length.expr());
        cb.stack_pop(rd_offset.expr());
        cb.stack_pop(rd_length.expr());
        cb.stack_push(0.expr());

        // Recomposition of random linear combination to integer
        let callee_address =
            from_bytes::expr(&callee_address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);
        let cd_address = MemoryAddressGadget::construct(cb, cd_offset, cd_length);
        let rd_address = MemoryAddressGadget::construct(cb, rd_offset, rd_length);
        let memory_expansion =
            MemoryExpansionGadget::construct(cb, [cd_address.address(), rd_address.address()]);

        // Add callee to access list
        let is_warm = cb.query_bool();
        cb.account_access_list_read(tx_id.expr(), callee_address.clone(), is_warm.expr());

        let value_is_zero = IsZeroGadget::construct(cb, sum::expr(&value.cells));
        let has_value = 1.expr() - value_is_zero.expr();
        cb.account_read(
            callee_address.clone(),
            AccountFieldTag::Balance,
            balance.expr(),
        );

        // Verify gas cost
        let [callee_nonce, callee_code_hash] = [AccountFieldTag::Nonce, AccountFieldTag::CodeHash]
            .map(|field_tag| {
                let value = cb.query_cell();
                cb.account_read(callee_address.clone(), field_tag, value.expr());
                value
            });
        let is_empty_nonce_and_balance =
            BatchedIsZeroGadget::construct(cb, [callee_nonce.expr(), balance.expr()]);
        let is_empty_code_hash = IsEqualGadget::construct(
            cb,
            callee_code_hash.expr(),
            Word::random_linear_combine_expr(
                (*EMPTY_HASH_LE).map(|byte| byte.expr()),
                cb.power_of_randomness(),
            ),
        );
        let is_empty_account = is_empty_nonce_and_balance.expr() * is_empty_code_hash.expr();
        // Sum up gas cost
        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        ) + has_value
            * (GasCost::CALL_WITH_VALUE.expr() + is_empty_account * GasCost::NEW_ACCOUNT.expr())
            + memory_expansion.gas_cost();

        // Check if the amount of gas available is less than the amount of gas
        // required
        let insufficient_gas = LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);
        cb.require_equal(
            "gas left is less than gas required ",
            insufficient_gas.expr(),
            1.expr(),
        );

        // current call must be failed.
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 0.expr());

        // Go to EndTx only when is_root
        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(15.expr() + cb.curr.state.reversible_write_counter.expr()),

                ..StepStateTransition::any()
            });
        });

        // When it's an internal call, need to restore caller's state as finishing this
        // call. Restore caller state to next StepState
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        Self {
            opcode,
            tx_id,
            is_static,
            gas: gas_word,
            callee_address: callee_address_word,
            value,
            is_warm,
            value_is_zero,
            cd_address,
            rd_address,
            memory_expansion,
            balance,
            callee_nonce,
            callee_code_hash,
            is_empty_nonce_and_balance,
            is_empty_code_hash,
            insufficient_gas,
            restore_context,
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

        let [tx_id, is_static] =
            [step.rw_indices[0], step.rw_indices[1]].map(|idx| block.rws[idx].call_context_value());
        let stack_index = 2;
        let [gas, callee_address, value, cd_offset, cd_length, rd_offset, rd_length] = [
            step.rw_indices[stack_index],
            step.rw_indices[stack_index + 1],
            step.rw_indices[stack_index + 2],
            step.rw_indices[stack_index + 3],
            step.rw_indices[stack_index + 4],
            step.rw_indices[stack_index + 5],
            step.rw_indices[stack_index + 6],
        ]
        .map(|idx| block.rws[idx].stack_value());

        let (is_warm, is_warm_prev) = block.rws[step.rw_indices[10]].tx_access_list_value_pair();
        let [callee_balance_pair, (callee_nonce, _), (callee_code_hash, _)] = [
            step.rw_indices[11],
            step.rw_indices[12],
            step.rw_indices[13],
        ]
        .map(|idx| block.rws[idx].account_value_pair());

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx_id.low_u64())))?;

        self.is_static
            .assign(region, offset, Value::known(F::from(is_static.low_u64())))?;

        self.gas.assign(region, offset, Some(gas.to_le_bytes()))?;
        self.callee_address
            .assign(region, offset, Some(callee_address.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        self.value_is_zero
            .assign(region, offset, sum::value(&value.to_le_bytes()))?;

        let cd_address =
            self.cd_address
                .assign(region, offset, cd_offset, cd_length, block.randomness)?;
        let rd_address =
            self.rd_address
                .assign(region, offset, rd_offset, rd_length, block.randomness)?;
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [cd_address, rd_address],
        )?;

        // new assignment
        self.balance
            .assign(region, offset, Some(callee_balance_pair.0.to_le_bytes()))?;

        self.callee_nonce.assign(
            region,
            offset,
            Value::known(
                callee_nonce
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;
        self.callee_code_hash.assign(
            region,
            offset,
            Value::known(Word::random_linear_combine(
                callee_code_hash.to_le_bytes(),
                block.randomness,
            )),
        )?;
        let is_empty_nonce_and_balance = self.is_empty_nonce_and_balance.assign(
            region,
            offset,
            [
                F::from(callee_nonce.low_u64()),
                Word::random_linear_combine(callee_balance_pair.1.to_le_bytes(), block.randomness),
            ],
        )?;
        let is_empty_code_hash = self.is_empty_code_hash.assign(
            region,
            offset,
            Word::random_linear_combine(callee_code_hash.to_le_bytes(), block.randomness),
            Word::random_linear_combine(*EMPTY_HASH_LE, block.randomness),
        )?;
        let is_empty_account = is_empty_nonce_and_balance * is_empty_code_hash;
        let has_value = !value.is_zero();
        let gas_cost = if is_warm_prev {
            GasCost::WARM_ACCESS.as_u64()
        } else {
            GasCost::COLD_ACCOUNT_ACCESS.as_u64()
        } + if has_value {
            GasCost::CALL_WITH_VALUE.as_u64()
                + if is_empty_account == F::one() {
                    GasCost::NEW_ACCOUNT.as_u64()
                } else {
                    0
                }
        } else {
            0
        } + memory_expansion_gas_cost;

        self.insufficient_gas
            .assign(region, offset, F::from(step.gas_left), F::from(gas_cost))?;

        self.restore_context
            .assign(region, offset, block, call, step, 15)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{test::run_test_circuit, witness::block_convert};
    use eth_types::{address, bytecode};
    use eth_types::{bytecode::Bytecode, evm_types::OpcodeId, geth_types::Account};
    use eth_types::{Address, ToWord, Word};
    use halo2_proofs::halo2curves::bn256::Fr;
    use itertools::Itertools;
    use mock::TestContext;
    use std::default::Default;

    #[derive(Clone, Copy, Debug, Default)]
    struct Stack {
        gas: u64,
        value: Word,
        cd_offset: u64,
        cd_length: u64,
        rd_offset: u64,
        rd_length: u64,
    }

    fn caller(stack: Stack, caller_is_success: bool) -> Account {
        let terminator = if caller_is_success {
            OpcodeId::RETURN
        } else {
            OpcodeId::REVERT
        };

        // Call twice for testing both cold and warm access
        let bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
            PUSH32(stack.value)
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            CALL
            PUSH1(0)
            PUSH1(0)
            .write_op(terminator)
        };

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(20.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
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

    fn test_oog(caller: Account, callee: Account, is_root: bool) {
        let tx_gas = if is_root { 21100 } else { 25000 };
        let block = TestContext::<3, 1>::new(
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
                    .gas(tx_gas.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();
        let block_data = bus_mapping::mock::BlockData::new_from_geth_data(block);
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&block_data.eth_block, &block_data.geth_traces)
            .unwrap();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db);
        assert_eq!(run_test_circuit(block.unwrap()), Ok(()));
    }

    #[test]
    fn call_with_oog_root() {
        let stacks = vec![
            // With gas and memory expansion
            Stack {
                gas: 100,
                cd_offset: 64,
                cd_length: 320,
                rd_offset: 0,
                rd_length: 32,
                ..Default::default()
            },
        ];

        let bytecode = bytecode! {
            PUSH32(Word::from(0))
            PUSH32(Word::from(0))
            STOP
        };
        let callees = vec![callee(bytecode)];
        for (stack, callee) in stacks.into_iter().cartesian_product(callees.into_iter()) {
            test_oog(caller(stack, true), callee, true);
        }
    }

    #[test]
    fn call_with_oog_internal() {
        let stacks = vec![
            // first call stack
            Stack {
                gas: 100,
                cd_offset: 64,
                cd_length: 320,
                rd_offset: 0,
                rd_length: 32,
                ..Default::default()
            },
            // second call stack
            Stack {
                gas: 21,
                cd_offset: 64,
                cd_length: 320,
                rd_offset: 0,
                rd_length: 32,
                ..Default::default()
            },
        ];

        let stack = stacks[1];
        let bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
            PUSH32(stack.value)
            PUSH32(Address::repeat_byte(0xfe).to_word())
            PUSH32(Word::from(stack.gas))
            CALL // make this call out of gas
            PUSH32(Word::from(0))
            PUSH32(Word::from(0))
        };
        let callee = callee(bytecode);
        test_oog(caller(stacks[0], false), callee, false);
    }
}
