use crate::evm_circuit::{
    execution::ExecutionGadget,
    param::N_BYTES_GAS,
    step::ExecutionState,
    util::{
        common_gadget::{CommonCallGadget, RestoreContextGadget},
        constraint_builder::{
            ConstraintBuilder, StepStateTransition,
            Transition::{Delta, Same},
        },
        math_gadget::LtGadget,
        CachedRegion, Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use crate::table::CallContextFieldTag;
use crate::util::Expr;
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, U256};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGCallGadget<F> {
    opcode: Cell<F>,
    tx_id: Cell<F>,
    is_static: Cell<F>,
    call: CommonCallGadget<F, false>,
    is_warm: Cell<F>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    rw_counter_end_of_reversion: Cell<F>,
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

        let rw_counter_end_of_reversion = cb.query_cell();
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);
        let call_gadget = CommonCallGadget::construct(cb, 1.expr(), 0.expr(), 0.expr());

        // Add callee to access list
        let is_warm = cb.query_bool();
        cb.account_access_list_read(
            tx_id.expr(),
            call_gadget.callee_address_expr(),
            is_warm.expr(),
        );

        // Verify gas cost
        let gas_cost = call_gadget.gas_cost_expr(is_warm.expr(), 1.expr());

        // Check if the amount of gas available is less than the amount of gas required
        let insufficient_gas = LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);
        cb.require_equal(
            "gas left is less than gas required ",
            insufficient_gas.expr(),
            1.expr(),
        );

        // current call must be failed.
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 0.expr());

        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::RwCounterEndOfReversion,
            rw_counter_end_of_reversion.expr(),
        );

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
                rw_counter: Delta(14.expr() + cb.curr.state.reversible_write_counter.expr()),
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

        // constrain RwCounterEndOfReversion
        let rw_counter_end_of_step =
            cb.curr.state.rw_counter.expr() + cb.rw_counter_offset() - 1.expr();
        cb.require_equal(
            "rw_counter_end_of_reversion = rw_counter_end_of_step + reversible_counter",
            rw_counter_end_of_reversion.expr(),
            rw_counter_end_of_step + cb.curr.state.reversible_write_counter.expr(),
        );

        Self {
            opcode,
            tx_id,
            is_static,
            call: call_gadget,
            is_warm,
            insufficient_gas,
            rw_counter_end_of_reversion,
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

        let callee_code_hash = block.rws[step.rw_indices[10]].account_value_pair().0;
        let callee_exists = !callee_code_hash.is_zero();

        let (is_warm, is_warm_prev) = block.rws[step.rw_indices[11]].tx_access_list_value_pair();

        let memory_expansion_gas_cost = self.call.assign(
            region,
            offset,
            gas,
            callee_address,
            value,
            U256::from(0),
            cd_offset,
            cd_length,
            rd_offset,
            rd_length,
            step.memory_word_size(),
            region.word_rlc(callee_code_hash),
        )?;

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx_id.low_u64())))?;

        self.is_static
            .assign(region, offset, Value::known(F::from(is_static.low_u64())))?;

        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        let has_value = !value.is_zero();
        let gas_cost = self.call.cal_gas_cost_for_assignment(
            memory_expansion_gas_cost,
            is_warm_prev,
            true,
            has_value,
            !callee_exists,
        )?;

        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(gas_cost)),
        )?;

        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Value::known(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;

        self.restore_context
            .assign(region, offset, block, call, step, 14)?;
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
    use pretty_assertions::assert_eq;
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
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        assert_eq!(run_test_circuit(block), Ok(()));
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
