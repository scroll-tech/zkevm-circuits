use crate::table::CallContextFieldTag;
use crate::util::Expr;
use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::{CommonCallGadget, RestoreContextGadget},
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, Same},
            },
            math_gadget::{IsZeroGadget, LtGadget},
            CachedRegion, Cell,
        },
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, U256};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::CALL`], [`OpcodeId::CALLCODE`], [`OpcodeId::DELEGATECALL`] and
/// [`OpcodeId::STATICCALL`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGCallGadget<F> {
    opcode: Cell<F>,
    is_call: IsZeroGadget<F>,
    is_callcode: IsZeroGadget<F>,
    is_delegatecall: IsZeroGadget<F>,
    is_staticcall: IsZeroGadget<F>,
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

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasCall;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());
        let is_call = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALL.expr());
        let is_callcode = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALLCODE.expr());
        let is_delegatecall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::DELEGATECALL.expr());
        let is_staticcall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::STATICCALL.expr());

        let rw_counter_end_of_reversion = cb.query_cell();
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);

        let call_gadget = CommonCallGadget::construct(
            cb,
            is_call.expr(),
            is_callcode.expr(),
            is_delegatecall.expr(),
            is_staticcall.expr(),
        );

        // Add callee to access list
        let is_warm = cb.query_bool();
        cb.account_access_list_read(
            tx_id.expr(),
            call_gadget.callee_address_expr(),
            is_warm.expr(),
        );

        cb.condition(call_gadget.has_value.expr(), |cb| {
            cb.require_zero(
                "CALL with value must not be in static call stack",
                is_static.expr(),
            );
        });

        // Verify gas cost
        let gas_cost = call_gadget.gas_cost_expr(is_warm.expr(), is_call.expr());

        // Check if the amount of gas available is less than the amount of gas required
        let insufficient_gas = LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);
        cb.require_equal(
            "gas left is less than gas required",
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
                // Both CALL and CALLCODE opcodes have an extra stack pop `value` relative to
                // DELEGATECALL and STATICCALL.
                rw_counter: Delta(
                    13.expr()
                        + is_call.expr()
                        + is_callcode.expr()
                        + cb.curr.state.reversible_write_counter.expr(),
                ),
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
            is_call,
            is_callcode,
            is_delegatecall,
            is_staticcall,
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
        let is_call_or_callcode =
            usize::from([OpcodeId::CALL, OpcodeId::CALLCODE].contains(&opcode));
        let [tx_id, is_static] =
            [step.rw_indices[0], step.rw_indices[1]].map(|idx| block.rws[idx].call_context_value());
        let stack_index = 2;
        let [gas, callee_address] = [
            step.rw_indices[stack_index],
            step.rw_indices[stack_index + 1],
        ]
        .map(|idx| block.rws[idx].stack_value());
        let value = if is_call_or_callcode == 1 {
            block.rws[step.rw_indices[stack_index + 2]].stack_value()
        } else {
            U256::zero()
        };
        let [cd_offset, cd_length, rd_offset, rd_length] = [
            step.rw_indices[stack_index + is_call_or_callcode + 2],
            step.rw_indices[stack_index + is_call_or_callcode + 3],
            step.rw_indices[stack_index + is_call_or_callcode + 4],
            step.rw_indices[stack_index + is_call_or_callcode + 5],
        ]
        .map(|idx| block.rws[idx].stack_value());

        let callee_code_hash = block.rws[step.rw_indices[9 + is_call_or_callcode]]
            .account_value_pair()
            .0;
        let callee_exists = !callee_code_hash.is_zero();

        let (is_warm, is_warm_prev) =
            block.rws[step.rw_indices[10 + is_call_or_callcode]].tx_access_list_value_pair();

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

        self.is_call.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::CALL.as_u64()),
        )?;
        self.is_callcode.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::CALLCODE.as_u64()),
        )?;
        self.is_delegatecall.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::DELEGATECALL.as_u64()),
        )?;
        self.is_staticcall.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::STATICCALL.as_u64()),
        )?;

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

        // Both CALL and CALLCODE opcodes have an extra stack pop `value` relative to
        // DELEGATECALL and STATICCALL.
        self.restore_context
            .assign(region, offset, block, call, step, 13 + is_call_or_callcode)
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode::Bytecode;
    use eth_types::evm_types::OpcodeId;
    use eth_types::geth_types::Account;
    use eth_types::{address, bytecode};
    use eth_types::{Address, ToWord, Word};
    use mock::TestContext;
    use std::default::Default;

    const TEST_CALL_OPCODES: &[OpcodeId] = &[
        OpcodeId::CALL,
        OpcodeId::CALLCODE,
        OpcodeId::DELEGATECALL,
        OpcodeId::STATICCALL,
    ];

    #[derive(Clone, Copy, Debug, Default)]
    struct Stack {
        gas: u64,
        value: Word,
        cd_offset: u64,
        cd_length: u64,
        rd_offset: u64,
        rd_length: u64,
    }

    fn call_bytecode(opcode: OpcodeId, address: Address, stack: Stack) -> Bytecode {
        let mut bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
        };
        if opcode == OpcodeId::CALL || opcode == OpcodeId::CALLCODE {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(address.to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(opcode)
            PUSH1(0)
            PUSH1(0)
            .write_op(OpcodeId::REVERT)
        });

        bytecode
    }

    fn caller(opcode: OpcodeId, stack: Stack) -> Account {
        let bytecode = call_bytecode(opcode, Address::repeat_byte(0xff), stack);

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

    fn test_oog(caller: &Account, callee: &Account, is_root: bool) {
        let tx_gas = if is_root { 21100 } else { 25000 };
        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(10u64.pow(19)));
                accs[1]
                    .address(caller.address)
                    .code(caller.code.clone())
                    .nonce(caller.nonce)
                    .balance(caller.balance);
                accs[2]
                    .address(callee.address)
                    .code(callee.code.clone())
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
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn call_with_oog_root() {
        let stack = Stack {
            gas: 100,
            cd_offset: 64,
            cd_length: 320,
            rd_offset: 0,
            rd_length: 32,
            ..Default::default()
        };
        let callee = callee(bytecode! {
            PUSH32(Word::from(0))
            PUSH32(Word::from(0))
            STOP
        });
        for opcode in TEST_CALL_OPCODES {
            test_oog(&caller(*opcode, stack), &callee, true);
        }
    }

    #[test]
    fn call_with_oog_internal() {
        let caller_stack = Stack {
            gas: 100,
            cd_offset: 64,
            cd_length: 320,
            rd_offset: 0,
            rd_length: 32,
            ..Default::default()
        };
        let callee_stack = Stack {
            gas: 21,
            cd_offset: 64,
            cd_length: 320,
            rd_offset: 0,
            rd_length: 32,
            ..Default::default()
        };

        let caller = caller(OpcodeId::CALL, caller_stack);
        for callee_opcode in TEST_CALL_OPCODES {
            let callee = callee(call_bytecode(
                *callee_opcode,
                Address::repeat_byte(0xfe),
                callee_stack,
            ));
            test_oog(&caller, &callee, false);
        }
    }
}
