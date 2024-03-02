use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        util::{
            common_gadget::{CommonCallGadget, CommonErrorGadget},
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{IsZeroGadget, LtGadget},
            memory_gadget::MemoryExpandedAddressGadget,
            or, CachedRegion, Cell, StepRws,
        },
    },
    table::CallContextFieldTag,
    util::Expr,
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
    is_warm: Cell<F>,
    call: CommonCallGadget<F, MemoryExpandedAddressGadget<F>, false>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGCallGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasCall";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasCall;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_call = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALL.expr());
        let is_callcode = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALLCODE.expr());
        let is_delegatecall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::DELEGATECALL.expr());
        let is_staticcall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::STATICCALL.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);

        let call_gadget: CommonCallGadget<F, MemoryExpandedAddressGadget<F>, false> =
            CommonCallGadget::construct(
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

        cb.condition(is_call.expr() * call_gadget.has_value.expr(), |cb| {
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
            "Either Memory address is overflow or gas left is less than cost",
            or::expr([
                call_gadget.cd_address.overflow(),
                call_gadget.rd_address.overflow(),
                insufficient_gas.expr(),
            ]),
            1.expr(),
        );

        // Both CALL and CALLCODE opcodes have an extra stack pop `value` relative to
        // DELEGATECALL and STATICCALL.
        let common_error_gadget = CommonErrorGadget::construct(
            cb,
            opcode.expr(),
            13.expr() + is_call.expr() + is_callcode.expr(),
        );

        Self {
            opcode,
            is_call,
            is_callcode,
            is_delegatecall,
            is_staticcall,
            tx_id,
            is_static,
            is_warm,
            call: call_gadget,
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
        let is_call = opcode == OpcodeId::CALL;
        let is_callcode = opcode == OpcodeId::CALLCODE;

        let mut rws = StepRws::new(block, step);

        let tx_id = rws.next().call_context_value();
        let is_static = rws.next().call_context_value();
        let gas = rws.next().stack_value();
        let callee_address = rws.next().stack_value();
        let value = if is_call || is_callcode {
            rws.next().stack_value()
        } else {
            U256::zero()
        };
        let cd_offset = rws.next().stack_value();
        let cd_length = rws.next().stack_value();
        let rd_offset = rws.next().stack_value();
        let rd_length = rws.next().stack_value();

        rws.offset_add(1);
        let callee_code_hash = rws.next().account_value_pair().0;
        let callee_exists = !callee_code_hash.is_zero();
        let (is_warm, is_warm_prev) = rws.next().tx_access_list_value_pair();

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
            region.code_hash(callee_code_hash),
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
            is_call,
            has_value,
            !callee_exists,
        )?;

        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(gas_cost)),
        )?;

        // Both CALL and CALLCODE opcodes have an extra stack pop `value` relative to
        // DELEGATECALL and STATICCALL.
        self.common_error_gadget.assign(
            region,
            offset,
            block,
            call,
            step,
            13 + if is_call || is_callcode { 1 } else { 0 },
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{
        address, bytecode, bytecode::Bytecode, evm_types::OpcodeId, geth_types::Account, Address,
        ToWord, Word,
    };
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
        gas: Word,
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
            PUSH32(stack.gas)
            .write_op(opcode)
            PUSH1(0)
            PUSH1(0)
            REVERT
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
    fn test_oog_call_root() {
        let stack = Stack {
            gas: 100.into(),
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
    fn test_oog_call_internal() {
        let caller_stack = Stack {
            gas: 100.into(),
            cd_offset: 64,
            cd_length: 320,
            rd_offset: 0,
            rd_length: 32,
            ..Default::default()
        };
        let callee_stack = Stack {
            gas: 21.into(),
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

    #[test]
    fn test_oog_call_with_overflow_gas() {
        let stack = Stack {
            gas: Word::MAX,
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
        test_oog(&caller(OpcodeId::CALL, stack), &callee, true);
    }

    #[test]
    fn test_oog_call_max_expanded_address() {
        // 0xffffffff1 + 0xffffffff0 = 0x1fffffffe1
        // > MAX_EXPANDED_MEMORY_ADDRESS (0x1fffffffe0)
        let stack = Stack {
            gas: Word::MAX,
            cd_offset: 0xffffffff1,
            cd_length: 0xffffffff0,
            rd_offset: 0xffffffff1,
            rd_length: 0xffffffff0,
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
    fn test_oog_call_max_u64_address() {
        let stack = Stack {
            gas: Word::MAX,
            cd_offset: u64::MAX,
            cd_length: u64::MAX,
            rd_offset: u64::MAX,
            rd_length: u64::MAX,
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
}
