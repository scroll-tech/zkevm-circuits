use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE, STACK_CAPACITY},
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{IsZeroGadget, MinMaxGadget},
            memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget},
            not, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::{Field, ToScalar, U256};
use ethers_core::utils::keccak256;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ReturnRevertGadget<F> {
    opcode: Cell<F>,

    range: MemoryAddressGadget<F>,

    is_success: Cell<F>,
    restore_context: RestoreContextGadget<F>,

    copy_length: MinMaxGadget<F, N_BYTES_MEMORY_ADDRESS>,
    copy_rw_increase: Cell<F>,
    copy_rw_increase_is_zero: IsZeroGadget<F>,

    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,

    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    code_hash: Cell<F>,

    caller_id: Cell<F>,
    address: Cell<F>,
    reversion_info: ReversionInfo<F>,
}

impl<F: Field> ExecutionGadget<F> for ReturnRevertGadget<F> {
    const NAME: &'static str = "RETURN_REVERT";

    const EXECUTION_STATE: ExecutionState = ExecutionState::RETURN_REVERT;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        let offset = cb.query_cell_phase2();
        let length = cb.query_word_rlc();
        cb.stack_pop(offset.expr());
        cb.stack_pop(length.expr());
        let range = MemoryAddressGadget::construct(cb, offset, length);

        let is_success = cb.call_context(None, CallContextFieldTag::IsSuccess);
        cb.require_boolean("is_success is boolean", is_success.expr());
        /*
        cb.require_equal(
            "if is_success, opcode is RETURN. if not, opcode is REVERT",
            opcode.expr(),
            is_success.expr() * OpcodeId::RETURN.expr()
                + not::expr(is_success.expr()) * OpcodeId::REVERT.expr(),
        );
        */

        // There are 4 cases non-mutually exclusive, A to D, to handle, depending on if
        // the call is, or is not, a create, root, or successful. See the specs at
        // https://github.com/privacy-scaling-explorations/zkevm-specs/blob/master/specs/opcode/F3RETURN_FDREVERT.md
        // for more details.
        let is_create = cb.curr.state.is_create.expr();
        let is_root = cb.curr.state.is_root.expr();

        // These are globally defined because they are used across multiple cases.
        let copy_rw_increase = cb.query_cell();
        let copy_rw_increase_is_zero = IsZeroGadget::construct(cb, copy_rw_increase.expr());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [range.address()]);

        // Case A in the specs.
        cb.condition(is_create.clone() * is_success.expr(), |cb| {
            cb.require_equal(
                "increase rw counter once for each memory to bytecode byte copied",
                copy_rw_increase.expr(),
                range.length(),
            );
        });

        let is_contract_deployment =
            is_create.clone() * is_success.expr() * not::expr(copy_rw_increase_is_zero.expr());
        let (caller_id, address, reversion_info, code_hash) =
            cb.condition(is_contract_deployment.clone(), |cb| {
                // We don't need to place any additional constraints on code_hash because the
                // copy circuit enforces that it is the hash of the bytes in the copy lookup.
                let code_hash = cb.query_cell_phase2();
                cb.copy_table_lookup(
                    cb.curr.state.call_id.expr(),
                    CopyDataType::Memory.expr(),
                    code_hash.expr(),
                    CopyDataType::Bytecode.expr(),
                    range.offset(),
                    range.address(),
                    0.expr(),
                    range.length(),
                    0.expr(),
                    copy_rw_increase.expr(),
                );

                let [caller_id, address] = [
                    CallContextFieldTag::CallerId,
                    CallContextFieldTag::CalleeAddress,
                ]
                .map(|tag| cb.call_context(None, tag));
                let mut reversion_info = cb.reversion_info_read(None);

                cb.account_write(
                    address.expr(),
                    AccountFieldTag::CodeHash,
                    code_hash.expr(),
                    cb.empty_hash_rlc(),
                    Some(&mut reversion_info),
                );

                (caller_id, address, reversion_info, code_hash)
            });

        // Case B in the specs.
        cb.condition(is_root.expr(), |cb| {
            cb.require_next_state(ExecutionState::EndTx);
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::IsPersistent,
                is_success.expr(),
            );
            cb.require_step_state_transition(StepStateTransition {
                program_counter: To(0.expr()),
                stack_pointer: To(STACK_CAPACITY.expr()),
                rw_counter: Delta(
                    cb.rw_counter_offset()
                        + not::expr(is_success.expr())
                            * cb.curr.state.reversible_write_counter.expr(),
                ),
                gas_left: Delta(-memory_expansion.gas_cost()),
                reversible_write_counter: To(0.expr()),
                memory_word_size: To(0.expr()),
                ..StepStateTransition::default()
            });
        });

        // Case C in the specs.
        let restore_context = cb.condition(not::expr(is_root.expr()), |cb| {
            RestoreContextGadget::construct(
                cb,
                is_create.expr(),
                is_success.expr(),
                not::expr(is_create.clone()) * (5.expr() + copy_rw_increase.expr()),
                range.offset(),
                range.length(),
                memory_expansion.gas_cost(),
                is_contract_deployment, // There is one reversible write in this case.
            )
        });

        // Case D in the specs.
        let (return_data_offset, return_data_length, copy_length) = cb.condition(
            not::expr(is_create.clone()) * not::expr(is_root.clone()),
            |cb| {
                let [return_data_offset, return_data_length] = [
                    CallContextFieldTag::ReturnDataOffset,
                    CallContextFieldTag::ReturnDataLength,
                ]
                .map(|field_tag| cb.call_context(None, field_tag));
                let copy_length =
                    MinMaxGadget::construct(cb, return_data_length.expr(), range.length());
                cb.require_equal(
                    "increase rw counter twice for each memory to memory byte copied",
                    copy_length.min() + copy_length.min(),
                    copy_rw_increase.expr(),
                );
                (return_data_offset, return_data_length, copy_length)
            },
        );
        cb.condition(
            not::expr(is_create.clone())
                * not::expr(is_root.clone())
                * not::expr(copy_rw_increase_is_zero.expr()),
            |cb| {
                cb.copy_table_lookup(
                    cb.curr.state.call_id.expr(),
                    CopyDataType::Memory.expr(),
                    cb.next.state.call_id.expr(),
                    CopyDataType::Memory.expr(),
                    range.offset(),
                    range.address(),
                    return_data_offset.expr(),
                    copy_length.min(),
                    0.expr(),
                    copy_rw_increase.expr(),
                );
            },
        );

        // Without this, copy_rw_increase would be unconstrained for non-create root
        // calls.
        cb.condition(not::expr(is_create) * is_root, |cb| {
            cb.require_zero(
                "rw counter is 0 if there is no copy event",
                copy_rw_increase.expr(),
            );
        });

        Self {
            opcode,
            range,
            is_success,
            copy_length,
            copy_rw_increase,
            copy_rw_increase_is_zero,
            return_data_offset,
            return_data_length,
            restore_context,
            memory_expansion,
            code_hash,
            address,
            caller_id,
            reversion_info,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.opcode.assign(
            region,
            offset,
            Value::known(F::from(step.opcode.unwrap().as_u64())),
        )?;

        let [memory_offset, length] = [0, 1].map(|i| block.rws[step.rw_indices[i]].stack_value());
        let range = self.range.assign(region, offset, memory_offset, length)?;
        self.memory_expansion
            .assign(region, offset, step.memory_word_size(), [range])?;

        self.is_success
            .assign(region, offset, Value::known(call.is_success.into()))?;

        if !call.is_root && !call.is_create {
            for (cell, value) in [
                (&self.return_data_length, call.return_data_length.into()),
                (&self.return_data_offset, call.return_data_offset.into()),
            ] {
                cell.assign(region, offset, Value::known(value))?;
            }

            self.copy_length.assign(
                region,
                offset,
                F::from(call.return_data_length),
                F::from(length.as_u64()),
            )?;
        }

        if call.is_create && call.is_success {
            let values: Vec<_> = (3..3 + length.as_usize())
                .map(|i| block.rws[step.rw_indices[i]].memory_value())
                .collect();
            let mut code_hash = keccak256(values);
            code_hash.reverse();
            self.code_hash.assign(
                region,
                offset,
                region.word_rlc(U256::from_little_endian(&code_hash)),
            )?;
        }

        let copy_rw_increase = if call.is_create && call.is_success {
            length.as_u64()
        } else if !call.is_root {
            2 * std::cmp::min(call.return_data_length, length.as_u64())
        } else {
            0
        };
        self.copy_rw_increase
            .assign(region, offset, Value::known(F::from(copy_rw_increase)))?;
        self.copy_rw_increase_is_zero
            .assign(region, offset, F::from(copy_rw_increase))?;

        let is_contract_deployment = call.is_create && call.is_success && !length.is_zero();
        if !call.is_root {
            let rw_counter_offset = 3 + if is_contract_deployment {
                5 + length.as_u64()
            } else {
                0
            };
            self.restore_context.assign(
                region,
                offset,
                block,
                call,
                step,
                rw_counter_offset.try_into().unwrap(),
            )?;
        }

        self.caller_id.assign(
            region,
            offset,
            Value::known(call.caller_id.to_scalar().unwrap()),
        )?;

        self.address.assign(
            region,
            offset,
            Value::known(call.callee_address.to_scalar().unwrap()),
        )?;

        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{
        address, bytecode, evm_types::OpcodeId, geth_types::Account, Address, Bytecode, ToWord,
        Word,
    };
    use itertools::Itertools;
    use mock::{eth, TestContext, MOCK_ACCOUNTS};

    const CALLEE_ADDRESS: Address = Address::repeat_byte(0xff);
    const CALLER_ADDRESS: Address = Address::repeat_byte(0x34);

    fn callee_bytecode(is_return: bool, offset: u64, length: u64) -> Bytecode {
        let memory_bytes = [0x60; 10];
        let memory_address = 0;
        let memory_value = Word::from_big_endian(&memory_bytes);
        let mut code = bytecode! {
            PUSH10(memory_value)
            PUSH1(memory_address)
            MSTORE
            PUSH2(length)
            PUSH2(32u64 - u64::try_from(memory_bytes.len()).unwrap() + offset)
        };
        code.write_op(if is_return {
            OpcodeId::RETURN
        } else {
            OpcodeId::REVERT
        });
        code
    }

    fn caller_bytecode(return_data_offset: u64, return_data_length: u64) -> Bytecode {
        bytecode! {
            PUSH32(return_data_length)
            PUSH32(return_data_offset)
            PUSH32(0) // call data length
            PUSH32(0) // call data offset
            PUSH32(0) // value
            PUSH32(CALLEE_ADDRESS.to_word())
            PUSH32(4000) // gas
            CALL
            STOP
        }
    }

    #[test]
    fn test_return_root_noncreate() {
        let test_parameters = [(0, 0), (0, 10), (300, 20), (1000, 0)];
        for ((offset, length), is_return) in
            test_parameters.iter().cartesian_product(&[true, false])
        {
            let code = callee_bytecode(*is_return, *offset, *length);
            CircuitTestBuilder::new_from_test_ctx(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
            )
            .run();
        }
    }

    #[test]
    fn test_return_nonroot_noncreate() {
        let test_parameters = [
            ((0, 0), (0, 0)),
            ((0, 10), (0, 10)),
            ((0, 10), (0, 20)),
            ((0, 20), (0, 10)),
            ((64, 1), (0, 10)), // Expands memory in RETURN/REVERT opcode
            ((0, 10), (1000, 0)),
            ((1000, 0), (0, 10)),
            ((1000, 0), (1000, 0)),
        ];
        for (((callee_offset, callee_length), (caller_offset, caller_length)), is_return) in
            test_parameters.iter().cartesian_product(&[true, false])
        {
            let callee = Account {
                address: CALLEE_ADDRESS,
                code: callee_bytecode(*is_return, *callee_offset, *callee_length).into(),
                nonce: Word::one(),
                ..Default::default()
            };
            let caller = Account {
                address: CALLER_ADDRESS,
                code: caller_bytecode(*caller_offset, *caller_length).into(),
                nonce: Word::one(),
                ..Default::default()
            };

            let ctx = TestContext::<3, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(address!("0x000000000000000000000000000000000000cafe"))
                        .balance(Word::from(10u64.pow(19)));
                    accs[1].account(&caller);
                    accs[2].account(&callee);
                },
                |mut txs, accs| {
                    txs[0]
                        .from(accs[0].address)
                        .to(accs[1].address)
                        .gas(100000u64.into());
                },
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        }
    }

    #[test]
    fn test_return_root_create() {
        let test_parameters = [(0, 0), (0, 10), (300, 20), (1000, 0)];
        for ((offset, length), is_return) in
            test_parameters.iter().cartesian_product(&[true, false])
        {
            let tx_input = callee_bytecode(*is_return, *offset, *length).code();
            let ctx = TestContext::<1, 1>::new(
                None,
                |accs| {
                    accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(10));
                },
                |mut txs, accs| {
                    txs[0].from(accs[0].address).input(tx_input.into());
                },
                |block, _| block,
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        }
    }

    #[test]
    fn test_return_nonroot_create() {
        let test_parameters = [(0, 0), (0, 10), (300, 20), (1000, 0)];
        for ((offset, length), is_return) in
            test_parameters.iter().cartesian_product(&[true, false])
        {
            let initializer = callee_bytecode(*is_return, *offset, *length).code();

            let root_code = bytecode! {
                PUSH32(Word::from_big_endian(&initializer))
                PUSH1(0)
                MSTORE

                PUSH1(initializer.len())        // size
                PUSH1(32 - initializer.len())   // offset
                PUSH1(0)                        // value

                CREATE
            };

            let caller = Account {
                address: CALLER_ADDRESS,
                code: root_code.into(),
                nonce: Word::one(),
                balance: eth(10),
                ..Default::default()
            };

            let ctx = TestContext::<2, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(address!("0x000000000000000000000000000000000000cafe"))
                        .balance(eth(10));
                    accs[1].account(&caller);
                },
                |mut txs, accs| {
                    txs[0]
                        .from(accs[0].address)
                        .to(accs[1].address)
                        .gas(100000u64.into());
                },
                |block, _| block,
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        }
    }

    #[test]
    fn test_nonpersistent_nonroot_create() {
        // Test the case where the initialization call is successful, but the CREATE
        // call is reverted.
        let initializer = callee_bytecode(true, 0, 10).code();

        let root_code = bytecode! {
            PUSH32(Word::from_big_endian(&initializer))
            PUSH1(0)
            MSTORE

            PUSH1(initializer.len())        // size
            PUSH1(32 - initializer.len())   // offset
            PUSH1(0)                        // value

            CREATE
            PUSH1(0)
            PUSH1(0)
            REVERT
        };

        let caller = Account {
            address: CALLER_ADDRESS,
            code: root_code.into(),
            nonce: Word::one(),
            balance: eth(10),
            ..Default::default()
        };

        let ctx = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(eth(10));
                accs[1].account(&caller);
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(accs[1].address)
                    .gas(100000u64.into());
            },
            |block, _| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
