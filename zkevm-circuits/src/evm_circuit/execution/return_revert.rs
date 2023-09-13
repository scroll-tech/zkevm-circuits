use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE, STACK_CAPACITY},
        step::ExecutionState,
        util::{
            common_gadget::{get_copy_bytes, RestoreContextGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{IsEqualGadget, IsZeroGadget, MinMaxGadget},
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryExpansionGadget,
            },
            not, CachedRegion, Cell, StepRws,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDataType, state_db::CodeDB};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field, ToScalar, U256,
};
use ethers_core::utils::keccak256;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ReturnRevertGadget<F> {
    opcode: Cell<F>,
    // check if it is REVERT opcode
    is_revert: IsEqualGadget<F>,

    range: MemoryAddressGadget<F>,
    deployed_bytecode_rlc: Cell<F>,

    is_success: Cell<F>,
    restore_context: RestoreContextGadget<F>,

    copy_length: MinMaxGadget<F, N_BYTES_MEMORY_ADDRESS>,
    copy_rw_increase: Cell<F>,
    copy_rw_increase_is_zero: IsZeroGadget<F>,

    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,

    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    code_hash: Cell<F>,
    prev_code_hash: Cell<F>,
    keccak_code_hash: Cell<F>,
    prev_keccak_code_hash: Cell<F>,
    code_size: Cell<F>,

    caller_id: Cell<F>,
    address: Cell<F>,
    reversion_info: ReversionInfo<F>,
}

impl<F: Field> ExecutionGadget<F> for ReturnRevertGadget<F> {
    const NAME: &'static str = "RETURN_REVERT";

    const EXECUTION_STATE: ExecutionState = ExecutionState::RETURN_REVERT;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        cb.opcode_lookup(opcode.expr(), 1.expr());
        let is_revert = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::REVERT.expr());

        // constrain op codes
        cb.require_in_set(
            "RETURN_REVERT state is for RETURN or REVERT",
            opcode.expr(),
            vec![OpcodeId::RETURN.expr(), OpcodeId::REVERT.expr()],
        );

        let offset = cb.query_cell_phase2();
        let length = cb.query_word_rlc();
        cb.stack_pop(offset.expr());
        cb.stack_pop(length.expr());
        let range = MemoryAddressGadget::construct(cb, offset, length);

        let is_success = cb.call_context(None, CallContextFieldTag::IsSuccess);
        cb.require_boolean("is_success is boolean", is_success.expr());

        // There are 4 cases non-mutually exclusive, A to D, to handle, depending on if
        // the call is, or is not, a create, root, or successful. See the specs at
        // https://github.com/privacy-scaling-explorations/zkevm-specs/blob/master/specs/opcode/F3RETURN_FDREVERT.md
        // for more details.
        let is_create = cb.curr.state.is_create.expr();
        let is_root = cb.curr.state.is_root.expr();

        // These are globally defined because they are used across multiple cases.
        let copy_rw_increase = cb.query_cell();
        let copy_rw_increase_is_zero = IsZeroGadget::construct(cb, copy_rw_increase.expr());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [range.end_offset()]);

        // Case A in the specs.
        // not work for memory word rw counter increase now.
        // cb.condition(is_create.clone() * is_success.expr(), |_cb| {
        //     cb.require_equal(
        //         "increase rw counter once for each memory to bytecode byte copied",
        //         copy_rw_increase.expr(),
        //         range.length(),
        //     );
        // });

        let is_contract_deployment =
            is_create.clone() * is_success.expr() * not::expr(copy_rw_increase_is_zero.expr());
        let code_deposit_cost = cb.curr.state.is_create.expr()
            * is_success.expr()
            * GasCost::CODE_DEPOSIT_BYTE_COST.expr()
            * range.length();
        let (
            caller_id,
            address,
            reversion_info,
            code_hash,
            prev_code_hash,
            keccak_code_hash,
            prev_keccak_code_hash,
            code_size,
            deployed_bytecode_rlc,
        ) = cb.condition(is_contract_deployment.clone(), |cb| {
            // poseidon hash of code.
            //
            // We don't need to place any additional constraints on code_hash. The lookup to
            // copy table ensures the bytes are copied correctly. And the copy circuit ensures
            // those bytes are in fact assigned in the bytecode circuit layout. The bytecode
            // circuit does the lookup to poseidon table.
            let code_hash = cb.query_cell_phase2();
            let deployed_bytecode_rlc = cb.query_cell_phase2();
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                code_hash.expr(),
                CopyDataType::Bytecode.expr(),
                range.offset(),
                range.end_offset(),
                0.expr(),
                range.length(),
                deployed_bytecode_rlc.expr(),
                copy_rw_increase.expr(),
            );

            let [caller_id, address] = [
                CallContextFieldTag::CallerId,
                CallContextFieldTag::CalleeAddress,
            ]
            .map(|tag| cb.call_context(None, tag));
            let mut reversion_info = cb.reversion_info_read(None);

            // TODO: prev_code_hash must be empty_code_hash instead of 0?
            // since Nonce 0->1 is updated when begin_tx.
            // So we should optimize it later.
            let prev_code_hash = cb.query_cell_phase2();
            cb.account_read(
                address.expr(),
                AccountFieldTag::CodeHash,
                prev_code_hash.expr(),
            );
            cb.account_write(
                address.expr(),
                AccountFieldTag::CodeHash,
                code_hash.expr(),
                prev_code_hash.expr(),
                Some(&mut reversion_info),
            );

            // keccak hash of code.
            let keccak_code_hash = cb.query_cell_phase2();
            let prev_keccak_code_hash = cb.query_cell_phase2();
            #[cfg(feature = "scroll")]
            {
                cb.account_read(
                    address.expr(),
                    AccountFieldTag::KeccakCodeHash,
                    prev_keccak_code_hash.expr(),
                );

                cb.account_write(
                    address.expr(),
                    AccountFieldTag::KeccakCodeHash,
                    keccak_code_hash.expr(),
                    prev_keccak_code_hash.expr(),
                    Some(&mut reversion_info),
                );
            }

            // code size.
            let code_size = cb.query_cell_phase2();
            cb.require_equal("range == code size", range.length(), code_size.expr());
            #[cfg(feature = "scroll")]
            cb.account_write(
                address.expr(),
                AccountFieldTag::CodeSize,
                code_size.expr(),
                0.expr(),
                Some(&mut reversion_info),
            );

            (
                caller_id,
                address,
                reversion_info,
                code_hash,
                prev_code_hash,
                keccak_code_hash,
                prev_keccak_code_hash,
                code_size,
                deployed_bytecode_rlc,
            )
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
                gas_left: Delta(-memory_expansion.gas_cost() - code_deposit_cost.expr()),
                reversible_write_counter: To(0.expr()),
                memory_word_size: To(0.expr()),
                end_tx: To(1.expr()),
                ..StepStateTransition::default()
            });
        });

        // Case C in the specs.
        #[cfg(feature = "scroll")]
        let contract_deployment_reversible_write_num = 3; // dual code hash + code size
        #[cfg(not(feature = "scroll"))]
        let contract_deployment_reversible_write_num = 1;
        let restore_context = cb.condition(not::expr(is_root.expr()), |cb| {
            RestoreContextGadget::construct(
                cb,
                is_success.expr(),
                not::expr(is_create.clone()) * (2.expr() + copy_rw_increase.expr()),
                range.offset(),
                range.length(),
                memory_expansion.gas_cost(),
                contract_deployment_reversible_write_num.expr() * is_contract_deployment,
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
                // cb.require_equal(
                //     "increase rw counter twice for each memory to memory byte copied",
                //     copy_length.min() + copy_length.min(),
                //     copy_rw_increase.expr(),
                // );
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
                    range.end_offset(),
                    return_data_offset.expr(),
                    copy_length.min(),
                    0.expr(),
                    copy_rw_increase.expr(),
                );
            },
        );

        // handle revert case
        cb.condition(is_revert.expr(), |cb| {
            // "rw_counter_end_of_reversion = rw_counter_end_of_step + reversible_counter",
            // constrain RwCounterEndOfReversion
            let rw_counter_end_of_step =
                cb.curr.state.rw_counter.expr() + cb.rw_counter_offset() - 1.expr();
            cb.require_equal(
                "rw_counter_end_of_reversion = rw_counter_end_of_step + reversible_counter",
                reversion_info.rw_counter_end_of_reversion(),
                rw_counter_end_of_step + cb.curr.state.reversible_write_counter.expr(),
            );
            //  when REVERT happens, current call must be failed.
            cb.condition(is_revert.expr(), |cb| {
                cb.require_zero("is_success is false when is_revert", is_success.expr());
            });
        });
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
            is_revert,
            range,
            deployed_bytecode_rlc,
            is_success,
            copy_length,
            copy_rw_increase,
            copy_rw_increase_is_zero,
            return_data_offset,
            return_data_length,
            restore_context,
            memory_expansion,
            code_hash,
            prev_code_hash,
            keccak_code_hash,
            prev_keccak_code_hash,
            code_size,
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
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = F::from(step.opcode.unwrap().as_u64());
        self.opcode.assign(region, offset, Value::known(opcode))?;

        self.is_revert
            .assign(region, offset, opcode, F::from(OpcodeId::REVERT.as_u64()))?;

        let mut rws = StepRws::new(block, step);

        let [memory_offset, length] = [(); 2].map(|_| rws.next().stack_value());
        rws.next(); // skip

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

        let shift = memory_offset.low_u64() % 32;
        let valid_length = if call.is_root || (call.is_create && call.is_success) {
            length.as_u64()
        } else {
            call.return_data_length.min(length.as_u64())
        };

        let copy_rwc_inc = step.copy_rw_counter_delta;

        if call.is_create && call.is_success {
            // read memory word and get real copy bytes
            let deployed_bytecode: Vec<u8> =
                get_copy_bytes(&mut rws, copy_rwc_inc as usize, shift, valid_length);

            self.deployed_bytecode_rlc.assign(
                region,
                offset,
                region.keccak_rlc(&deployed_bytecode.iter().rev().cloned().collect::<Vec<u8>>()),
            )?;

            // keccak hash of code.
            let keccak_code_hash = keccak256(&deployed_bytecode);
            self.keccak_code_hash.assign(
                region,
                offset,
                region.word_rlc(U256::from_big_endian(&keccak_code_hash)),
            )?;

            // poseidon hash of code.
            let mut code_hash = CodeDB::hash(&deployed_bytecode).to_fixed_bytes();
            code_hash.reverse();
            self.code_hash.assign(
                region,
                offset,
                region.code_hash(U256::from_little_endian(&code_hash)),
            )?;

            // code size.
            self.code_size.assign(
                region,
                offset,
                Value::known(F::from(deployed_bytecode.len() as u64)),
            )?;

            if !deployed_bytecode.is_empty() {
                rws.offset_add(5);
                let prev_code_hash = rws.next().account_codehash_pair().1;
                self.prev_code_hash
                    .assign(region, offset, region.code_hash(prev_code_hash))?;
                #[cfg(feature = "scroll")]
                {
                    rws.next();
                    let prev_keccak_code_hash = rws.next().account_keccak_codehash_pair().1;
                    self.prev_keccak_code_hash.assign(
                        region,
                        offset,
                        region.word_rlc(prev_keccak_code_hash),
                    )?;
                }
            }
        }

        self.copy_rw_increase
            .assign(region, offset, Value::known(F::from(copy_rwc_inc)))?;
        self.copy_rw_increase_is_zero
            .assign(region, offset, F::from(copy_rwc_inc))?;

        let is_contract_deployment = call.is_create && call.is_success && !length.is_zero();
        if !call.is_root {
            let mut rw_counter_offset = 3; // stack read, stack read, call_context_read is_success
            if is_contract_deployment {
                rw_counter_offset += 6 + copy_rwc_inc; // 4 call_context_read + 2 codehash rw
                #[cfg(feature = "scroll")]
                {
                    rw_counter_offset += 3; // keccak code hash rw, code size
                }
            }
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
        address, bytecode,
        evm_types::OpcodeId,
        geth_types::{Account, GethData},
        Address, Bytecode, ToWord, Word, U256,
    };
    use itertools::Itertools;
    use mock::{eth, TestContext, MOCK_ACCOUNTS};

    const CALLEE_ADDRESS: Address = Address::repeat_byte(0xff);
    const CALLER_ADDRESS: Address = Address::repeat_byte(0x34);

    fn callee_bytecode(is_return: bool, offset: u128, length: u64) -> Bytecode {
        let memory_bytes = [0x60; 6];
        let memory_address = 0;
        let memory_value = Word::from_big_endian(&memory_bytes);
        let mut code: Bytecode = bytecode! {
            PUSH6(memory_value)
            PUSH1(memory_address)
            MSTORE
            PUSH2(length)
            PUSH17(Word::from(offset) + 32 - memory_bytes.len())
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
                RETURNDATASIZE
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

    #[test]
    // test CREATE/CREATE2 returndatasize both 0 for successful case
    fn test_return_nonroot_create_returndatasize() {
        for is_return in [false, true] {
            let initializer = callee_bytecode(is_return, 0, 10).code();

            let mut bytecode = bytecode! {
                 // CREATE + RETURNDATASIZE + RETURNDATACOPY logic
                PUSH32(Word::from_big_endian(&initializer))
                PUSH1(0)
                MSTORE

                PUSH1(initializer.len())        // size
                PUSH1(32 - initializer.len())   // offset
                PUSH1(0)                        // value
                CREATE
                RETURNDATASIZE
                PUSH1(0) // offset
                PUSH1(0) // dest offset
                RETURNDATACOPY // test return data copy
            };

            // CREATE2 logic
            let code_creator: Vec<u8> = initializer
                .to_vec()
                .iter()
                .cloned()
                .chain(0u8..((32 - initializer.len() % 32) as u8))
                .collect();
            for (index, word) in code_creator.chunks(32).enumerate() {
                bytecode.op_mstore(index * 32, Word::from_big_endian(word));
            }
            bytecode.append(&bytecode! {
                PUSH3(0x123456) // salt
                PUSH1(initializer.len()) // length
                PUSH1(0) // offset
                PUSH1(0) // value
                CREATE2
                RETURNDATASIZE
                PUSH1(0) // offset
                PUSH1(0) // dest offset
                RETURNDATACOPY
            });

            let block: GethData = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode.clone())
                .unwrap()
                .into();
            if is_return {
                // collect return opcode, retrieve next step, assure both contract create
                // successfully
                let created_contract_addr = block.geth_traces[0]
                    .struct_logs
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.op == OpcodeId::RETURN)
                    .flat_map(|(index, _)| block.geth_traces[0].struct_logs.get(index + 1))
                    .flat_map(|s| s.stack.nth_last(0)) // contract addr on stack top
                    .collect_vec();
                assert!(created_contract_addr.len() == 2); // both contract addr exist
                created_contract_addr
                    .iter()
                    .for_each(|addr| assert!(addr > &U256::zero()));

                // collect return opcode, retrieve next step, assure both returndata size is 0
                let return_data_size = block.geth_traces[0]
                    .struct_logs
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.op == OpcodeId::RETURNDATASIZE)
                    .flat_map(|(index, _)| block.geth_traces[0].struct_logs.get(index + 1))
                    .flat_map(|s| s.stack.nth_last(0)) // returndata size on stack top
                    .collect_vec();
                assert!(return_data_size.len() == 2);
                return_data_size
                    .iter()
                    .for_each(|size| assert_eq!(size, &Word::zero()));
            }
            let text_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap();
            CircuitTestBuilder::new_from_test_ctx(text_ctx).run();
        }
    }

    #[test]
    fn test_return_overflow_offset_and_zero_length() {
        for is_return in [true, false] {
            let code = callee_bytecode(is_return, u128::MAX, 0);
            CircuitTestBuilder::new_from_test_ctx(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
            )
            .run();
        }
    }
}
