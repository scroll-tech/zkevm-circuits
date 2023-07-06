use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{
            N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE,
            N_BYTES_U64, N_BYTES_WORD,
        },
        step::ExecutionState,
        util::{
            common_gadget::TransferGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{
                ConstantDivisionGadget, ContractCreateGadget, IsZeroGadget, LtGadget, LtWordGadget,
            },
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryExpansionGadget,
            },
            not, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId, state_db::CodeDB};
use eth_types::{
    evm_types::{GasCost, CREATE2_GAS_PER_CODE_WORD, CREATE_GAS_PER_CODE_WORD, MAX_INIT_CODE_SIZE},
    Field, ToBigEndian, ToLittleEndian, ToScalar, U256,
};
use ethers_core::utils::keccak256;
use gadgets::util::{and, expr_from_bytes};
use halo2_proofs::{circuit::Value, plonk::Error};

use std::iter::once;

/// Gadget for CREATE and CREATE2 opcodes
#[derive(Clone, Debug)]
pub(crate) struct CreateGadget<F, const IS_CREATE2: bool, const S: ExecutionState> {
    opcode: Cell<F>,
    value: Word<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    was_warm: Cell<F>,
    depth: Cell<F>,
    callee_reversion_info: ReversionInfo<F>,
    callee_is_success: Cell<F>,
    transfer: TransferGadget<F>,
    init_code: MemoryAddressGadget<F>,
    init_code_word_size: ConstantDivisionGadget<F, N_BYTES_MEMORY_ADDRESS>,
    // Init code size must be less than or equal to 49152
    // (maximum init code size) if Shanghai, otherwise should be less than or
    // equal to 0x1FFFFFFFE0 (maximum value of offset + size).
    init_code_size_not_overflow: LtGadget<F, { N_BYTES_MEMORY_ADDRESS }>,
    init_code_rlc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    gas_left: ConstantDivisionGadget<F, N_BYTES_GAS>,
    create: ContractCreateGadget<F, IS_CREATE2>,
    caller_balance: Word<F>,
    is_depth_in_range: LtGadget<F, N_BYTES_U64>,
    is_insufficient_balance: LtWordGadget<F>,
    is_nonce_in_range: LtGadget<F, N_BYTES_U64>,
    keccak_code_hash: Cell<F>,
    keccak_output: Word<F>,
    // prevous code hash befor creating
    code_hash_previous: Cell<F>,
    // if code_hash_previous is zero, then no collision
    not_address_collision: IsZeroGadget<F>,
}

impl<F: Field, const IS_CREATE2: bool, const S: ExecutionState> ExecutionGadget<F>
    for CreateGadget<F, IS_CREATE2, S>
{
    const NAME: &'static str = "CREATE";

    const EXECUTION_STATE: ExecutionState = S;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let callee_call_id = cb.curr.state.rw_counter.clone();
        let code_hash_previous = cb.query_cell();
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        cb.require_equal(
            "Opcode is CREATE or CREATE2",
            opcode.expr(),
            if IS_CREATE2 {
                OpcodeId::CREATE2
            } else {
                OpcodeId::CREATE
            }
            .expr(),
        );

        // constrain not in static call
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static is false", is_static.expr());

        let value = cb.query_word_rlc();

        let init_code_memory_offset = cb.query_cell_phase2();
        let init_code_length = cb.query_word_rlc();
        let init_code =
            MemoryAddressGadget::construct(cb, init_code_memory_offset, init_code_length);
        let init_code_size_not_overflow =
            LtGadget::construct(cb, init_code.length(), MAX_INIT_CODE_SIZE.expr() + 1.expr());

        // Init code size overflow is checked before ErrDepth, ErrInsufficientBalance,
        // ErrNonceUintOverflow and ErrContractAddressCollision.
        cb.require_equal(
            "Init code size must be not overflow",
            init_code_size_not_overflow.expr(),
            1.expr(),
        );

        let keccak_output = cb.query_word_rlc();
        let new_address_rlc = cb.word_rlc::<N_BYTES_ACCOUNT_ADDRESS>(
            keccak_output
                .cells
                .iter()
                .take(N_BYTES_ACCOUNT_ADDRESS)
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        let new_address = expr_from_bytes(&keccak_output.cells[..N_BYTES_ACCOUNT_ADDRESS]);
        let callee_is_success = cb.query_bool();

        let create = ContractCreateGadget::construct(cb);

        cb.stack_pop(value.expr());
        cb.stack_pop(init_code.offset_rlc());
        cb.stack_pop(init_code.length_rlc());
        if IS_CREATE2 {
            cb.stack_pop(create.salt_word_rlc(cb));
        }

        cb.stack_push(callee_is_success.expr() * new_address_rlc);

        let (init_code_rlc, keccak_code_hash) = cb.condition(init_code.has_length(), |cb| {
            // the init code is being copied from memory to bytecode, so a copy table lookup to
            // verify that the associated fields for the copy event.
            let keccak_code_hash = cb.query_cell_phase2();
            let init_code_rlc = cb.query_cell_phase2();
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                create.code_hash_word_rlc(),
                CopyDataType::Bytecode.expr(),
                init_code.offset(),
                init_code.address(),
                0.expr(),
                init_code.length(),
                init_code_rlc.expr(),
                init_code.length(),
            );
            (init_code_rlc, keccak_code_hash)
        });
        cb.condition(not::expr(init_code.has_length()), |cb| {
            cb.require_equal(
                "keccak hash of empty bytes",
                keccak_code_hash.expr(),
                cb.empty_keccak_hash_rlc(),
            );
            cb.require_equal(
                "code hash of empty bytes",
                create.code_hash_word_rlc(),
                cb.empty_code_hash_rlc(),
            );
        });

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let was_warm = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            new_address.clone(),
            1.expr(),
            was_warm.expr(),
            Some(&mut reversion_info),
        );

        let depth = cb.call_context(None, CallContextFieldTag::Depth);
        let is_depth_in_range = LtGadget::construct(cb, depth.expr(), 1025.expr());

        cb.call_context_lookup(
            0.expr(),
            None,
            CallContextFieldTag::CalleeAddress,
            create.caller_address(),
        );

        let caller_balance = cb.query_word_rlc();
        cb.account_read(
            create.caller_address(),
            AccountFieldTag::Balance,
            caller_balance.expr(),
        );
        let is_insufficient_balance = LtWordGadget::construct(cb, &caller_balance, &value);

        let caller_nonce = create.caller_nonce();
        cb.account_read(
            create.caller_address(),
            AccountFieldTag::Nonce,
            caller_nonce.expr(),
        );
        let is_nonce_in_range = LtGadget::construct(cb, caller_nonce.expr(), u64::MAX.expr());

        cb.condition(is_insufficient_balance.expr(), |cb| {
            cb.require_equal(
                "Depth must be in range if caller balance is insufficient",
                is_depth_in_range.expr(),
                1.expr(),
            );
        });

        cb.condition(not::expr(is_nonce_in_range.expr()), |cb| {
            cb.require_equal(
                "Depth must be in range and caller balance must be sufficient if nonce is overflow",
                and::expr([
                    is_depth_in_range.expr(),
                    not::expr(is_insufficient_balance.expr()),
                ]),
                1.expr(),
            );
        });

        let is_precheck_ok = and::expr([
            is_depth_in_range.expr(),
            not::expr(is_insufficient_balance.expr()),
            is_nonce_in_range.expr(),
        ]);

        cb.condition(is_precheck_ok.expr(), |cb| {
            cb.account_write(
                create.caller_address(),
                AccountFieldTag::Nonce,
                caller_nonce.expr() + 1.expr(),
                caller_nonce,
                Some(&mut reversion_info),
            );
        });

        cb.condition(
            and::expr([is_precheck_ok.expr(), init_code.has_length()]),
            |cb| {
                cb.keccak_table_lookup(
                    init_code_rlc.expr(),
                    init_code.length(),
                    keccak_code_hash.expr(),
                );
            },
        );

        let mut callee_reversion_info = cb.reversion_info_write(Some(callee_call_id.expr()));
        cb.require_equal(
            "callee_is_persistent == is_persistent ⋅ is_success",
            callee_reversion_info.is_persistent(),
            reversion_info.is_persistent() * callee_is_success.expr(),
        );
        cb.condition(callee_is_success.expr() * (1.expr() - reversion_info.is_persistent()), |cb| {
            cb.require_equal(
                "callee_rw_counter_end_of_reversion == rw_counter_end_of_reversion - (reversible_write_counter + 1)",
                callee_reversion_info.rw_counter_end_of_reversion(),
                reversion_info.rw_counter_of_reversion(1.expr()),
            );
        });

        // check for address collision case by code hash previous
        cb.account_read(
            new_address.clone(),
            AccountFieldTag::CodeHash,
            code_hash_previous.expr(),
        );

        let not_address_collision = IsZeroGadget::construct(cb, "", code_hash_previous.expr());
        /*
        // CREATE2 may cause address collision error. And for a tricky
        // case of CREATE, it could also cause this error. e.g. the `to`
        // field of transaction is set to the calculated contract
        // address (reference testool case
        // `RevertDepthCreateAddressCollision_d0_g0_v0` for details).
        cb.condition(not::expr(not_address_collision.expr()), |cb| {
            cb.require_equal(
                "op code is create2 for address collision",
                opcode.expr(),
                OpcodeId::CREATE2.expr(),
            );
        });
        */

        // conditional transfer for address collision case
        let transfer = cb.condition(
            and::expr([is_precheck_ok.expr(), not_address_collision.expr()]),
            |cb| {
                let tansfer_gadget = TransferGadget::construct(
                    cb,
                    create.caller_address(),
                    new_address.clone(),
                    0.expr(),
                    1.expr(),
                    value.clone(),
                    &mut callee_reversion_info,
                );
                cb.account_write(
                    new_address.clone(),
                    AccountFieldTag::Nonce,
                    1.expr(),
                    0.expr(),
                    Some(&mut callee_reversion_info),
                );

                tansfer_gadget
            },
        );

        let memory_expansion = MemoryExpansionGadget::construct(cb, [init_code.address()]);

        let init_code_word_size = ConstantDivisionGadget::construct(
            cb,
            init_code.length() + (N_BYTES_WORD - 1).expr(),
            N_BYTES_WORD as u64,
        );
        let keccak_gas_cost = init_code_word_size.quotient()
            * if IS_CREATE2 {
                CREATE2_GAS_PER_CODE_WORD
            } else {
                CREATE_GAS_PER_CODE_WORD
            }
            .expr();

        let gas_cost = GasCost::CREATE.expr() + memory_expansion.gas_cost() + keccak_gas_cost;
        let gas_remaining = cb.curr.state.gas_left.expr() - gas_cost.clone();
        let gas_left = ConstantDivisionGadget::construct(cb, gas_remaining.clone(), 64);
        let callee_gas_left = gas_remaining - gas_left.quotient();
        for (field_tag, value) in [
            (
                CallContextFieldTag::ProgramCounter,
                cb.curr.state.program_counter.expr() + 1.expr(),
            ),
            (
                CallContextFieldTag::StackPointer,
                cb.curr.state.stack_pointer.expr() + 2.expr() + IS_CREATE2.expr(),
            ),
            (CallContextFieldTag::GasLeft, gas_left.quotient()),
            (
                CallContextFieldTag::MemorySize,
                memory_expansion.next_memory_word_size(),
            ),
            (
                CallContextFieldTag::ReversibleWriteCounter,
                cb.curr.state.reversible_write_counter.expr() + 2.expr(),
            ),
        ] {
            cb.call_context_lookup(true.expr(), None, field_tag, value);
        }

        // Handle the case where an error of ErrDepth, ErrInsufficientBalance or
        // ErrNonceUintOverflow occurred.
        cb.condition(not::expr(is_precheck_ok.expr()), |cb| {
            // Save caller's call state
            for field_tag in [
                CallContextFieldTag::LastCalleeId,
                CallContextFieldTag::LastCalleeReturnDataOffset,
                CallContextFieldTag::LastCalleeReturnDataLength,
            ] {
                cb.call_context_lookup(true.expr(), None, field_tag, 0.expr());
            }

            cb.require_step_state_transition(StepStateTransition {
                rw_counter: Delta(cb.rw_counter_offset()),
                program_counter: Delta(1.expr()),
                stack_pointer: Delta(2.expr() + IS_CREATE2.expr()),
                memory_word_size: To(memory_expansion.next_memory_word_size()),
                // - (Reversible) Write TxAccessListAccount (Contract Address)
                reversible_write_counter: Delta(1.expr()),
                gas_left: Delta(-gas_cost.expr()),
                ..StepStateTransition::default()
            });
        });

        // Proceed to handle the case where precheck is OK.
        cb.condition(is_precheck_ok, |cb| {
            for (field_tag, value) in [
                (CallContextFieldTag::CallerId, cb.curr.state.call_id.expr()),
                (CallContextFieldTag::IsSuccess, callee_is_success.expr()),
                (
                    CallContextFieldTag::IsPersistent,
                    callee_reversion_info.is_persistent(),
                ),
                (CallContextFieldTag::TxId, tx_id.expr()),
                (CallContextFieldTag::CallerAddress, create.caller_address()),
                (CallContextFieldTag::CalleeAddress, new_address),
                (
                    CallContextFieldTag::RwCounterEndOfReversion,
                    callee_reversion_info.rw_counter_end_of_reversion(),
                ),
                (CallContextFieldTag::Depth, depth.expr() + 1.expr()),
                (CallContextFieldTag::IsRoot, false.expr()),
                (CallContextFieldTag::IsStatic, false.expr()),
                (CallContextFieldTag::IsCreate, true.expr()),
                (CallContextFieldTag::CodeHash, create.code_hash_word_rlc()),
                (CallContextFieldTag::Value, value.expr()),
            ] {
                cb.call_context_lookup(true.expr(), Some(callee_call_id.expr()), field_tag, value);
            }

            // keccak table lookup to verify contract address.
            cb.keccak_table_lookup(
                create.input_rlc(cb),
                create.input_length(),
                keccak_output.expr(),
            );

            // handle state transition if non-empty init code and no collision.
            cb.condition(
                init_code.has_length() * not_address_collision.expr(),
                |cb| {
                    cb.require_step_state_transition(StepStateTransition {
                        rw_counter: Delta(cb.rw_counter_offset()),
                        call_id: To(callee_call_id.expr()),
                        is_root: To(false.expr()),
                        is_create: To(true.expr()),
                        code_hash: To(create.code_hash_word_rlc()),
                        gas_left: To(callee_gas_left),
                        reversible_write_counter: To(1.expr() + transfer.reversible_w_delta()),
                        ..StepStateTransition::new_context()
                    })
                },
            );

            // handle state transition if empty init code and no collision.
            cb.condition(
                not::expr(init_code.has_length()) * not_address_collision.expr(),
                |cb| {
                    for field_tag in [
                        CallContextFieldTag::LastCalleeId,
                        CallContextFieldTag::LastCalleeReturnDataOffset,
                        CallContextFieldTag::LastCalleeReturnDataLength,
                    ] {
                        cb.call_context_lookup(true.expr(), None, field_tag, 0.expr());
                    }
                    cb.require_step_state_transition(StepStateTransition {
                        rw_counter: Delta(cb.rw_counter_offset()),
                        program_counter: Delta(1.expr()),
                        stack_pointer: Delta(2.expr() + IS_CREATE2.expr()),
                        gas_left: Delta(-gas_cost.expr()),
                        reversible_write_counter: Delta(3.expr() + transfer.reversible_w_delta()),
                        ..Default::default()
                    })
                },
            );

            // handle address collision.
            cb.condition(not::expr(not_address_collision.expr()), |cb| {
                for field_tag in [
                    CallContextFieldTag::LastCalleeId,
                    CallContextFieldTag::LastCalleeReturnDataOffset,
                    CallContextFieldTag::LastCalleeReturnDataLength,
                ] {
                    cb.call_context_lookup(true.expr(), None, field_tag, 0.expr());
                }

                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(cb.rw_counter_offset()),
                    program_counter: Delta(1.expr()),
                    stack_pointer: Delta(2.expr() + IS_CREATE2.expr()),
                    gas_left: To(gas_left.quotient()),
                    reversible_write_counter: Delta(2.expr()),
                    ..Default::default()
                })
            });
        });

        Self {
            opcode,
            reversion_info,
            tx_id,
            was_warm,
            value,
            depth,
            callee_reversion_info,
            transfer,
            init_code,
            init_code_rlc,
            memory_expansion,
            gas_left,
            callee_is_success,
            init_code_word_size,
            init_code_size_not_overflow,
            create,
            caller_balance,
            is_depth_in_range,
            is_insufficient_balance,
            is_nonce_in_range,
            keccak_code_hash,
            keccak_output,
            code_hash_previous,
            not_address_collision,
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
        let opcode = step.opcode.unwrap();
        let is_create2 = opcode == OpcodeId::CREATE2;
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let mut rw_offset = 1; // is_static
        let [value, init_code_start, init_code_length] = [0, 1, 2]
            .map(|i| step.rw_indices[i + rw_offset])
            .map(|idx| block.rws[idx].stack_value());
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        let salt = if is_create2 {
            block.rws[step.rw_indices[3 + rw_offset]].stack_value()
        } else {
            U256::zero()
        };
        rw_offset += usize::from(is_create2);
        let values: Vec<_> = (4..4 + init_code_length.as_usize())
            .map(|i| block.rws[step.rw_indices[i + rw_offset]].memory_value())
            .collect();
        let copy_rw_increase = init_code_length.as_usize();
        let keccak_code_hash = keccak256(&values);

        let init_code_address =
            self.init_code
                .assign(region, offset, init_code_start, init_code_length)?;
        self.init_code_rlc.assign(
            region,
            offset,
            region.keccak_rlc(&values.iter().rev().cloned().collect::<Vec<u8>>()),
        )?;
        self.init_code_size_not_overflow.assign(
            region,
            offset,
            F::from(init_code_length.as_u64()),
            F::from(MAX_INIT_CODE_SIZE + 1),
        )?;

        self.tx_id
            .assign(region, offset, Value::known(tx.id.to_scalar().unwrap()))?;
        self.depth.assign(
            region,
            offset,
            Value::known(call.depth.to_scalar().unwrap()),
        )?;

        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        rw_offset += copy_rw_increase;
        let tx_access_rw = block.rws[step.rw_indices[7 + rw_offset]];
        self.was_warm.assign(
            region,
            offset,
            Value::known(
                tx_access_rw
                    .tx_access_list_value_pair()
                    .1
                    .to_scalar()
                    .unwrap(),
            ),
        )?;

        let caller_balance = block.rws[step.rw_indices[10 + rw_offset]]
            .account_balance_pair()
            .1;

        let caller_nonce = block.rws[step.rw_indices[11 + rw_offset]]
            .account_nonce_pair()
            .1
            .low_u64();

        let is_precheck_ok =
            if call.depth < 1025 && caller_balance >= value && caller_nonce < u64::MAX {
                1
            } else {
                0
            };
        rw_offset += is_precheck_ok;
        let [callee_rw_counter_end_of_reversion, callee_is_persistent] = [12, 13].map(|i| {
            let rw = block.rws[step.rw_indices[i + rw_offset]];
            rw.call_context_value()
        });

        self.callee_reversion_info.assign(
            region,
            offset,
            callee_rw_counter_end_of_reversion
                .low_u64()
                .try_into()
                .unwrap(),
            callee_is_persistent.low_u64() != 0,
        )?;

        // retrieve code_hash for creating address
        let code_hash_previous = block.rws[step.rw_indices[14 + rw_offset]].account_codehash_pair();
        let code_hash_previous_rlc = region.code_hash(code_hash_previous.0);
        self.code_hash_previous
            .assign(region, offset, code_hash_previous_rlc)?;
        self.not_address_collision
            .assign_value(region, offset, code_hash_previous_rlc)?;
        let is_address_collision = !code_hash_previous.0.is_zero();

        #[cfg(feature = "scroll")]
        {
            rw_offset += 1; // Write empty Keccak code hash.
        }

        if is_precheck_ok == 1 && !is_address_collision {
            let [caller_balance_pair, callee_balance_pair] = if !value.is_zero() {
                let account_balance_pair = [16, 17]
                    .map(|i| block.rws[step.rw_indices[i + rw_offset]].account_balance_pair());
                rw_offset += 2;
                account_balance_pair
            } else {
                [(0.into(), 0.into()), (0.into(), 0.into())]
            };

            self.transfer.assign(
                region,
                offset,
                caller_balance_pair,
                callee_balance_pair,
                value,
            )?;
        }

        let (_next_memory_word_size, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [init_code_address],
        )?;

        let (init_code_word_size, _remainder) = self.init_code_word_size.assign(
            region,
            offset,
            (31u64 + init_code_length.as_u64()).into(),
        )?;

        let keccak_gas_cost = u64::try_from(init_code_word_size).unwrap()
            * if IS_CREATE2 {
                CREATE2_GAS_PER_CODE_WORD
            } else {
                CREATE_GAS_PER_CODE_WORD
            };
        let gas_left =
            step.gas_left - GasCost::CREATE.as_u64() - memory_expansion_gas_cost - keccak_gas_cost;
        self.gas_left.assign(region, offset, gas_left.into())?;

        self.callee_is_success.assign(
            region,
            offset,
            Value::known(if is_precheck_ok == 0 || is_address_collision {
                F::zero()
            } else {
                block.rws[step.rw_indices[23 + rw_offset]]
                    .call_context_value()
                    .to_scalar()
                    .unwrap()
            }),
        )?;

        let keccak_input: Vec<u8> = if is_create2 {
            once(0xffu8)
                .chain(call.callee_address.to_fixed_bytes())
                .chain(salt.to_be_bytes())
                .chain(keccak_code_hash)
                .collect()
        } else {
            let mut stream = ethers_core::utils::rlp::RlpStream::new();
            stream.begin_list(2);
            stream.append(&call.callee_address);
            stream.append(&U256::from(caller_nonce));
            stream.out().to_vec()
        };
        let mut keccak_output = keccak256(keccak_input);
        keccak_output.reverse();

        self.keccak_output
            .assign(region, offset, Some(keccak_output))?;

        let code_hash = CodeDB::hash(&values);
        self.create.assign(
            region,
            offset,
            call.callee_address,
            caller_nonce,
            Some(U256::from(keccak_code_hash)),
            Some(U256::from(code_hash.to_fixed_bytes())),
            Some(salt),
        )?;
        self.caller_balance
            .assign(region, offset, Some(caller_balance.to_le_bytes()))?;
        self.is_insufficient_balance
            .assign(region, offset, caller_balance, value)?;

        self.is_depth_in_range
            .assign(region, offset, F::from(call.depth as u64), F::from(1025))?;
        self.is_nonce_in_range
            .assign(region, offset, F::from(caller_nonce), F::from(u64::MAX))?;

        self.keccak_code_hash.assign(
            region,
            offset,
            region.word_rlc(U256::from_big_endian(&keccak_code_hash)),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        address, bytecode, evm_types::OpcodeId, geth_types::Account, word, Address, Bytecode, Word,
    };
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use mock::{eth, TestContext};

    const CALLEE_ADDRESS: Address = Address::repeat_byte(0xff);
    lazy_static! {
        static ref CALLER_ADDRESS: Address = address!("0x00bbccddee000000000000000000000000002400");
    }

    fn run_test_circuits(ctx: TestContext<2, 1>) {
        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_rws: 300000,
                ..Default::default()
            })
            .run();
    }

    // RETURN or REVERT with data of [0x60; 5]
    fn initialization_bytecode(is_success: bool) -> Bytecode {
        let memory_bytes = [0x60; 10];
        let memory_address = 0;
        let memory_value = Word::from_big_endian(&memory_bytes);
        let mut code = bytecode! {
            PUSH10(memory_value)
            PUSH1(memory_address)
            MSTORE
            PUSH2(5)
            PUSH2(32u64 - u64::try_from(memory_bytes.len()).unwrap())
        };
        code.write_op(if is_success {
            OpcodeId::RETURN
        } else {
            OpcodeId::REVERT
        });
        code
    }

    fn creater_bytecode(
        initialization_bytecode: Bytecode,
        value: Word,
        is_create2: bool,
        is_persistent: bool,
    ) -> Bytecode {
        let initialization_bytes = initialization_bytecode.code();
        let mut code = bytecode! {
            PUSH32(Word::from_big_endian(&initialization_bytes))
            PUSH1(0)
            MSTORE
        };
        if is_create2 {
            code.append(&bytecode! {PUSH1(45)}); // salt;
        }
        code.append(&bytecode! {
            PUSH1(initialization_bytes.len()) // size
            PUSH1(32 - initialization_bytes.len()) // length
            PUSH2(value) // value
        });
        code.write_op(if is_create2 {
            OpcodeId::CREATE2
        } else {
            OpcodeId::CREATE
        });
        if !is_persistent {
            code.append(&bytecode! {
                PUSH1(0)
                PUSH1(0)
                REVERT
            });
        }
        code
    }

    fn creater_bytecode_address_collision(initialization_bytecode: Bytecode) -> Bytecode {
        let initialization_bytes = initialization_bytecode.code();
        let mut code = bytecode! {
            PUSH32(Word::from_big_endian(&initialization_bytes))
            PUSH1(0)
            MSTORE
        };

        code.append(&bytecode! {PUSH1(45)}); // salt;
        code.append(&bytecode! {
            PUSH1(initialization_bytes.len()) // size
            PUSH1(32 - initialization_bytes.len()) // length
            PUSH2(23414) // value
        });
        code.write_op(OpcodeId::CREATE2);

        // construct address collision by create2 twice
        code.append(&bytecode! {PUSH1(45)}); // salt;

        code.append(&bytecode! {
            PUSH1(initialization_bytes.len()) // size
            PUSH1(32 - initialization_bytes.len()) // length
            PUSH2(23414) // value
        });
        code.write_op(OpcodeId::CREATE2);
        code.append(&bytecode! {
            PUSH1(0)
            PUSH1(0)
            REVERT
        });

        code
    }

    fn test_context(caller: Account) -> TestContext<2, 1> {
        TestContext::new(
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
                    .gas(word!("0x2386F26FC10000"));
            },
            |block, _| block,
        )
        .unwrap()
    }

    #[test]
    fn test_create() {
        for ((is_success, is_create2), is_persistent) in [true, false]
            .iter()
            .cartesian_product(&[true, false])
            .cartesian_product(&[true, false])
        {
            let init_code = initialization_bytecode(*is_success);
            let root_code = creater_bytecode(init_code, 23414.into(), *is_create2, *is_persistent);
            let caller = Account {
                address: *CALLER_ADDRESS,
                code: root_code.into(),
                nonce: Word::one(),
                balance: eth(10),
                ..Default::default()
            };
            run_test_circuits(test_context(caller));
        }
    }

    #[test]
    fn test_create_rlp_nonce() {
        for nonce in [0, 1, 127, 128, 255, 256, 0x10000, u64::MAX - 1] {
            let caller = Account {
                address: *CALLER_ADDRESS,
                code: creater_bytecode(initialization_bytecode(true), 23414.into(), false, true)
                    .into(),
                nonce: nonce.into(),
                balance: eth(10),
                ..Default::default()
            };
            run_test_circuits(test_context(caller))
        }
    }

    #[test]
    fn test_create_empty_init_code() {
        for is_create2 in [true, false] {
            let caller = Account {
                address: *CALLER_ADDRESS,
                code: creater_bytecode(vec![].into(), 23414.into(), is_create2, true).into(),
                nonce: 10.into(),
                balance: eth(10),
                ..Default::default()
            };
            run_test_circuits(test_context(caller));
        }
    }

    #[test]
    fn test_create_overflow_offset_and_zero_size() {
        for is_create2 in [true, false] {
            let mut bytecode = bytecode! {
                PUSH1(0) // size
                PUSH32(Word::MAX) // offset
                PUSH2(23414) // value
            };
            bytecode.write_op(if is_create2 {
                OpcodeId::CREATE2
            } else {
                OpcodeId::CREATE
            });
            let caller = Account {
                address: *CALLER_ADDRESS,
                code: bytecode.into(),
                nonce: 10.into(),
                balance: eth(10),
                ..Default::default()
            };
            run_test_circuits(test_context(caller));
        }
    }

    #[test]
    fn test_create_address_collision_error() {
        let initialization_code = initialization_bytecode(false);
        let root_code = creater_bytecode_address_collision(initialization_code);
        let caller = Account {
            address: *CALLER_ADDRESS,
            code: root_code.into(),
            nonce: Word::one(),
            balance: eth(10),
            ..Default::default()
        };
        run_test_circuits(test_context(caller));
    }

    // Ignore this test case. It could run successfully but slow for CI.
    #[ignore]
    #[test]
    fn test_create_error_depth() {
        let code = bytecode! {
            PUSH1(0x20)
            PUSH1(0x0)
            PUSH1(0x0)
            CODECOPY
            PUSH1(0x20)
            PUSH1(0x0)
            PUSH1(0x0)
            CREATE
        }
        .into();
        let caller = Account {
            address: *CALLER_ADDRESS,
            code,
            nonce: Word::one(),
            balance: eth(10),
            ..Default::default()
        };
        run_test_circuits(test_context(caller));
    }

    #[test]
    fn test_create_insufficient_balance() {
        let value = 23414.into();
        for is_create2 in [true, false] {
            let caller = Account {
                address: mock::MOCK_ACCOUNTS[0],
                nonce: 1.into(),
                code: creater_bytecode(initialization_bytecode(false), value, is_create2, true)
                    .into(),
                balance: value - 1,
                ..Default::default()
            };
            run_test_circuits(test_context(caller));
        }
    }

    #[test]
    fn test_create_nonce_uint_overflow() {
        // TRICKY:
        // Caller nonce could not be set to `u64::MAX` directly. Since geth
        // [preCheck](https://github.com/ethereum/go-ethereum/blob/4a9fa31450d3cdcea84735b68cd5a0a8450473f8/core/state_transition.go#L262)
        // function has a check for nonce uint overflow. So there are two nested
        // CREATE (or CREATE2) in bytecode, which could increase nonce from
        // `u64::MAX - 1` to `u64::MAX` in the internal loop.
        let bytecodes = [
            bytecode! {
                PUSH1(2) // size
                PUSH1(0) // offset
                PUSH1(1) // value
                CREATE
                PUSH1(2) // size
                PUSH1(2) // offset
                PUSH1(1) // value
                CREATE
            },
            bytecode! {
                PUSH1(0) // salt
                PUSH1(2) // size
                PUSH1(0) // offset
                PUSH1(1) // value
                CREATE2
                PUSH1(0) // salt
                PUSH1(2) // size
                PUSH1(2) // offset
                PUSH1(1) // value
                CREATE2
            },
        ];

        bytecodes.into_iter().for_each(|code| {
            let caller = Account {
                address: *CALLER_ADDRESS,
                code: code.into(),
                nonce: (u64::MAX - 1).into(),
                balance: eth(10),
                ..Default::default()
            };
            run_test_circuits(test_context(caller));
        });
    }
}
