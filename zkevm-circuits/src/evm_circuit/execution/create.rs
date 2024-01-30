use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{
            N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE,
            N_BYTES_U64, N_BYTES_WORD,
        },
        step::ExecutionState,
        util::{
            common_gadget::{get_copy_bytes, TransferGadget},
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
            not, CachedRegion, Cell, StepRws, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag, RwTableTag},
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId, state_db::CodeDB};
use eth_types::{
    evm_types::{GasCost, CREATE2_GAS_PER_CODE_WORD, CREATE_GAS_PER_CODE_WORD, MAX_INIT_CODE_SIZE},
    Field, ToBigEndian, ToLittleEndian, ToScalar, ToWord, H256, KECCAK_CODE_HASH_EMPTY, U256,
};
use ethers_core::utils::keccak256;
use gadgets::util::{and, expr_from_bytes};
use halo2_proofs::{circuit::Value, plonk::Error};
use log::trace;
use std::iter::once;

/// Gadget for CREATE and CREATE2 opcodes
#[derive(Clone, Debug)]
pub(crate) struct CreateGadget<F, const IS_CREATE2: bool, const S: ExecutionState> {
    opcode: Cell<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    depth: Cell<F>,

    is_success: Cell<F>,
    was_warm: Cell<F>,
    value: Word<F>,

    caller_balance: Word<F>,
    callee_reversion_info: ReversionInfo<F>,
    callee_nonce: Cell<F>,
    prev_code_hash: Cell<F>,
    prev_code_hash_is_zero: IsZeroGadget<F>,
    transfer: TransferGadget<F>,
    create: ContractCreateGadget<F, IS_CREATE2>,

    init_code: MemoryAddressGadget<F>,
    init_code_word_size: ConstantDivisionGadget<F, N_BYTES_MEMORY_ADDRESS>,
    // Init code size must be less than or equal to 49152
    // (maximum init code size) if Shanghai, otherwise should be less than or
    // equal to 0x1FFFFFFFE0 (maximum value of offset + size).
    init_code_size_not_overflow: LtGadget<F, { N_BYTES_MEMORY_ADDRESS }>,
    init_code_rlc: Cell<F>,
    keccak_output: Word<F>,

    is_depth_in_range: LtGadget<F, N_BYTES_U64>,
    is_insufficient_balance: LtWordGadget<F>,
    is_nonce_in_range: LtGadget<F, N_BYTES_U64>,
    not_address_collision: IsZeroGadget<F>,

    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    gas_left: ConstantDivisionGadget<F, N_BYTES_GAS>,
    // check address collision use
    keccak_code_hash: Cell<F>,
    #[cfg(feature = "scroll")]
    prev_keccak_code_hash: Cell<F>,
    copy_rw_increase: Cell<F>,
}

impl<F: Field, const IS_CREATE2: bool, const S: ExecutionState> ExecutionGadget<F>
    for CreateGadget<F, IS_CREATE2, S>
{
    const NAME: &'static str = "CREATE";

    const EXECUTION_STATE: ExecutionState = S;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let copy_rw_increase = cb.query_cell();

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

        // Use rw_counter of the step which triggers next call as its call_id.
        let callee_call_id = cb.curr.state.rw_counter.clone();
        let current_call_id = cb.curr.state.call_id.clone();
        let is_success = cb.query_bool();

        // read from call context
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let depth = cb.call_context(None, CallContextFieldTag::Depth);
        let mut reversion_info = cb.reversion_info_read(None);

        // constrain not in static call
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static is false", is_static.expr());

        let keccak_output = cb.query_word_rlc();
        let create = ContractCreateGadget::construct(cb);
        let contract_addr_rlc = cb.word_rlc::<N_BYTES_ACCOUNT_ADDRESS>(
            keccak_output
                .cells
                .iter()
                .take(N_BYTES_ACCOUNT_ADDRESS)
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );
        let contract_addr = expr_from_bytes(&keccak_output.cells[..N_BYTES_ACCOUNT_ADDRESS]);

        // stack operations
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

        cb.stack_pop(value.expr());
        cb.stack_pop(init_code.offset_rlc());
        cb.stack_pop(init_code.length_rlc());
        if IS_CREATE2 {
            cb.stack_pop(create.salt_word_rlc(cb));
        }

        cb.stack_push(is_success.expr() * contract_addr_rlc);

        let (init_code_rlc, keccak_code_hash) = cb.condition(init_code.has_length(), |cb| {
            // the init code is being copied from memory to bytecode, so a copy table lookup to
            // verify that the associated fields for the copy event.
            let keccak_code_hash = cb.query_cell_phase2();
            let init_code_rlc = cb.query_cell_phase2();

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

        cb.call_context_lookup(
            0.expr(),
            None,
            CallContextFieldTag::CalleeAddress,
            create.caller_address(),
        );

        // read caller's balance and nonce
        let caller_nonce = create.caller_nonce();
        let caller_balance = cb.query_word_rlc();
        cb.account_read(
            create.caller_address(),
            AccountFieldTag::Balance,
            caller_balance.expr(),
        );
        cb.account_read(
            create.caller_address(),
            AccountFieldTag::Nonce,
            caller_nonce.expr(),
        );

        // Pre-check: call depth, user's nonce and user's balance
        let is_depth_in_range = LtGadget::construct(cb, depth.expr(), 1025.expr());
        let is_insufficient_balance = LtWordGadget::construct(cb, &caller_balance, &value);
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

        // verify gas cost
        let memory_expansion = MemoryExpansionGadget::construct(cb, [init_code.end_offset()]);
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

        let was_warm = cb.query_bool();
        let prev_code_hash = cb.query_cell();
        #[cfg(feature = "scroll")]
        let prev_keccak_code_hash = cb.query_cell_phase2();
        let callee_nonce = cb.query_cell();

        // callee address's nonce
        let (prev_code_hash_is_zero, not_address_collision) =
            cb.condition(is_precheck_ok.expr(), |cb| {
                // increase caller's nonce
                cb.account_write(
                    create.caller_address(),
                    AccountFieldTag::Nonce,
                    caller_nonce.expr() + 1.expr(),
                    caller_nonce,
                    Some(&mut reversion_info),
                );

                // add callee to access list
                cb.account_access_list_write(
                    tx_id.expr(),
                    contract_addr.clone(),
                    1.expr(),
                    was_warm.expr(),
                    Some(&mut reversion_info),
                );

                // read contract's previous hash
                cb.account_read(
                    contract_addr.clone(),
                    AccountFieldTag::CodeHash,
                    prev_code_hash.expr(),
                );
                let prev_code_hash_is_zero = IsZeroGadget::construct(cb, prev_code_hash.expr());
                cb.condition(not::expr(prev_code_hash_is_zero.expr()), |cb| {
                    cb.account_read(
                        contract_addr.clone(),
                        AccountFieldTag::Nonce,
                        callee_nonce.expr(),
                    );
                });
                // ErrContractAddressCollision, if any one of following criteria meets.
                // Nonce is not zero or account code hash is not either 0 or EMPTY_CODE_HASH.
                // Here use `isZeroGadget(callee_nonce + prev_code_hash * (prev_code_hash -
                // empty_code_hash))` to represent `(callee_nonce == 0 && (prev_code_hash == 0
                // or prev_code_hash == empty_code_hash))`
                (
                    prev_code_hash_is_zero,
                    IsZeroGadget::construct(
                        cb,
                        callee_nonce.expr()
                            + prev_code_hash.expr()
                                * (prev_code_hash.expr() - cb.empty_code_hash_rlc()),
                    ),
                )
            });

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

        cb.condition(is_precheck_ok.clone(), |cb| {
            cb.condition(init_code.has_length(), |cb| {
                // the init code is being copied from memory to bytecode, so a copy table lookup
                // to verify that the associated fields for the copy event.
                cb.copy_table_lookup(
                    cb.curr.state.call_id.expr(),
                    CopyDataType::Memory.expr(),
                    create.code_hash_word_rlc(),
                    CopyDataType::Bytecode.expr(),
                    init_code.offset(),
                    init_code.end_offset(),
                    0.expr(),
                    init_code.length(),
                    init_code_rlc.expr(),
                    copy_rw_increase.expr(),
                );
            });
        });

        let mut callee_reversion_info = cb.reversion_info_write(Some(callee_call_id.expr()));

        // Case1: Handle the case where an error of ErrDepth, ErrInsufficientBalance or
        // ErrNonceUintOverflow occurred.
        cb.condition(not::expr(is_precheck_ok.expr()), |cb| {
            // Save caller's call state
            cb.call_context_lookup(
                true.expr(),
                None,
                CallContextFieldTag::LastCalleeId,
                callee_call_id.expr(),
            );
            for field_tag in [
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
                gas_left: Delta(-gas_cost.expr()),
                ..StepStateTransition::default()
            });
        });

        // Case2: normal create all, precheck is ok and no address collision
        let transfer = cb.condition(
            and::expr([is_precheck_ok.clone(), not_address_collision.expr()]),
            |cb| {
                cb.condition(init_code.has_length(), |cb| {
                    cb.keccak_table_lookup(
                        init_code_rlc.expr(),
                        init_code.length(),
                        keccak_code_hash.expr(),
                    );
                });

                // keccak table lookup to verify contract address.
                cb.keccak_table_lookup(
                    create.input_rlc(cb),
                    create.input_length(),
                    keccak_output.expr(),
                );

                // propagate is_persistent
                cb.require_equal(
                    "callee_is_persistent == is_persistent ⋅ is_success",
                    callee_reversion_info.is_persistent(),
                    reversion_info.is_persistent() * is_success.expr(),
                );

                // transfer
                let transfer = TransferGadget::construct(
                    cb,
                    create.caller_address(),
                    contract_addr.clone(),
                    0.expr(),
                    1.expr(),
                    prev_code_hash.expr(),
                    #[cfg(feature = "scroll")]
                    prev_keccak_code_hash.expr(),
                    value.clone(),
                    &mut callee_reversion_info,
                );
                // EIP 161, the nonce of a newly created contract is 1
                cb.account_write(
                    contract_addr.clone(),
                    AccountFieldTag::Nonce,
                    1.expr(),
                    0.expr(),
                    Some(&mut callee_reversion_info),
                );

                cb.condition(init_code.has_length(), |cb| {
                    for (field_tag, value) in [
                        (CallContextFieldTag::CallerId, current_call_id.expr()),
                        (CallContextFieldTag::IsSuccess, is_success.expr()),
                        (
                            CallContextFieldTag::IsPersistent,
                            callee_reversion_info.is_persistent(),
                        ),
                        (CallContextFieldTag::TxId, tx_id.expr()),
                        (CallContextFieldTag::CallerAddress, create.caller_address()),
                        (CallContextFieldTag::CalleeAddress, contract_addr),
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
                        cb.call_context_lookup(
                            true.expr(),
                            Some(callee_call_id.expr()),
                            field_tag,
                            value,
                        );
                    }
                    cb.require_step_state_transition(StepStateTransition {
                        rw_counter: Delta(cb.rw_counter_offset()),
                        call_id: To(callee_call_id.expr()),
                        is_root: To(false.expr()),
                        is_create: To(true.expr()),
                        code_hash: To(create.code_hash_word_rlc()),
                        gas_left: To(callee_gas_left),
                        reversible_write_counter: To(1.expr() + transfer.reversible_w_delta()),
                        ..StepStateTransition::new_context()
                    });
                });
                // handle state transition if empty init code
                cb.condition(not::expr(init_code.has_length()), |cb| {
                    cb.call_context_lookup(
                        true.expr(),
                        None,
                        CallContextFieldTag::LastCalleeId,
                        callee_call_id.expr(),
                    );
                    for field_tag in [
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
                });

                transfer
            },
        );

        cb.condition(
            is_success.expr() * (1.expr() - reversion_info.is_persistent()),
            |cb| {
                cb.require_equal(
                    "callee_rw_counter_end_of_reversion == rw_counter_end_of_reversion-(reversible_write_counter + 1)",
                    callee_reversion_info.rw_counter_end_of_reversion(),
                    reversion_info.rw_counter_of_reversion(1.expr()),
                );
            },
        );

        // Case3: Handle the case where ErrContractAddressCollision occurred.
        cb.condition(
            and::expr([is_precheck_ok, not::expr(not_address_collision.expr())]),
            |cb| {
                cb.call_context_lookup(
                    true.expr(),
                    None,
                    CallContextFieldTag::LastCalleeId,
                    callee_call_id.expr(),
                );
                for field_tag in [
                    CallContextFieldTag::LastCalleeReturnDataOffset,
                    CallContextFieldTag::LastCalleeReturnDataLength,
                ] {
                    cb.call_context_lookup(true.expr(), None, field_tag, 0.expr());
                }
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(cb.rw_counter_offset()),
                    program_counter: Delta(1.expr()),
                    stack_pointer: Delta(2.expr() + IS_CREATE2.expr()),
                    reversible_write_counter: Delta(2.expr()),
                    memory_word_size: To(memory_expansion.next_memory_word_size()),
                    gas_left: To(gas_left.quotient()),
                    ..StepStateTransition::default()
                })
            },
        );

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
            init_code_word_size,
            init_code_size_not_overflow,
            create,
            caller_balance,
            is_depth_in_range,
            is_insufficient_balance,
            is_nonce_in_range,
            callee_nonce,
            keccak_code_hash,
            keccak_output,
            not_address_collision,
            is_success,
            prev_code_hash,
            prev_code_hash_is_zero,
            #[cfg(feature = "scroll")]
            prev_keccak_code_hash,
            copy_rw_increase,
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

        let mut rws = StepRws::new(block, step);
        // 0..3 : TxId, Depth, RwCounterEndOfReversion and IsPersistent
        // 4 : IsStatic
        rws.offset_add(5);

        let [value, init_code_start, init_code_length] = [(); 3].map(|_| rws.next().stack_value());
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        let salt = if is_create2 {
            rws.next().stack_value()
        } else {
            U256::zero()
        };
        rws.next(); // skip stack output

        rws.next(); // caller address
                    // Pre-check: call depth, user's nonce and user's balance
        let caller_balance = rws.next().account_balance_pair().1;
        let caller_nonce = rws.next().account_nonce_pair().1.low_u64();
        let is_precheck_ok =
            call.depth < 1025 && caller_balance >= value && caller_nonce < u64::MAX;

        self.caller_balance
            .assign(region, offset, Some(caller_balance.to_le_bytes()))?;

        let (was_warm, callee_prev_code_hash, callee_nonce) = if is_precheck_ok {
            rws.next(); // caller nonce += 1
            let was_warm = rws.next().tx_access_list_value_pair().1;
            let callee_prev_code_hash = rws.next().account_codehash_pair().0;
            let callee_nonce = if !callee_prev_code_hash.is_zero() {
                rws.next().account_nonce_pair().1.low_u64()
            } else {
                0
            };
            (was_warm, callee_prev_code_hash, callee_nonce)
        } else {
            // not used
            (false, U256::from(0), 0)
        };

        // 3 RWs while is_precheck_ok is true

        rws.offset_add(5); // skip caller call context

        // retrieve code_hash for creating address
        let callee_nonce_is_zero = callee_nonce == 0;
        let codehash_non_empty = !callee_prev_code_hash.is_zero()
            && callee_prev_code_hash != CodeDB::empty_code_hash().to_word();
        let is_address_collision = !callee_nonce_is_zero || codehash_non_empty;

        let code_hash_previous_rlc = region.code_hash(callee_prev_code_hash);
        self.prev_code_hash
            .assign(region, offset, code_hash_previous_rlc)?;
        self.prev_code_hash_is_zero
            .assign_value(region, offset, code_hash_previous_rlc)?;
        self.not_address_collision.assign_value(
            region,
            offset,
            Value::known(F::from(callee_nonce))
                + code_hash_previous_rlc * (code_hash_previous_rlc - region.empty_code_hash_rlc()),
        )?;

        let shift = init_code_start.low_u64() % 32;
        let copy_rw_increase: u64 = step.copy_rw_counter_delta;
        let values: Vec<u8> = if is_precheck_ok {
            get_copy_bytes(
                &mut rws,
                copy_rw_increase as usize,
                shift,
                init_code_length.as_u64(),
            )
        } else {
            Vec::new()
        };

        let [callee_rw_counter_end_of_reversion, callee_is_persistent] =
            [(); 2].map(|_| rws.next().call_context_value());

        // gas cost of memory expansion

        let init_code_address =
            self.init_code
                .assign(region, offset, init_code_start, init_code_length)?;
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
        self.init_code_size_not_overflow.assign(
            region,
            offset,
            F::from(init_code_length.as_u64()),
            F::from(MAX_INIT_CODE_SIZE + 1),
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

        self.callee_reversion_info.assign(
            region,
            offset,
            callee_rw_counter_end_of_reversion.low_u64() as usize,
            callee_is_persistent.low_u64() != 0,
        )?;

        // assign witness while pre-check is okay
        if is_precheck_ok {
            self.was_warm
                .assign(region, offset, Value::known(was_warm.to_scalar().unwrap()))?;
            if !is_address_collision {
                debug_assert_eq!(callee_nonce, 0);
            }
            self.callee_nonce
                .assign(region, offset, Value::known(F::from(callee_nonce)))?;
        }
        let (code_hash, keccak_code_hash) = if is_precheck_ok {
            if !is_address_collision {
                let _transfer_assign_result = self
                    .transfer
                    .assign_from_rws(region, offset, false, true, value, &mut rws)?;

                #[cfg(feature = "scroll")]
                self.prev_keccak_code_hash.assign(
                    region,
                    offset,
                    region.word_rlc(_transfer_assign_result.account_keccak_code_hash.unwrap()),
                )?;
            }

            let code_hash = CodeDB::hash(&values);
            let keccak_code_hash = H256::from(keccak256(&values));
            trace!(
                "initcode keccak {:?} keccak_rlc {:?}",
                keccak_code_hash,
                region.keccak_rlc(&values.iter().rev().cloned().collect::<Vec<u8>>())
            );

            let keccak_input: Vec<u8> = if is_create2 {
                once(0xffu8)
                    .chain(call.callee_address.to_fixed_bytes())
                    .chain(salt.to_be_bytes())
                    .chain(keccak_code_hash.to_fixed_bytes())
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

            self.init_code_rlc.assign(
                region,
                offset,
                region.keccak_rlc(&values.iter().rev().cloned().collect::<Vec<u8>>()),
            )?;
            (code_hash, keccak_code_hash)
        } else {
            (CodeDB::empty_code_hash(), *KECCAK_CODE_HASH_EMPTY)
        };

        self.create.assign(
            region,
            offset,
            call.callee_address,
            caller_nonce,
            Some(keccak_code_hash.to_word()),
            Some(code_hash.to_word()),
            Some(salt),
        )?;

        self.is_success.assign(
            region,
            offset,
            Value::known(if !is_precheck_ok || is_address_collision {
                F::zero()
            } else if init_code_length.as_usize() == 0 {
                F::one()
            } else {
                rws.next(); // callee nonce += 1
                rws.next(); // caller id
                let rw = rws.next();
                debug_assert_eq!(rw.tag(), RwTableTag::CallContext);
                debug_assert_eq!(
                    rw.field_tag().unwrap(),
                    CallContextFieldTag::IsSuccess as u64
                );
                rw.call_context_value().to_scalar().unwrap()
            }),
        )?;

        self.keccak_code_hash.assign(
            region,
            offset,
            region.word_rlc(keccak_code_hash.to_word()),
        )?;

        self.copy_rw_increase.assign(
            region,
            offset,
            Value::known(
                (copy_rw_increase)
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        self.is_insufficient_balance
            .assign(region, offset, caller_balance, value)?;
        self.is_depth_in_range
            .assign(region, offset, F::from(call.depth as u64), F::from(1025))?;
        self.is_nonce_in_range
            .assign(region, offset, F::from(caller_nonce), F::from(u64::MAX))?;

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
    use mock::{eth, TestContext, MOCK_ACCOUNTS};
    use std::sync::LazyLock;

    const CALLEE_ADDRESS: Address = Address::repeat_byte(0xff);
    static CALLER_ADDRESS: LazyLock<Address> =
        LazyLock::new(|| address!("0x00bbccddee000000000000000000000000002400"));

    fn run_test_circuits<const NACC: usize, const NTX: usize>(ctx: TestContext<NACC, NTX>) {
        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_rws: 0, // dynamic
                max_copy_rows: 140_000,
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
            CALLDATASIZE
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

    fn creator_bytecode(
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
            PUSH1(initialization_bytes.len()) // length
            PUSH1(32 - initialization_bytes.len()) // offset
            PUSH2(value) // value
        });
        code.write_op(if is_create2 {
            OpcodeId::CREATE2
        } else {
            OpcodeId::CREATE
        });

        // Add some basic check to make sure rw consistency
        code.append(&bytecode! {
            MSIZE
            GAS
            RETURNDATASIZE
            // callee address is_warm?
            PUSH32(word!("0x40e487463307cf170d059cb3f4b3d3603ef74e1e"))
            BALANCE
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
            let root_code = creator_bytecode(init_code, 23414.into(), *is_create2, *is_persistent);

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
                code: creator_bytecode(initialization_bytecode(true), 23414.into(), false, true)
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
                code: creator_bytecode(vec![].into(), 23414.into(), is_create2, true).into(),
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

    #[ignore]
    #[test]
    fn test_create_2tx_at_same_address() {
        let ctx = TestContext::<4, 2>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(mock::eth(10));
                accs[1]
                    .address(MOCK_ACCOUNTS[1])
                    .code(bytecode! {
                        PUSH0
                        PUSH32(100)
                        PUSH0
                        PUSH0
                        CREATE2
                        PUSH0
                        PUSH0
                        REVERT
                    })
                    .balance(mock::eth(10));
                accs[2]
                    .address(MOCK_ACCOUNTS[2])
                    .code(bytecode! {
                        PUSH0
                        PUSH32(100)
                        PUSH0
                        PUSH0
                        CREATE2
                        PUSH0
                        PUSH0
                        RETURN
                    })
                    .balance(mock::eth(10));
            },
            |mut txs, accs| {
                txs[0].from(accs[0].address).to(accs[1].address);
                txs[1].from(accs[0].address).to(accs[2].address);
            },
            |block, _| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn test_create_address_collision_and_mem_expansion() {
        for offset in [100, 200] {
            /*
            create2(value=0, offset=0, length=100, salt=0);
            create2(value=0, offset=100-or-200, length=100, salt=0);
            */
            let code_bytes = bytecode! {
                PUSH0
                PUSH32(100)
                PUSH0
                PUSH0
                CREATE2
                PUSH0
                PUSH32(100)
                PUSH32(offset)
                PUSH0
                CREATE2
            };

            let ctx = TestContext::<2, 1>::new(
                None,
                |accs| {
                    accs[0].address(MOCK_ACCOUNTS[0]).balance(mock::eth(10));
                    accs[1]
                        .address(MOCK_ACCOUNTS[1])
                        .code(code_bytes)
                        .balance(mock::eth(10));
                },
                |mut txs, accs| {
                    txs[0].from(accs[0].address).to(accs[1].address);
                },
                |block, _| block,
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        }
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
                code: creator_bytecode(initialization_bytecode(false), value, is_create2, true)
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

    #[test]
    fn test_create2_deploy_to_non_zero_balance_address() {
        let initialization_code = initialization_bytecode(true);
        let root_code = creator_bytecode(initialization_code, 0.into(), true, true);
        let caller = Account {
            address: *CALLER_ADDRESS,
            code: root_code.into(),
            nonce: Word::one(),
            balance: eth(10),
            ..Default::default()
        };
        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(eth(10));
                accs[1].account(&caller);
                accs[2]
                    .address(address!("0x4e74035cefd0998ea16ab5145f7713620a9eb0c5"))
                    .balance(eth(10));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(accs[1].address)
                    .gas(word!("0x2386F26FC10000"));
            },
            |block, _| block,
        )
        .unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_rws: 200,
                max_copy_rows: 200,
                ..Default::default()
            })
            .run();
    }
}
