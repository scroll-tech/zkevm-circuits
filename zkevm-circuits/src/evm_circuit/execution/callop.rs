use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS};
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::{CommonCallGadget, TransferGadget};
use crate::evm_circuit::util::constraint_builder::Transition::{Delta, To};
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, ReversionInfo, StepStateTransition,
};
use crate::evm_circuit::util::math_gadget::{
    ConstantDivisionGadget, IsZeroGadget, LtGadget, LtWordGadget, MinMaxGadget,
};
use crate::evm_circuit::util::{and, not, or, select, CachedRegion, Cell, Word};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::table::{AccountFieldTag, CallContextFieldTag};
use crate::util::Expr;
use bus_mapping::evm::OpcodeId;
use bus_mapping::precompile::is_precompiled;
use eth_types::evm_types::GAS_STIPEND_CALL_WITH_VALUE;
use eth_types::{Field, ToAddress, ToLittleEndian, ToScalar, U256};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

/// Gadget for call related opcodes. It supports `OpcodeId::CALL`,
/// `OpcodeId::CALLCODE`, `OpcodeId::DELEGATECALL` and `OpcodeId::STATICCALL`.
/// both for successful and failure(insufficient balance error) cases.
#[derive(Clone, Debug)]

pub(crate) struct CallOpGadget<F> {
    opcode: Cell<F>,
    is_call: IsZeroGadget<F>,
    is_callcode: IsZeroGadget<F>,
    is_delegatecall: IsZeroGadget<F>,
    is_staticcall: IsZeroGadget<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    current_callee_address: Cell<F>,
    current_caller_address: Cell<F>,
    is_static: Cell<F>,
    depth: Cell<F>,
    call: CommonCallGadget<F, true>,
    current_value: Word<F>,
    is_warm: Cell<F>,
    is_warm_prev: Cell<F>,
    callee_reversion_info: ReversionInfo<F>,
    transfer: TransferGadget<F>,
    // current handling Call* opcode's caller balance
    caller_balance_word: Word<F>,
    // check if insufficient balance case
    is_insufficient_balance: LtWordGadget<F>,
    one_64th_gas: ConstantDivisionGadget<F, N_BYTES_GAS>,
    capped_callee_gas_left: MinMaxGadget<F, N_BYTES_GAS>,
    is_code_address_zero: IsZeroGadget<F>,
    is_precompile_lt: LtGadget<F, N_BYTES_ACCOUNT_ADDRESS>,
    // FIXME: free cells, only used in empty codehash (empty account and precompiles)
    step_gas_cost: Cell<F>,
    // used only in precompiled contracts
    return_data_len: Cell<F>,
    return_data_copy_size: MinMaxGadget<F, N_BYTES_GAS>,
}

impl<F: Field> ExecutionGadget<F> for CallOpGadget<F> {
    const NAME: &'static str = "CALL_OP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALL_OP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());
        let is_call = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALL.expr());
        let is_callcode = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALLCODE.expr());
        let is_delegatecall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::DELEGATECALL.expr());
        let is_staticcall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::STATICCALL.expr());

        // Use rw_counter of the step which triggers next call as its call_id.
        let callee_call_id = cb.curr.state.rw_counter.clone();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let [is_static, depth, current_callee_address] = [
            CallContextFieldTag::IsStatic,
            CallContextFieldTag::Depth,
            CallContextFieldTag::CalleeAddress,
        ]
        .map(|field_tag| cb.call_context(None, field_tag));

        let (current_caller_address, current_value) = cb.condition(is_delegatecall.expr(), |cb| {
            (
                cb.call_context(None, CallContextFieldTag::CallerAddress),
                cb.call_context_as_word(None, CallContextFieldTag::Value),
            )
        });

        cb.range_lookup(depth.expr(), 1024);

        let call_gadget = CommonCallGadget::construct(
            cb,
            is_call.expr(),
            is_callcode.expr(),
            is_delegatecall.expr(),
            is_staticcall.expr(),
        );
        cb.condition(not::expr(is_call.expr() + is_callcode.expr()), |cb| {
            cb.require_zero(
                "for non call/call code, value is zero",
                call_gadget.value.expr(),
            );
        });

        let caller_address = select::expr(
            is_delegatecall.expr(),
            current_caller_address.expr(),
            current_callee_address.expr(),
        );
        let callee_address = select::expr(
            is_callcode.expr() + is_delegatecall.expr(),
            current_callee_address.expr(),
            call_gadget.callee_address_expr(),
        );

        // Add callee to access list
        let is_warm = cb.query_bool();
        let is_warm_prev = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            call_gadget.callee_address_expr(),
            is_warm.expr(),
            is_warm_prev.expr(),
            Some(&mut reversion_info),
        );

        // Propagate rw_counter_end_of_reversion and is_persistent
        let mut callee_reversion_info = cb.reversion_info_write(Some(callee_call_id.expr()));
        cb.require_equal(
            "callee_is_persistent == is_persistent ⋅ is_success",
            callee_reversion_info.is_persistent(),
            reversion_info.is_persistent() * call_gadget.is_success.expr(),
        );
        cb.condition(call_gadget.is_success.expr() * (1.expr() - reversion_info.is_persistent()), |cb| {
            cb.require_equal(
                "callee_rw_counter_end_of_reversion == rw_counter_end_of_reversion - (reversible_write_counter + 1)",
                callee_reversion_info.rw_counter_end_of_reversion(),
                reversion_info.rw_counter_of_reversion(1.expr()),
            );
        });

        cb.condition(is_call.expr() * call_gadget.has_value.clone(), |cb| {
            cb.require_zero(
                "CALL with value must not be in static call stack",
                is_static.expr(),
            );
        });

        let caller_balance_word = cb.query_word_rlc();
        cb.account_read(
            caller_address.expr(),
            AccountFieldTag::Balance,
            caller_balance_word.expr(),
        );
        let is_insufficient_balance =
            LtWordGadget::construct(cb, &caller_balance_word, &call_gadget.value);

        // stack write is zero when is_insufficient_balance is true
        cb.condition(is_insufficient_balance.expr(), |cb| {
            cb.require_zero(
                "stack write result is zero when is_insufficient_balance is true",
                call_gadget.is_success.expr(),
            );
        });

        let is_code_address_zero = IsZeroGadget::construct(cb, call_gadget.callee_address_expr());
        let is_precompile_lt =
            LtGadget::construct(cb, call_gadget.callee_address_expr(), 0xA.expr());
        let is_precompile = and::expr(&[
            not::expr(is_code_address_zero.expr()),
            is_precompile_lt.expr(),
        ]);

        // Verify transfer only for CALL opcode in the successful case.  If value == 0,
        // skip the transfer (this is necessary for non-existing accounts, which
        // will not be crated when value is 0 and so the callee balance lookup
        // would be invalid).
        let transfer = cb.condition(
            is_call.expr() * not::expr(is_insufficient_balance.expr()),
            |cb| {
                TransferGadget::construct(
                    cb,
                    caller_address.expr(),
                    callee_address.expr(),
                    or::expr([
                        not::expr(call_gadget.callee_not_exists.expr()),
                        is_precompile.expr(),
                    ]),
                    0.expr(),
                    call_gadget.value.clone(),
                    &mut callee_reversion_info,
                )
            },
        );

        // For CALLCODE opcode, verify caller balance is greater than or equal to stack
        // `value` in successful case. that is `is_insufficient_balance` is false.
        // for call opcode, this has been checked in transfer gadget implicitly.
        cb.condition(is_callcode.expr() * call_gadget.is_success.expr(), |cb| {
            cb.require_zero(
                "transfer_value <= caller_balance for CALLCODE opcode in successful case ",
                is_insufficient_balance.expr(),
            );
        });

        // no_callee_code is true when the account exists and has empty
        // code hash, or when the account doesn't exist (which we encode with
        // code_hash = 0).
        let no_callee_code =
            call_gadget.is_empty_code_hash.expr() + call_gadget.callee_not_exists.expr();

        // Sum up and verify gas cost.
        // Only CALL opcode could invoke transfer to make empty account into non-empty.
        let gas_cost = call_gadget.gas_cost_expr(is_warm_prev.expr(), is_call.expr());
        // Apply EIP 150
        let gas_available = cb.curr.state.gas_left.expr() - gas_cost.clone();
        let one_64th_gas = ConstantDivisionGadget::construct(cb, gas_available.clone(), 64);
        let all_but_one_64th_gas = gas_available - one_64th_gas.quotient();
        let capped_callee_gas_left =
            MinMaxGadget::construct(cb, call_gadget.gas_expr(), all_but_one_64th_gas.clone());
        let callee_gas_left = select::expr(
            call_gadget.gas_is_u64.expr(),
            capped_callee_gas_left.min(),
            all_but_one_64th_gas,
        );

        let return_data_len = cb.query_cell();
        let return_data_copy_size = MinMaxGadget::<F, N_BYTES_GAS>::construct(
            cb,
            return_data_len.expr(),
            call_gadget.rd_address.length(),
        );
        let precompile_memory_writes =
            is_precompile.expr() * (return_data_len.expr() + return_data_copy_size.min());

        let stack_pointer_delta =
            select::expr(is_call.expr() + is_callcode.expr(), 6.expr(), 5.expr());
        let step_gas_cost = cb.query_cell();
        let memory_expansion = call_gadget.memory_expansion.clone();

        cb.condition(
            and::expr([
                no_callee_code.expr(),
                not::expr(is_precompile.expr()),
                not::expr(is_insufficient_balance.expr()),
            ]),
            |cb| {
                // Save caller's call state
                for field_tag in [
                    CallContextFieldTag::LastCalleeId,
                    CallContextFieldTag::LastCalleeReturnDataOffset,
                    CallContextFieldTag::LastCalleeReturnDataLength,
                ] {
                    cb.call_context_lookup(true.expr(), None, field_tag, 0.expr());
                }
            },
        );
        cb.condition(
            and::expr([
                is_precompile.expr(),
                not::expr(is_insufficient_balance.expr()),
            ]),
            |cb| {
                // Save caller's call state
                for (field_tag, value) in [
                    (CallContextFieldTag::LastCalleeId, callee_call_id.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
                    (
                        CallContextFieldTag::LastCalleeReturnDataLength,
                        return_data_len.expr(),
                    ),
                ] {
                    cb.call_context_lookup(true.expr(), None, field_tag, value);
                }
            },
        );

        cb.condition(
            and::expr([
                call_gadget.is_empty_code_hash.expr(),
                not::expr(is_insufficient_balance.expr()),
            ]),
            |cb| {
                //
                // For CALLCODE opcode, it has an extra stack pop `value` and one account read
                // for caller balance (+2).
                //
                // For DELEGATECALL opcode, it has two extra call context lookups for current
                // caller address and value (+2).
                //
                // No extra lookups for STATICCALL opcode.
                let transfer_rwc_delta =
                    is_call.expr() * not::expr(transfer.value_is_zero.expr()) * 2.expr();
                let rw_counter_delta = 21.expr()
                    + is_call.expr() * 1.expr()
                    + transfer_rwc_delta.clone()
                    + is_callcode.expr()
                    + is_delegatecall.expr() * 2.expr()
                    + precompile_memory_writes;
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(rw_counter_delta),
                    program_counter: Delta(1.expr()),
                    stack_pointer: Delta(stack_pointer_delta.expr()),
                    gas_left: Delta(-step_gas_cost.expr()),

                    memory_word_size: To(memory_expansion.next_memory_word_size()),
                    // For CALL opcode, `transfer` invocation has two account write if value is not
                    // zero.
                    reversible_write_counter: Delta(1.expr() + transfer_rwc_delta),
                    ..StepStateTransition::default()
                });
            },
        );

        // handle is_insufficient_balance step transition
        cb.condition(is_insufficient_balance.expr(), |cb| {
            // Save caller's call state
            for field_tag in [
                CallContextFieldTag::LastCalleeId,
                CallContextFieldTag::LastCalleeReturnDataOffset,
                CallContextFieldTag::LastCalleeReturnDataLength,
            ] {
                cb.call_context_lookup(true.expr(), None, field_tag, 0.expr());
            }

            cb.require_step_state_transition(StepStateTransition {
                rw_counter: Delta(22.expr()),
                program_counter: Delta(1.expr()),
                stack_pointer: Delta(stack_pointer_delta.expr()),
                gas_left: Delta(
                    call_gadget.has_value.clone() * GAS_STIPEND_CALL_WITH_VALUE.expr()
                        - gas_cost.clone(),
                ),
                memory_word_size: To(memory_expansion.next_memory_word_size()),
                reversible_write_counter: Delta(1.expr()),
                ..StepStateTransition::default()
            });
        });

        cb.condition(
            and::expr(&[
                not::expr(no_callee_code.expr()),
                not::expr(is_insufficient_balance.expr()),
            ]),
            |cb| {
                // Save caller's call state
                for (field_tag, value) in [
                    (
                        CallContextFieldTag::ProgramCounter,
                        cb.curr.state.program_counter.expr() + 1.expr(),
                    ),
                    (
                        CallContextFieldTag::StackPointer,
                        cb.curr.state.stack_pointer.expr() + stack_pointer_delta,
                    ),
                    (
                        CallContextFieldTag::GasLeft,
                        cb.curr.state.gas_left.expr() - gas_cost - callee_gas_left.clone(),
                    ),
                    (
                        CallContextFieldTag::MemorySize,
                        memory_expansion.next_memory_word_size(),
                    ),
                    (
                        CallContextFieldTag::ReversibleWriteCounter,
                        cb.curr.state.reversible_write_counter.expr() + 1.expr(),
                    ),
                ] {
                    cb.call_context_lookup(true.expr(), None, field_tag, value);
                }

                // Setup next call's context.
                let cd_address = call_gadget.cd_address.clone();
                let rd_address = call_gadget.rd_address.clone();
                for (field_tag, value) in [
                    (CallContextFieldTag::CallerId, cb.curr.state.call_id.expr()),
                    (CallContextFieldTag::TxId, tx_id.expr()),
                    (CallContextFieldTag::Depth, depth.expr() + 1.expr()),
                    (CallContextFieldTag::CallerAddress, caller_address),
                    (CallContextFieldTag::CalleeAddress, callee_address),
                    (CallContextFieldTag::CallDataOffset, cd_address.offset()),
                    (CallContextFieldTag::CallDataLength, cd_address.length()),
                    (CallContextFieldTag::ReturnDataOffset, rd_address.offset()),
                    (CallContextFieldTag::ReturnDataLength, rd_address.length()),
                    (
                        CallContextFieldTag::Value,
                        select::expr(
                            is_delegatecall.expr(),
                            current_value.expr(),
                            call_gadget.value.expr(),
                        ),
                    ),
                    (
                        CallContextFieldTag::IsSuccess,
                        call_gadget.is_success.expr(),
                    ),
                    (
                        CallContextFieldTag::IsStatic,
                        or::expr([is_static.expr(), is_staticcall.expr()]),
                    ),
                    (CallContextFieldTag::LastCalleeId, 0.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
                    (CallContextFieldTag::IsRoot, 0.expr()),
                    (CallContextFieldTag::IsCreate, 0.expr()),
                    (
                        CallContextFieldTag::CodeHash,
                        call_gadget.phase2_callee_code_hash.expr(),
                    ),
                ] {
                    cb.call_context_lookup(
                        true.expr(),
                        Some(callee_call_id.expr()),
                        field_tag,
                        value,
                    );
                }

                // Give gas stipend if value is not zero
                let callee_gas_left = callee_gas_left
                    + call_gadget.has_value.clone() * GAS_STIPEND_CALL_WITH_VALUE.expr();

                // For CALL opcode, it has an extra stack pop `value` (+1) and if the value is
                // not zero, two account write for `transfer` call (+2).
                //
                // For CALLCODE opcode, it has an extra stack pop `value` and one account read
                // for caller balance (+2).
                //
                // For DELEGATECALL opcode, it has two extra call context lookups for current
                // caller address and value (+2).
                //
                // No extra lookups for STATICCALL opcode.
                let transfer_rwc_delta =
                    is_call.expr() * not::expr(transfer.value_is_zero.expr()) * 2.expr();
                let rw_counter_delta = 41.expr()
                    + is_call.expr() * 1.expr()
                    + transfer_rwc_delta.clone()
                    + is_callcode.expr()
                    + is_delegatecall.expr() * 2.expr();
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(rw_counter_delta),
                    call_id: To(callee_call_id.expr()),
                    is_root: To(false.expr()),
                    is_create: To(false.expr()),
                    code_hash: To(call_gadget.phase2_callee_code_hash.expr()),
                    gas_left: To(callee_gas_left),
                    // For CALL opcode, `transfer` invocation has two account write if value is not
                    // zero.
                    reversible_write_counter: To(transfer_rwc_delta),
                    ..StepStateTransition::new_context()
                });
            },
        );

        Self {
            opcode,
            is_call,
            is_callcode,
            is_delegatecall,
            is_staticcall,
            tx_id,
            reversion_info,
            current_callee_address,
            current_caller_address,
            current_value,
            is_static,
            depth,
            call: call_gadget,
            is_warm,
            is_warm_prev,
            callee_reversion_info,
            transfer,
            caller_balance_word,
            is_insufficient_balance,
            one_64th_gas,
            capped_callee_gas_left,
            is_code_address_zero,
            is_precompile_lt,
            return_data_len,
            return_data_copy_size,
            step_gas_cost,
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
        for (_i, _rw) in step.rw_indices.iter().enumerate() {
            //log::trace!("rw {}th, {:?}", i, block.rws[*rw]);
        }
        let opcode = step.opcode.unwrap();
        let is_call = opcode == OpcodeId::CALL;
        let is_callcode = opcode == OpcodeId::CALLCODE;
        let is_delegatecall = opcode == OpcodeId::DELEGATECALL;
        let [tx_id, is_static, depth, current_callee_address] = [
            step.rw_indices[0],
            step.rw_indices[3],
            step.rw_indices[4],
            step.rw_indices[5],
        ]
        .map(|idx| block.rws[idx].call_context_value());
        let stack_index = 6;

        // This offset is used to change the index offset of `step.rw_indices`.
        // Since both CALL and CALLCODE have an extra stack pop `value`, and
        // opcode DELEGATECALL has two extra call context lookups - current
        // caller address and current value.
        let mut rw_offset = 0;
        let [current_caller_address, current_value] = if is_delegatecall {
            rw_offset += 2;
            [step.rw_indices[6], step.rw_indices[7]].map(|idx| block.rws[idx].call_context_value())
        } else {
            [U256::zero(), U256::zero()]
        };
        let [gas, callee_address] = [
            step.rw_indices[stack_index + rw_offset],
            step.rw_indices[stack_index + 1 + rw_offset],
        ]
        .map(|idx| block.rws[idx].stack_value());
        let is_precompile = is_precompiled(&callee_address.to_address());
        let value = if is_call || is_callcode {
            rw_offset += 1;
            block.rws[step.rw_indices[7 + rw_offset]].stack_value()
        } else {
            U256::zero()
        };
        let [cd_offset, cd_length, rd_offset, rd_length, is_success] = [
            step.rw_indices[stack_index + 2 + rw_offset],
            step.rw_indices[stack_index + 3 + rw_offset],
            step.rw_indices[stack_index + 4 + rw_offset],
            step.rw_indices[stack_index + 5 + rw_offset],
            step.rw_indices[stack_index + 6 + rw_offset],
        ]
        .map(|idx| block.rws[idx].stack_value());
        //log::trace!("rw_offset {:?}", rw_offset);
        let callee_code_hash = block.rws[step.rw_indices[13 + rw_offset]]
            .account_codehash_pair()
            .0;
        let callee_exists = !callee_code_hash.is_zero() || is_precompile;

        let (is_warm, is_warm_prev) =
            block.rws[step.rw_indices[14 + rw_offset]].tx_access_list_value_pair();

        let [callee_rw_counter_end_of_reversion, callee_is_persistent] = [
            step.rw_indices[15 + rw_offset],
            step.rw_indices[16 + rw_offset],
        ]
        .map(|idx| block.rws[idx].call_context_value());

        // check if it is insufficient balance case.
        // get caller balance
        let (caller_balance, _) = block.rws[step.rw_indices[17 + rw_offset]].account_balance_pair();
        self.caller_balance_word
            .assign(region, offset, Some(caller_balance.to_le_bytes()))?;
        self.is_insufficient_balance
            .assign(region, offset, caller_balance, value)?;

        let is_insufficient = (value > caller_balance) && (is_call || is_callcode);

        // only call opcode do transfer in sucessful case.
        let (caller_balance_pair, callee_balance_pair) =
            if is_call && !is_insufficient && !value.is_zero() {
                if !callee_exists {
                    rw_offset += 1;
                }
                let caller_balance_pair =
                    block.rws[step.rw_indices[18 + rw_offset]].account_balance_pair();
                let callee_balance_pair =
                    block.rws[step.rw_indices[19 + rw_offset]].account_balance_pair();
                rw_offset += 2;
                (caller_balance_pair, callee_balance_pair)
            } else {
                ((U256::zero(), U256::zero()), (U256::zero(), U256::zero()))
            };

        let return_data_len = if is_precompile {
            let return_data_len_rw = block.rws[step.rw_indices[20 + rw_offset]];
            assert_eq!(
                return_data_len_rw.field_tag().unwrap(),
                CallContextFieldTag::LastCalleeReturnDataLength as u64
            );
            return_data_len_rw.call_context_value()
        } else {
            0.into()
        };
        self.return_data_len.assign(
            region,
            offset,
            Value::known(F::from(return_data_len.as_u64())),
        )?;
        self.return_data_copy_size.assign(
            region,
            offset,
            F::from(return_data_len.as_u64()),
            F::from(rd_length.as_u64()),
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
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.current_callee_address.assign(
            region,
            offset,
            Value::known(
                current_callee_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.current_caller_address.assign(
            region,
            offset,
            Value::known(
                current_caller_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.current_value
            .assign(region, offset, Some(current_value.to_le_bytes()))?;
        self.is_static
            .assign(region, offset, Value::known(F::from(is_static.low_u64())))?;
        self.depth
            .assign(region, offset, Value::known(F::from(depth.low_u64())))?;

        let memory_expansion_gas_cost = self.call.assign(
            region,
            offset,
            gas,
            callee_address,
            value,
            is_success,
            cd_offset,
            cd_length,
            rd_offset,
            rd_length,
            step.memory_word_size(),
            region.word_rlc(callee_code_hash),
        )?;
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;
        self.is_warm_prev
            .assign(region, offset, Value::known(F::from(is_warm_prev as u64)))?;
        self.callee_reversion_info.assign(
            region,
            offset,
            callee_rw_counter_end_of_reversion.low_u64() as usize,
            callee_is_persistent.low_u64() != 0,
        )?;
        // conditionally assign
        if !is_insufficient && !value.is_zero() {
            self.transfer.assign(
                region,
                offset,
                caller_balance_pair,
                callee_balance_pair,
                value,
            )?;
        }

        let mut code_address_bytes = [0; 32];
        code_address_bytes[0..N_BYTES_ACCOUNT_ADDRESS]
            .copy_from_slice(&callee_address.to_le_bytes()[0..N_BYTES_ACCOUNT_ADDRESS]);
        let code_address_bytes = F::from_repr(code_address_bytes).unwrap();
        self.is_code_address_zero
            .assign(region, offset, code_address_bytes)?;
        self.is_precompile_lt
            .assign(region, offset, code_address_bytes, F::from(0xA))?;
        let has_value = !value.is_zero() && !is_delegatecall;
        let gas_cost = self.call.cal_gas_cost_for_assignment(
            memory_expansion_gas_cost,
            is_warm_prev,
            is_call,
            has_value,
            !callee_exists,
        )?;
        let gas_available = step.gas_left - gas_cost;
        self.step_gas_cost
            .assign(region, offset, Value::known(F::from(step.gas_cost)))?;
        self.one_64th_gas
            .assign(region, offset, gas_available.into())?;
        self.capped_callee_gas_left.assign(
            region,
            offset,
            F::from(gas.low_u64()),
            F::from(gas_available - gas_available / 64),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::evm_types::OpcodeId;
    use eth_types::geth_types::Account;
    use eth_types::{address, bytecode, word, Address, ToWord, Word};

    use itertools::Itertools;
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;

    use rayon::prelude::{ParallelBridge, ParallelIterator};
    use std::default::Default;

    const TEST_CALL_OPCODES: &[OpcodeId] = &[
        OpcodeId::CALL,
        OpcodeId::CALLCODE,
        OpcodeId::DELEGATECALL,
        OpcodeId::STATICCALL,
    ];

    #[test]
    fn callop_insufficient_balance() {
        let stacks = [Stack {
            // this value is bigger than caller's balance
            value: Word::from(11).pow(18.into()),
            ..Default::default()
        }];

        let callees = [callee(bytecode! {}), callee(bytecode! { STOP })];
        // only call, callcode will encounter insufficient balance error.
        let test_opcodes: &[OpcodeId] = &[OpcodeId::CALL, OpcodeId::CALLCODE];

        for ((opcode, stack), callee) in test_opcodes
            .iter()
            .cartesian_product(stacks.into_iter())
            .cartesian_product(callees.into_iter())
        {
            test_ok(caller_for_insufficient_balance(opcode, stack), callee);
        }
    }

    #[test]
    fn test_precompiled_call() {
        let head = bytecode! {
            PUSH16(word!("0123456789ABCDEF0123456789ABCDEF"))
            PUSH1(0x00)
            MSTORE
        };

        let call6 = bytecode! {
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
        };

        let call7 = bytecode! {
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x20)
            PUSH1(0x00)
            PUSH1(0x00)
            PUSH1(0x04)
            PUSH1(0xFF)
        };

        let tail = bytecode! {
            PUSH1(0x20)
            MLOAD
        };

        let tests = [bytecode! { STATICCALL }, bytecode! { DELEGATECALL }]
            .map(|c| {
                let mut call6 = call6.clone();
                call6.append(&c);
                call6
            })
            .into_iter()
            .chain([bytecode! { CALL }, bytecode! { CALLCODE }].map(|c| {
                let mut call7 = call7.clone();
                call7.append(&c);
                call7
            }))
            .map(|c| {
                let mut code = head.clone();
                code.append(&c);
                code.append(&tail);
                code
            });

        for test in tests {
            // Get the execution steps from the external tracer
            let ctx = TestContext::<2, 1>::new(
                None,
                account_0_code_account_1_no_code(test),
                tx_from_1_to_0,
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx)
                .params(CircuitsParams {
                    max_rws: 4500,
                    ..Default::default()
                })
                .run();
        }
    }

    #[test]
    fn callop_nested() {
        for opcode in TEST_CALL_OPCODES {
            test_nested(opcode);
        }
    }

    #[ignore]
    #[test]
    fn callop_recursive() {
        for opcode in TEST_CALL_OPCODES {
            test_recursive(opcode);
        }
    }

    #[ignore]
    #[test]
    fn callop_simple() {
        let stacks = [
            // With nothing
            Stack::default(),
            // With value
            Stack {
                value: Word::from(10).pow(18.into()),
                ..Default::default()
            },
            // With gas
            Stack {
                gas: 100,
                ..Default::default()
            },
            Stack {
                gas: 100000,
                ..Default::default()
            },
            // With memory expansion
            Stack {
                cd_offset: 64.into(),
                cd_length: 320,
                rd_offset: Word::zero(),
                rd_length: 32,
                ..Default::default()
            },
            Stack {
                cd_offset: Word::zero(),
                cd_length: 32,
                rd_offset: 64.into(),
                rd_length: 320,
                ..Default::default()
            },
            Stack {
                cd_offset: 0xFFFFFF.into(),
                cd_length: 0,
                rd_offset: 0xFFFFFF.into(),
                rd_length: 0,
                ..Default::default()
            },
            // With memory expansion and value
            Stack {
                cd_offset: 64.into(),
                cd_length: 320,
                rd_offset: 0.into(),
                rd_length: 32,
                value: Word::from(10).pow(18.into()),
                ..Default::default()
            },
        ];
        let callees = [callee(bytecode! {}), callee(bytecode! { STOP })];

        TEST_CALL_OPCODES
            .iter()
            .cartesian_product(stacks.into_iter())
            .cartesian_product(callees.into_iter())
            .par_bridge()
            .for_each(|((opcode, stack), callee)| {
                test_ok(caller(opcode, stack, true), callee);
            });
    }

    #[test]
    fn callop_overflow_offset_and_zero_length() {
        let stack = Stack {
            cd_offset: Word::MAX,
            cd_length: 0,
            rd_offset: Word::MAX,
            rd_length: 0,
            ..Default::default()
        };

        TEST_CALL_OPCODES
            .iter()
            .for_each(|opcode| test_ok(caller(opcode, stack, true), callee(bytecode! {})));
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Stack {
        gas: u64,
        value: Word,
        cd_offset: Word,
        cd_length: u64,
        rd_offset: Word,
        rd_length: u64,
    }

    fn callee(code: bytecode::Bytecode) -> Account {
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

    fn caller(opcode: &OpcodeId, stack: Stack, caller_is_success: bool) -> Account {
        let is_call_or_callcode = opcode == &OpcodeId::CALL || opcode == &OpcodeId::CALLCODE;
        let terminator = if caller_is_success {
            OpcodeId::RETURN
        } else {
            OpcodeId::REVERT
        };

        // Call twice for testing both cold and warm access
        let mut bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(stack.rd_offset)
            PUSH32(Word::from(stack.cd_length))
            PUSH32(stack.cd_offset)
        };
        if is_call_or_callcode {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(*opcode)
            PUSH32(Word::from(stack.rd_length))
            PUSH32(stack.rd_offset)
            PUSH32(Word::from(stack.cd_length))
            PUSH32(stack.cd_offset)
        });
        if is_call_or_callcode {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(*opcode)
            PUSH1(0)
            PUSH1(0)
            .write_op(terminator)
        });

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(20.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
    }

    fn caller_for_insufficient_balance(opcode: &OpcodeId, stack: Stack) -> Account {
        let is_call_or_callcode = opcode == &OpcodeId::CALL || opcode == &OpcodeId::CALLCODE;
        let terminator = OpcodeId::STOP;

        let mut bytecode = bytecode! {
            PUSH32(Word::from(stack.rd_length))
            PUSH32(stack.rd_offset)
            PUSH32(Word::from(stack.cd_length))
            PUSH32(stack.cd_offset)
        };
        if is_call_or_callcode {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(*opcode)
            .write_op(terminator)
        });

        Account {
            address: Address::repeat_byte(0xfe),
            balance: Word::from(10).pow(18.into()),
            code: bytecode.to_vec().into(),
            ..Default::default()
        }
    }

    fn test_nested(opcode: &OpcodeId) {
        let callers = [
            caller(
                opcode,
                Stack {
                    gas: 100000,
                    ..Default::default()
                },
                true,
            ),
            caller(
                opcode,
                Stack {
                    gas: 100000,
                    ..Default::default()
                },
                false,
            ),
        ];
        let callees = [
            // Success
            callee(bytecode! { PUSH1(0) PUSH1(0) RETURN }),
            // Failure
            callee(bytecode! { PUSH1(0) PUSH1(0) REVERT }),
        ];

        for (caller, callee) in callers.into_iter().cartesian_product(callees.into_iter()) {
            test_ok(caller, callee);
        }
    }

    #[test]
    fn callop_base() {
        test_ok(
            caller(&OpcodeId::CALL, Stack::default(), true),
            callee(bytecode! {}),
        );
    }

    fn test_ok(caller: Account, callee: Account) {
        let ctx = TestContext::<3, 1>::new(
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
                    .gas(100000.into())
                    // Set a non-zero value could test if DELEGATECALL use value of current call.
                    .value(1000.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_rws: 500,
                ..Default::default()
            })
            .run();
    }

    fn test_recursive(opcode: &OpcodeId) {
        let is_call_or_callcode = opcode == &OpcodeId::CALL || opcode == &OpcodeId::CALLCODE;
        let mut caller_bytecode = bytecode! {
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
        };
        if is_call_or_callcode {
            caller_bytecode.push(1, U256::zero());
        }
        caller_bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH2(if is_call_or_callcode {10000} else {10032})
            .write_op(*opcode)
            STOP
        });
        // The following bytecode calls itself recursively if gas_left is greater than
        // 100, and halts with REVERT if gas_left is odd, otherwise just halts
        // with STOP.
        let mut callee_bytecode = bytecode! {
            GAS
            PUSH1(100)
            GT
            PUSH1(if is_call_or_callcode {43} else {41}) // jump dest
            JUMPI

            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
            PUSH1(0)
        };

        if is_call_or_callcode {
            callee_bytecode.push(1, U256::zero());
        }

        callee_bytecode.append(&bytecode! {
            PUSH20(Address::repeat_byte(0xff).to_word())
            PUSH1(if is_call_or_callcode {132} else {129}) // gas
            GAS
            SUB
            .write_op(*opcode)

            JUMPDEST // 41 for static_call, 43 for call
            GAS
            PUSH1(1)
            AND
            PUSH1(if is_call_or_callcode {56} else {54})
            JUMPI

            PUSH1(0)
            PUSH1(0)
            REVERT

            // 56 or 54 for call or static_call
            JUMPDEST
            STOP
        });
        test_ok(
            Account {
                address: Address::repeat_byte(0xfe),
                balance: Word::from(10).pow(20.into()),
                code: caller_bytecode.into(),
                ..Default::default()
            },
            callee(callee_bytecode),
        );
    }
}
