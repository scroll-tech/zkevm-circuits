use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE};
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::TransferGadget;
use crate::evm_circuit::util::constraint_builder::Transition::{Delta, To};
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, ReversionInfo, StepStateTransition,
};
use crate::evm_circuit::util::math_gadget::{
    ConstantDivisionGadget, IsEqualGadget, IsZeroGadget, LtGadget, LtWordGadget, MinMaxGadget,
};
use crate::evm_circuit::util::memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget};
use crate::evm_circuit::util::{
    and, from_bytes, not, or, select, sum, CachedRegion, Cell, RandomLinearCombination, Word,
};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Rw, Transaction};
use crate::table::{AccountFieldTag, CallContextFieldTag};
use crate::util::Expr;
use bus_mapping::evm::OpcodeId;
use eth_types::evm_types::{GasCost, GAS_STIPEND_CALL_WITH_VALUE};
use eth_types::{Field, ToLittleEndian, ToScalar, U256};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use keccak256::EMPTY_HASH_LE;

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
    gas: Word<F>,
    code_address: Word<F>,
    value: Word<F>,
    current_value: Word<F>,
    is_success: Cell<F>,
    gas_is_u64: IsZeroGadget<F>,
    is_warm: Cell<F>,
    is_warm_prev: Cell<F>,
    callee_reversion_info: ReversionInfo<F>,
    value_is_zero: IsZeroGadget<F>,
    cd_address: MemoryAddressGadget<F>,
    rd_address: MemoryAddressGadget<F>,
    memory_expansion: MemoryExpansionGadget<F, 2, N_BYTES_MEMORY_WORD_SIZE>,
    transfer: TransferGadget<F>,
    // current handling Call* opcode's caller balance
    caller_balance_word: Word<F>,
    // check if insufficient balance case
    is_insufficient_balance: LtWordGadget<F>,

    callee_exists: Cell<F>,
    callee_code_hash: Cell<F>,

    is_empty_code_hash: IsEqualGadget<F>,
    one_64th_gas: ConstantDivisionGadget<F, N_BYTES_GAS>,
    capped_callee_gas_left: MinMaxGadget<F, N_BYTES_GAS>,
    is_code_address_zero: IsZeroGadget<F>,
    is_precompile_lt: LtGadget<F, N_BYTES_ACCOUNT_ADDRESS>,
    // FIXME: free cells
    gas_cost: Cell<F>,
    // used only in precompiled contracts
    return_len_cell: Cell<F>,
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

        // We do the responsible opcode check explicitly here because we're not
        // using the SameContextGadget for CALL, CALLCODE, DELEGATECALL or
        // STATICCALL.
        cb.require_equal(
            "Opcode should be CALL, CALLCODE, DELEGATECALL or STATICCALL",
            is_call.expr() + is_callcode.expr() + is_delegatecall.expr() + is_staticcall.expr(),
            1.expr(),
        );

        let gas_word = cb.query_word();
        let code_address_word = cb.query_word();
        let value = cb.query_word();
        let cd_offset = cb.query_cell();
        let cd_length = cb.query_rlc();
        let rd_offset = cb.query_cell();
        let rd_length = cb.query_rlc();
        let is_success = cb.query_bool();

        let caller_balance_word = cb.query_word();
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

        // Lookup values from stack
        cb.stack_pop(gas_word.expr());
        cb.stack_pop(code_address_word.expr());

        // `CALL` opcode has an additional stack pop `value`.
        cb.condition(is_call.expr() + is_callcode.expr(), |cb| {
            cb.stack_pop(value.expr())
        });

        cb.condition(not::expr(is_call.expr() + is_callcode.expr()), |cb| {
            cb.require_zero("for non call/call code, value is zero", value.expr());
        });

        [
            cd_offset.expr(),
            cd_length.expr(),
            rd_offset.expr(),
            rd_length.expr(),
        ]
        .map(|expression| cb.stack_pop(expression));
        cb.stack_push(is_success.expr());

        // Recomposition of random linear combination to integer
        let gas = from_bytes::expr(&gas_word.cells[..N_BYTES_GAS]);
        let gas_is_u64 = IsZeroGadget::construct(cb, sum::expr(&gas_word.cells[N_BYTES_GAS..]));
        let cd_address = MemoryAddressGadget::construct(cb, cd_offset, cd_length);
        let rd_address = MemoryAddressGadget::construct(cb, rd_offset, rd_length);
        let memory_expansion =
            MemoryExpansionGadget::construct(cb, [cd_address.address(), rd_address.address()]);

        // `code_address` is poped from stack and used to check if it exists in
        // access list and get code hash.
        // For CALLCODE, both caller and callee addresses are
        // `current_callee_address`.
        // For DELEGATECALL, caller address is `current_caller_address` and
        // callee address is `current_callee_address`.
        // For both CALL and STATICCALL, caller address is
        // `current_callee_address` and callee address is `code_address`.
        let code_address = from_bytes::expr(&code_address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);
        let caller_address = select::expr(
            is_delegatecall.expr(),
            current_caller_address.expr(),
            current_callee_address.expr(),
        );
        let callee_address = select::expr(
            is_callcode.expr() + is_delegatecall.expr(),
            current_callee_address.expr(),
            code_address.expr(),
        );

        // Add callee to access list
        let is_warm = cb.query_bool();
        let is_warm_prev = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            code_address.expr(),
            is_warm.expr(),
            is_warm_prev.expr(),
            Some(&mut reversion_info),
        );

        // Propagate rw_counter_end_of_reversion and is_persistent
        let mut callee_reversion_info = cb.reversion_info_write(Some(callee_call_id.expr()));
        cb.require_equal(
            "callee_is_persistent == is_persistent ⋅ is_success",
            callee_reversion_info.is_persistent(),
            reversion_info.is_persistent() * is_success.expr(),
        );
        cb.condition(is_success.expr() * (1.expr() - reversion_info.is_persistent()), |cb| {
            cb.require_equal(
                "callee_rw_counter_end_of_reversion == rw_counter_end_of_reversion - (reversible_write_counter + 1)",
                callee_reversion_info.rw_counter_end_of_reversion(),
                reversion_info.rw_counter_of_reversion(),
            );
        });

        let value_is_zero = IsZeroGadget::construct(cb, sum::expr(&value.cells));
        let has_value = select::expr(
            is_delegatecall.expr(),
            0.expr(),
            1.expr() - value_is_zero.expr(),
        );
        cb.condition(has_value.clone(), |cb| {
            cb.require_zero(
                "CALL with value must not be in static call stack",
                is_static.expr(),
            );
        });

        cb.account_read(
            callee_address.expr(),
            AccountFieldTag::Balance,
            caller_balance_word.expr(),
        );
        let is_insufficient_balance = LtWordGadget::construct(cb, &caller_balance_word, &value);

        // stack write is zero when is_insufficient_balance is true
        cb.condition(is_insufficient_balance.expr(), |cb| {
            cb.require_zero(
                "stack write result is zero when is_insufficient_balance is true",
                is_success.expr(),
            );
        });

        // Verify transfer only for CALL opcode in the successful case.
        let transfer = cb.condition(
            is_call.expr() * not::expr(is_insufficient_balance.expr()),
            |cb| {
                TransferGadget::construct(
                    cb,
                    caller_address.expr(),
                    callee_address.expr(),
                    value.clone(),
                    &mut callee_reversion_info,
                )
            },
        );

        // For CALLCODE opcode, verify caller balance is greater than or equal to stack
        // `value` in successful case. that is `is_insufficient_balance` is false.
        // for call opcode, this has been checked in transfer gadget implicitly.
        cb.condition(is_callcode.expr() * is_success.expr(), |cb| {
            cb.require_zero(
                "transfer_value <= caller_balance for CALLCODE opcode in successful case ",
                is_insufficient_balance.expr(),
            );
        });

        let callee_exists = cb.query_bool();
        let callee_code_hash = cb.query_cell();
        cb.condition(callee_exists.expr(), |cb| {
            cb.account_read(
                code_address.expr(),
                AccountFieldTag::CodeHash,
                callee_code_hash.expr(),
            );
        });
        cb.condition(not::expr(callee_exists.expr()), |cb| {
            cb.account_read(code_address.expr(), AccountFieldTag::NonExisting, 0.expr());
        });

        let is_empty_code_hash = IsEqualGadget::construct(
            cb,
            callee_code_hash.expr(),
            Word::random_linear_combine_expr(
                (*EMPTY_HASH_LE).map(|byte| byte.expr()),
                cb.power_of_randomness(),
            ),
        );

        // Sum up and verify gas cost.
        let gas_cost = select::expr(
            is_warm_prev.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        ) + has_value.clone()
            * (GasCost::CALL_WITH_VALUE.expr()
                // Only CALL opcode could invoke transfer to make empty account into non-empty.
                + is_call.expr() * (1.expr() - callee_exists.expr()) * GasCost::NEW_ACCOUNT.expr())
            + memory_expansion.gas_cost();

        // Apply EIP 150
        let gas_available = cb.curr.state.gas_left.expr() - gas_cost.clone();
        let one_64th_gas = ConstantDivisionGadget::construct(cb, gas_available.clone(), 64);
        let all_but_one_64th_gas = gas_available - one_64th_gas.quotient();
        let capped_callee_gas_left = MinMaxGadget::construct(cb, gas, all_but_one_64th_gas.clone());
        let callee_gas_left = select::expr(
            gas_is_u64.expr(),
            capped_callee_gas_left.min(),
            all_but_one_64th_gas,
        );

        let is_code_address_zero = IsZeroGadget::construct(cb, code_address.expr());
        let is_precompile_lt = LtGadget::construct(cb, code_address.expr(), 0xA.expr());
        let is_precompile = and::expr(&[
            not::expr(is_code_address_zero.expr()),
            is_precompile_lt.expr(),
        ]);
        let return_len_cell = cb.query_cell();
        let precompile_memory_writes = 2.expr() * is_precompile.expr() * return_len_cell.expr();

        let stack_pointer_delta =
            select::expr(is_call.expr() + is_callcode.expr(), 6.expr(), 5.expr());
        let gas_cost_cell = cb.query_cell();

        cb.condition(
            and::expr([
                is_empty_code_hash.expr(),
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
                        return_len_cell.expr(),
                    ),
                ] {
                    cb.call_context_lookup(true.expr(), None, field_tag, value);
                }
            },
        );

        cb.condition(
            and::expr([
                is_empty_code_hash.expr(),
                not::expr(is_insufficient_balance.expr()),
            ]),
            |cb| {
                // For CALL opcode, it has an extra stack pop `value` and two account write for
                // `transfer` call (+3).
                //
                // For CALLCODE opcode, it has an extra stack pop `value` and one account read
                // for caller balance (+2).
                //
                // For DELEGATECALL opcode, it has two extra call context lookups for current
                // caller address and value (+2).
                //
                // No extra lookups for STATICCALL opcode.
                let rw_counter_delta = 21.expr()
                    + is_call.expr() * 3.expr()
                    + is_callcode.expr()
                    + is_delegatecall.expr() * 2.expr()
                    + precompile_memory_writes;
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(rw_counter_delta),
                    program_counter: Delta(1.expr()),
                    stack_pointer: Delta(stack_pointer_delta.expr()),
                    gas_left: Delta(-gas_cost_cell.expr()),
                    memory_word_size: To(memory_expansion.next_memory_word_size()),
                    // For CALL opcode, `transfer` invocation has two account write.
                    reversible_write_counter: Delta(1.expr() + is_call.expr() * 2.expr()),
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
                    has_value.clone() * GAS_STIPEND_CALL_WITH_VALUE.expr() - gas_cost.clone(),
                ),
                memory_word_size: To(memory_expansion.next_memory_word_size()),
                reversible_write_counter: Delta(1.expr()),
                ..StepStateTransition::default()
            });
        });

        cb.condition(
            and::expr(&[
                not::expr(is_empty_code_hash.expr()),
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
                        select::expr(is_delegatecall.expr(), current_value.expr(), value.expr()),
                    ),
                    (CallContextFieldTag::IsSuccess, is_success.expr()),
                    (
                        CallContextFieldTag::IsStatic,
                        or::expr([is_static.expr(), is_staticcall.expr()]),
                    ),
                    (CallContextFieldTag::LastCalleeId, 0.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
                    (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
                    (CallContextFieldTag::IsRoot, 0.expr()),
                    (CallContextFieldTag::IsCreate, 0.expr()),
                    (CallContextFieldTag::CodeHash, callee_code_hash.expr()),
                ] {
                    cb.call_context_lookup(
                        true.expr(),
                        Some(callee_call_id.expr()),
                        field_tag,
                        value,
                    );
                }

                // Give gas stipend if value is not zero
                let callee_gas_left =
                    callee_gas_left + has_value * GAS_STIPEND_CALL_WITH_VALUE.expr();

                // For CALL opcode, it has an extra stack pop `value` and two account write for
                // `transfer` call (+3).
                //
                // For CALLCODE opcode, it has an extra stack pop `value` and one account read
                // for caller balance (+2).
                //
                // For DELEGATECALL opcode, it has two extra call context lookups for current
                // caller address and value (+2).
                //
                // No extra lookups for STATICCALL opcode.
                let rw_counter_delta = 41.expr()
                    + is_call.expr() * 3.expr()
                    + is_callcode.expr()
                    + is_delegatecall.expr() * 2.expr();
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(rw_counter_delta),
                    call_id: To(callee_call_id.expr()),
                    is_root: To(false.expr()),
                    is_create: To(false.expr()),
                    code_hash: To(callee_code_hash.expr()),
                    gas_left: To(callee_gas_left),
                    // For CALL opcode, `transfer` invocation has two account write.
                    reversible_write_counter: To(is_call.expr() * 2.expr()),
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
            gas: gas_word,
            code_address: code_address_word,
            value,
            is_success,
            gas_is_u64,
            is_warm,
            is_warm_prev,
            callee_reversion_info,
            value_is_zero,
            cd_address,
            rd_address,
            memory_expansion,
            transfer,
            caller_balance_word,
            is_insufficient_balance,
            callee_exists,
            callee_code_hash,
            is_empty_code_hash,
            one_64th_gas,
            capped_callee_gas_left,
            is_code_address_zero,
            is_precompile_lt,
            return_len_cell,
            gas_cost: gas_cost_cell,
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
        let is_delegatecall = opcode == OpcodeId::DELEGATECALL;
        let [tx_id, is_static, depth, current_callee_address] = [
            step.rw_indices[0],
            step.rw_indices[3],
            step.rw_indices[4],
            step.rw_indices[5],
        ]
        .map(|idx| block.rws[idx].call_context_value());
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
        let [gas, code_address] = [
            step.rw_indices[6 + rw_offset],
            step.rw_indices[7 + rw_offset],
        ]
        .map(|idx| block.rws[idx].stack_value());
        let is_precompile = code_address < 10.into() && !code_address.is_zero();
        let value = if is_call || is_callcode {
            rw_offset += 1;
            block.rws[step.rw_indices[7 + rw_offset]].stack_value()
        } else {
            U256::zero()
        };
        let [cd_offset, cd_length, rd_offset, rd_length, is_success] = [
            step.rw_indices[8 + rw_offset],
            step.rw_indices[9 + rw_offset],
            step.rw_indices[10 + rw_offset],
            step.rw_indices[11 + rw_offset],
            step.rw_indices[12 + rw_offset],
        ]
        .map(|idx| block.rws[idx].stack_value());
        let (is_warm, is_warm_prev) =
            block.rws[step.rw_indices[13 + rw_offset]].tx_access_list_value_pair();
        let [callee_rw_counter_end_of_reversion, callee_is_persistent] = [
            step.rw_indices[14 + rw_offset],
            step.rw_indices[15 + rw_offset],
        ]
        .map(|idx| block.rws[idx].call_context_value());

        // check if it is insufficient balance case.
        // get caller balance
        let (caller_balance, _) = block.rws[step.rw_indices[16 + rw_offset]].account_value_pair();
        self.caller_balance_word
            .assign(region, offset, Some(caller_balance.to_le_bytes()))?;
        self.is_insufficient_balance
            .assign(region, offset, caller_balance, value)?;

        let is_insufficient = value > caller_balance;

        // only call opcode do transfer in sucessful case.
        let (caller_balance_pair, callee_balance_pair) = if is_call & !is_insufficient {
            rw_offset += 2;
            (
                block.rws[step.rw_indices[15 + rw_offset]].account_value_pair(),
                block.rws[step.rw_indices[16 + rw_offset]].account_value_pair(),
            )
        } else {
            ((U256::zero(), U256::zero()), (U256::zero(), U256::zero()))
        };

        let (callee_code_hash, callee_exists) = match block.rws[step.rw_indices[17 + rw_offset]] {
            Rw::Account {
                field_tag: AccountFieldTag::CodeHash,
                value,
                ..
            } => (value.to_le_bytes(), true),
            Rw::Account {
                field_tag: AccountFieldTag::NonExisting,
                ..
            } => (*EMPTY_HASH_LE, false),
            _ => unreachable!(),
        };
        let callee_code_hash =
            RandomLinearCombination::random_linear_combine(callee_code_hash, block.randomness);
        if is_precompile {
            let last_caller_return_data_length_rw = block.rws[step.rw_indices[20 + rw_offset]];
            assert_eq!(
                last_caller_return_data_length_rw.field_tag().unwrap(),
                CallContextFieldTag::LastCalleeReturnDataLength as u64
            );
            let return_len = last_caller_return_data_length_rw.call_context_value();
            self.return_len_cell.assign(
                region,
                offset,
                Value::known(F::from(return_len.as_u64())),
            )?;
        }
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
        self.gas.assign(region, offset, Some(gas.to_le_bytes()))?;
        self.code_address
            .assign(region, offset, Some(code_address.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        self.is_success
            .assign(region, offset, Value::known(F::from(is_success.low_u64())))?;
        self.gas_is_u64.assign(
            region,
            offset,
            sum::value(&gas.to_le_bytes()[N_BYTES_GAS..]),
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
        // conditionally assign
        if !is_insufficient {
            self.transfer.assign(
                region,
                offset,
                caller_balance_pair,
                callee_balance_pair,
                value,
            )?;
        }

        self.callee_exists
            .assign(region, offset, Value::known(F::from(callee_exists)))?;
        self.callee_code_hash
            .assign(region, offset, Value::known(callee_code_hash))?;
        self.is_empty_code_hash.assign(
            region,
            offset,
            callee_code_hash,
            Word::random_linear_combine(*EMPTY_HASH_LE, block.randomness),
        )?;
        let mut code_address_bytes = [0; 32];
        code_address_bytes[0..N_BYTES_ACCOUNT_ADDRESS]
            .copy_from_slice(&code_address.to_le_bytes()[0..N_BYTES_ACCOUNT_ADDRESS]);
        let code_address_bytes = F::from_repr(code_address_bytes).unwrap();
        self.is_code_address_zero
            .assign(region, offset, code_address_bytes)?;
        self.is_precompile_lt
            .assign(region, offset, code_address_bytes, F::from(0xA))?;
        let has_value = !value.is_zero() && !is_delegatecall;
        let gas_cost = if is_warm_prev {
            GasCost::WARM_ACCESS.as_u64()
        } else {
            GasCost::COLD_ACCOUNT_ACCESS.as_u64()
        } + if has_value {
            GasCost::CALL_WITH_VALUE.as_u64()
                // Only CALL opcode could invoke transfer in successful case to make empty
                // account into non-empty.
                + if is_call && !callee_exists {
                    GasCost::NEW_ACCOUNT.as_u64()
                } else {
                    0
                }
        } else {
            0
        } + memory_expansion_gas_cost;
        let gas_available = step.gas_left - gas_cost;
        self.gas_cost
            .assign(region, offset, Value::known(F::from(step.gas_cost)))?;
        self.one_64th_gas
            .assign(region, offset, gas_available as u128)?;
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
    use crate::evm_circuit::test::run_test_circuit_geth_data;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::evm_types::OpcodeId;
    use eth_types::geth_types::{Account, GethData};
    use eth_types::{address, bytecode, word, Address, ToWord, Word};
    use halo2_proofs::halo2curves::bn256::Fr;
    use itertools::Itertools;
    use mock::test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0};
    use mock::TestContext;
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
            let block: GethData = TestContext::<2, 1>::new(
                None,
                account_0_code_account_1_no_code(test),
                tx_from_1_to_0,
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap()
            .into();
            assert_eq!(
                run_test_circuit_geth_data::<Fr>(
                    block,
                    CircuitsParams {
                        max_rws: 4500,
                        ..Default::default()
                    }
                ),
                Ok(())
            );
        }
    }

    #[test]
    fn callop_nested() {
        for opcode in TEST_CALL_OPCODES {
            test_nested(opcode);
        }
    }

    #[test]
    fn callop_recursive() {
        for opcode in TEST_CALL_OPCODES {
            test_recursive(opcode);
        }
    }

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
                cd_offset: 64,
                cd_length: 320,
                rd_offset: 0,
                rd_length: 32,
                ..Default::default()
            },
            Stack {
                cd_offset: 0,
                cd_length: 32,
                rd_offset: 64,
                rd_length: 320,
                ..Default::default()
            },
            Stack {
                cd_offset: 0xFFFFFF,
                cd_length: 0,
                rd_offset: 0xFFFFFF,
                rd_length: 0,
                ..Default::default()
            },
            // With memory expansion and value
            Stack {
                cd_offset: 64,
                cd_length: 320,
                rd_offset: 0,
                rd_length: 32,
                value: Word::from(10).pow(18.into()),
                ..Default::default()
            },
        ];
        let callees = [callee(bytecode! {}), callee(bytecode! { STOP })];

        for ((opcode, stack), callee) in TEST_CALL_OPCODES
            .iter()
            .cartesian_product(stacks.into_iter())
            .cartesian_product(callees.into_iter())
        {
            test_ok(caller(opcode, stack, true), callee);
        }
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Stack {
        gas: u64,
        value: Word,
        cd_offset: u64,
        cd_length: u64,
        rd_offset: u64,
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
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
        };
        if is_call_or_callcode {
            bytecode.push(32, stack.value);
        }
        bytecode.append(&bytecode! {
            PUSH32(Address::repeat_byte(0xff).to_word())
            PUSH32(Word::from(stack.gas))
            .write_op(*opcode)
            PUSH32(Word::from(stack.rd_length))
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
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
            PUSH32(Word::from(stack.rd_offset))
            PUSH32(Word::from(stack.cd_length))
            PUSH32(Word::from(stack.cd_offset))
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

    fn test_ok(caller: Account, callee: Account) {
        let block: GethData = TestContext::<3, 1>::new(
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
        .unwrap()
        .into();
        assert_eq!(
            run_test_circuit_geth_data::<Fr>(
                block,
                CircuitsParams {
                    max_rws: 4500,
                    ..Default::default()
                }
            ),
            Ok(())
        );
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
