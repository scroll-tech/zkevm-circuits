use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{
            N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE,
            N_BYTES_WORD,
        },
        step::ExecutionState,
        util::{
            common_gadget::TransferGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{ConstantDivisionGadget, ContractCreateGadget},
            memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget},
            not, select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToBigEndian, ToLittleEndian, ToScalar, U256};
use ethers_core::utils::keccak256;
use gadgets::util::expr_from_bytes;
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
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    gas_left: ConstantDivisionGadget<F, N_BYTES_GAS>,
    create: ContractCreateGadget<F, IS_CREATE2>,
    keccak_output: Word<F>,
}

impl<F: Field, const IS_CREATE2: bool, const S: ExecutionState> ExecutionGadget<F>
    for CreateGadget<F, IS_CREATE2, S>
{
    const NAME: &'static str = "CREATE";

    const EXECUTION_STATE: ExecutionState = S;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let callee_call_id = cb.curr.state.rw_counter.clone();

        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        cb.require_equal(
            "Opcode is CREATE or CREATE2",
            opcode.expr(),
            select::expr(
                IS_CREATE2.expr(),
                OpcodeId::CREATE2.expr(),
                OpcodeId::CREATE.expr(),
            ),
        );

        let value = cb.query_word_rlc();

        let init_code_memory_offset = cb.query_cell_phase2();
        let init_code_length = cb.query_word_rlc();
        let init_code =
            MemoryAddressGadget::construct(cb, init_code_memory_offset, init_code_length);

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
        cb.condition(IS_CREATE2.expr(), |cb| {
            cb.stack_pop(create.salt_keccak_rlc());
        });

        cb.stack_push(callee_is_success.expr() * new_address_rlc);

        cb.condition(init_code.has_length(), |cb| {
            // TODO(rohit): lookup to keccak table to verify keccak code hash?
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                create.code_hash_word_rlc(cb),
                CopyDataType::Bytecode.expr(),
                init_code.offset(),
                init_code.address(),
                0.expr(),
                init_code.length(),
                0.expr(),
                init_code.length(),
            );
        });
        cb.condition(not::expr(init_code.has_length()), |_cb| {
            /* FIXME
            cb.require_equal(
                "keccak hash of empty bytes",
                keccak_code_hash.expr(),
                cb.empty_keccak_hash_rlc(),
            );
            cb.require_equal(
                "code hash of empty bytes",
                create.code_hash_keccak_rlc(cb),
                cb.empty_code_hash_rlc(),
            );
            */
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

        cb.call_context_lookup(
            0.expr(),
            None,
            CallContextFieldTag::CalleeAddress,
            create.caller_address(),
        );

        cb.account_write(
            create.caller_address(),
            AccountFieldTag::Nonce,
            create.caller_nonce() + 1.expr(),
            create.caller_nonce(),
            Some(&mut reversion_info),
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

        let transfer = TransferGadget::construct(
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

        let memory_expansion = MemoryExpansionGadget::construct(cb, [init_code.address()]);

        let init_code_word_size = ConstantDivisionGadget::construct(
            cb,
            init_code.length() + (N_BYTES_WORD - 1).expr(),
            N_BYTES_WORD as u64,
        );
        let keccak_gas_cost =
            GasCost::COPY_SHA3.expr() * IS_CREATE2.expr() * init_code_word_size.quotient();

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

        let depth = cb.call_context(None, CallContextFieldTag::Depth);

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
            (CallContextFieldTag::CodeHash, create.code_hash_word_rlc(cb)),
            (CallContextFieldTag::Value, value.expr()),
        ] {
            cb.call_context_lookup(true.expr(), Some(callee_call_id.expr()), field_tag, value);
        }

        cb.keccak_table_lookup(
            create.input_rlc(cb),
            create.input_length(),
            keccak_output.expr(),
        );
        cb.condition(init_code.has_length(), |cb| {
            cb.require_step_state_transition(StepStateTransition {
                rw_counter: Delta(cb.rw_counter_offset()),
                call_id: To(callee_call_id.expr()),
                is_root: To(false.expr()),
                is_create: To(true.expr()),
                code_hash: To(create.code_hash_word_rlc(cb)),
                gas_left: To(callee_gas_left),
                reversible_write_counter: To(1.expr() + transfer.reversible_w_delta()),
                ..StepStateTransition::new_context()
            })
        });

        cb.condition(not::expr(init_code.has_length()), |cb| {
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
                gas_left: Delta(-gas_cost),
                reversible_write_counter: Delta(3.expr() + transfer.reversible_w_delta()),
                ..Default::default()
            })
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
            memory_expansion,
            gas_left,
            callee_is_success,
            init_code_word_size,
            create,
            keccak_output,
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

        let [value, init_code_start, init_code_length] = [0, 1, 2]
            .map(|i| step.rw_indices[i])
            .map(|idx| block.rws[idx].stack_value());
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        let salt = if is_create2 {
            block.rws[step.rw_indices[3]].stack_value()
        } else {
            U256::zero()
        };

        let values: Vec<_> = (4 + usize::from(is_create2)
            ..4 + usize::from(is_create2) + init_code_length.as_usize())
            .map(|i| block.rws[step.rw_indices[i]].memory_value())
            .collect();

        let init_code_address =
            self.init_code
                .assign(region, offset, init_code_start, init_code_length)?;

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

        let copy_rw_increase = init_code_length.as_usize();
        let tx_access_rw =
            block.rws[step.rw_indices[7 + usize::from(is_create2) + copy_rw_increase]];
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

        let caller_nonce = block.rws
            [step.rw_indices[9 + usize::from(is_create2) + copy_rw_increase]]
            .account_value_pair()
            .1
            .low_u64();

        let [callee_rw_counter_end_of_reversion, callee_is_persistent] = [10, 11].map(|i| {
            let rw = block.rws[step.rw_indices[i + usize::from(is_create2) + copy_rw_increase]];
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

        let mut rw_offset = 0;

        let [caller_balance_pair, callee_balance_pair] = if !value.is_zero() {
            rw_offset += 2;
            [13, 14].map(|i| {
                let rw = block.rws[step.rw_indices[i + usize::from(is_create2) + copy_rw_increase]];
                debug_assert_eq!(
                    rw.field_tag(),
                    Some(AccountFieldTag::Balance as u64),
                    "invalid rw {:?}",
                    rw
                );
                rw.account_value_pair()
            })
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

        let gas_left = step.gas_left
            - GasCost::CREATE.as_u64()
            - memory_expansion_gas_cost
            - if is_create2 {
                u64::try_from(init_code_word_size).unwrap() * GasCost::COPY_SHA3.as_u64()
            } else {
                0
            };
        self.gas_left.assign(region, offset, gas_left.into())?;

        self.callee_is_success.assign(
            region,
            offset,
            Value::known(
                block.rws
                    [step.rw_indices[21 + rw_offset + usize::from(is_create2) + copy_rw_increase]]
                    .call_context_value()
                    .to_scalar()
                    .unwrap(),
            ),
        )?;

        let keccak_input: Vec<u8> = if is_create2 {
            once(0xffu8)
                .chain(call.callee_address.to_fixed_bytes())
                .chain(salt.to_be_bytes())
                .chain(keccak256(&values))
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

        let code_hash = keccak256(&values);
        self.create.assign(
            region,
            offset,
            call.callee_address,
            caller_nonce,
            Some(U256::from_big_endian(&code_hash)),
            Some(salt),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        address, bytecode, evm_types::OpcodeId, geth_types::Account, Address, Bytecode, Word,
    };

    use itertools::Itertools;
    use lazy_static::lazy_static;
    use mock::{eth, TestContext};

    use crate::test_util::CircuitTestBuilder;

    const CALLEE_ADDRESS: Address = Address::repeat_byte(0xff);
    lazy_static! {
        static ref CALLER_ADDRESS: Address = address!("0x00bbccddee000000000000000000000000002400");
    }

    fn run_test_circuits(ctx: TestContext<2, 1>) {
        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_rws: 4500,
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
            PUSH2(23414) // value
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
                    .gas(100000u64.into());
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
            let root_code = creater_bytecode(init_code, *is_create2, *is_persistent);
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
                code: creater_bytecode(initialization_bytecode(true), false, true).into(),
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
                code: creater_bytecode(vec![].into(), is_create2, true).into(),
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
}
