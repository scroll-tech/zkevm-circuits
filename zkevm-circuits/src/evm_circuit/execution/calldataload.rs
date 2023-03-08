use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            and,
            common_gadget::{SameContextGadget, WordByteCapGadget},
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            memory_gadget::BufferReaderGadget,
            not, select, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};

use super::ExecutionGadget;

// The offset in the RW indices that mark the start of memory lookups.
const OFFSET_RW_MEMORY_INDICES: usize = 4usize;

#[derive(Clone, Debug)]
pub(crate) struct CallDataLoadGadget<F> {
    /// Gadget to constrain the same context.
    same_context: SameContextGadget<F>,
    /// Source of data, this is transaction ID for a root call and caller ID for
    /// an internal call.
    src_id: Cell<F>,
    /// The size of the call's data (tx input for a root call or calldata length
    /// of an internal call).
    call_data_length: Cell<F>,
    /// The offset from where call data begins. This is 0 for a root call since
    /// tx data starts at the first byte, but can be non-zero offset for an
    /// internal call.
    call_data_offset: Cell<F>,
    /// The bytes offset in calldata, from which we load a 32-bytes word. It
    /// is valid if within range of Uint64 and less than call_data_length.
    data_offset: WordByteCapGadget<F, N_BYTES_U64>,
    /// Gadget to read from tx calldata, which we validate against the word
    /// pushed to stack.
    buffer_reader: BufferReaderGadget<F, N_BYTES_WORD, N_BYTES_MEMORY_ADDRESS>,
}

impl<F: Field> ExecutionGadget<F> for CallDataLoadGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATALOAD;

    const NAME: &'static str = "CALLDATALOAD";

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let src_id = cb.query_cell();
        let call_data_length = cb.query_cell();
        let call_data_offset = cb.query_cell();

        let data_offset = WordByteCapGadget::construct(cb, call_data_length.expr());
        cb.stack_pop(data_offset.original_word());

        cb.condition(
            and::expr([data_offset.within_range(), cb.curr.state.is_root.expr()]),
            |cb| {
                cb.call_context_lookup(
                    false.expr(),
                    None,
                    CallContextFieldTag::TxId,
                    src_id.expr(),
                );
                cb.call_context_lookup(
                    false.expr(),
                    None,
                    CallContextFieldTag::CallDataLength,
                    call_data_length.expr(),
                );
                cb.require_equal(
                    "if is_root then call_data_offset == 0",
                    call_data_offset.expr(),
                    0.expr(),
                );
            },
        );

        cb.condition(
            and::expr([
                data_offset.within_range(),
                not::expr(cb.curr.state.is_root.expr()),
            ]),
            |cb| {
                cb.call_context_lookup(
                    false.expr(),
                    None,
                    CallContextFieldTag::CallerId,
                    src_id.expr(),
                );
                cb.call_context_lookup(
                    false.expr(),
                    None,
                    CallContextFieldTag::CallDataLength,
                    call_data_length.expr(),
                );
                cb.call_context_lookup(
                    false.expr(),
                    None,
                    CallContextFieldTag::CallDataOffset,
                    call_data_offset.expr(),
                );
            },
        );

        // Set source start to the minimun value of data offset and call data length.
        let src_addr = call_data_offset.expr()
            + select::expr(
                data_offset.lt_cap(),
                data_offset.valid_value(),
                call_data_length.expr(),
            );

        let src_addr_end = call_data_offset.expr() + call_data_length.expr();

        let buffer_reader = BufferReaderGadget::construct(cb, src_addr.expr(), src_addr_end);

        let mut calldata_word: Vec<_> = (0..N_BYTES_WORD)
            .map(|idx| {
                // For a root call, the call data comes from tx's data field.
                cb.condition(
                    and::expr([
                        data_offset.within_range(),
                        buffer_reader.read_flag(idx),
                        cb.curr.state.is_root.expr(),
                    ]),
                    |cb| {
                        cb.tx_context_lookup(
                            src_id.expr(),
                            TxContextFieldTag::CallData,
                            Some(src_addr.expr() + idx.expr()),
                            buffer_reader.byte(idx),
                        );
                    },
                );
                // For an internal call, the call data comes from memory.
                cb.condition(
                    and::expr([
                        data_offset.within_range(),
                        buffer_reader.read_flag(idx),
                        not::expr(cb.curr.state.is_root.expr()),
                    ]),
                    |cb| {
                        cb.memory_lookup(
                            0.expr(),
                            src_addr.expr() + idx.expr(),
                            buffer_reader.byte(idx),
                            Some(src_id.expr()),
                        );
                    },
                );
                buffer_reader.byte(idx)
            })
            .collect();

        // Since the stack items are in little endian form, we reverse the bytes
        // here.
        calldata_word.reverse();

        // Add a lookup constraint for the 32-bytes that should have been pushed
        // to the stack.
        let calldata_word: [Expression<F>; N_BYTES_WORD] = calldata_word.try_into().unwrap();
        let calldata_word = cb.word_rlc(calldata_word);
        cb.require_zero(
            "Stack push result must be 0 if stack pop offset is Uint64 overflow",
            data_offset.overflow() * calldata_word.expr(),
        );

        cb.stack_push(calldata_word);

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::CALLDATALOAD.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            src_id,
            call_data_length,
            call_data_offset,
            data_offset,
            buffer_reader,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        // Assign to the buffer reader gadget.
        let (src_id, call_data_offset, call_data_length) = if call.is_root {
            (tx.id, 0, tx.call_data_length as u64)
        } else {
            (call.caller_id, call.call_data_offset, call.call_data_length)
        };
        self.src_id
            .assign(region, offset, Value::known(F::from(src_id as u64)))?;
        self.call_data_length
            .assign(region, offset, Value::known(F::from(call_data_length)))?;
        self.call_data_offset
            .assign(region, offset, Value::known(F::from(call_data_offset)))?;

        let data_offset = block.rws[step.rw_indices[0]].stack_value();
        let offset_within_range =
            self.data_offset
                .assign(region, offset, data_offset, F::from(call_data_length))?;

        let data_offset = if offset_within_range {
            data_offset.as_u64()
        } else {
            call_data_length
        };
        let src_addr_end = call_data_offset.checked_add(call_data_length).unwrap();
        let src_addr = call_data_offset
            .checked_add(data_offset)
            .unwrap_or(src_addr_end)
            .min(src_addr_end);

        let mut calldata_bytes = vec![0u8; N_BYTES_WORD];
        if offset_within_range {
            for (i, byte) in calldata_bytes.iter_mut().enumerate() {
                if call.is_root {
                    // Fetch from tx call data.
                    if src_addr.checked_add(i as u64).unwrap() < tx.call_data_length as u64 {
                        *byte = tx.call_data[src_addr as usize + i];
                    }
                } else {
                    // Fetch from memory.
                    if src_addr.checked_add(i as u64).unwrap()
                        < call.call_data_offset + call.call_data_length
                    {
                        *byte =
                            block.rws[step.rw_indices[OFFSET_RW_MEMORY_INDICES + i]].memory_value();
                    }
                }
            }
        }

        self.buffer_reader.assign(
            region,
            offset,
            src_addr,
            src_addr_end,
            &calldata_bytes,
            &[true; N_BYTES_WORD],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, ToWord, Word};
    use mock::TestContext;

    fn test_root_ok(offset: Word) {
        let bytecode = bytecode! {
            PUSH32(offset)
            CALLDATALOAD
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    fn test_internal_ok(call_data_length: usize, call_data_offset: usize, offset: Word) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = bytecode! {
            PUSH32(offset)
            CALLDATALOAD
            STOP
        };

        let pushdata = rand_bytes(32);
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH32(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call addr_b
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn calldataload_gadget_root() {
        test_root_ok(0x00.into());
        test_root_ok(0x08.into());
        test_root_ok(0x10.into());
        test_root_ok(0x2010.into());
    }

    #[test]
    fn calldataload_gadget_internal() {
        test_internal_ok(0x20, 0x00, 0x00.into());
        test_internal_ok(0x20, 0x10, 0x10.into());
        test_internal_ok(0x40, 0x20, 0x08.into());
        test_internal_ok(0x1010, 0xff, 0x10.into());
    }

    #[test]
    fn calldataload_gadget_offset_overflow() {
        test_root_ok(Word::MAX);
        test_internal_ok(0x1010, 0xff, Word::MAX);
    }
}
