use array_init::array_init;
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use log::trace;

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            and,
            common_gadget::{SameContextGadget, WordByteCapGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            },
            from_bytes,
            memory_gadget::{BufferReaderGadget, MemoryMask, MemoryWordAddress},
            not, select, CachedRegion, Cell, Word,
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
    // read two memory words
    // memory_address: MemoryWordAddress<F>,
    address_align: MemoryWordAddress<F>,
    mask: MemoryMask<F>,
    value: Word<F>,
    value_left: Word<F>,
    value_right: Word<F>,
}

impl<F: Field> ExecutionGadget<F> for CallDataLoadGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATALOAD;

    const NAME: &'static str = "CALLDATALOAD";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let src_id = cb.query_cell();
        let call_data_length = cb.query_cell();
        let call_data_offset = cb.query_cell();

        let value = cb.query_word_rlc();
        let value_left = cb.query_word_rlc();
        let value_right = cb.query_word_rlc();

        let data_offset = WordByteCapGadget::construct(cb, call_data_length.expr());
        cb.stack_pop(data_offset.original_word());

        cb.condition(
            and::expr([data_offset.not_overflow(), cb.curr.state.is_root.expr()]),
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
                data_offset.not_overflow(),
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

        // Read the call data word, potentially including trailing zeros
        // when reading out-of-bound.
        let mut calldata_word: Vec<_> = (0..N_BYTES_WORD)
            .map(|idx| {
                // For a root call, the call data comes from tx's data field.
                cb.condition(
                    and::expr([
                        data_offset.not_overflow(),
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
                buffer_reader.byte(idx)
            })
            .collect();
        // Since the stack is interpreted as MSB-first in CALLDATALOAD, we reverse the bytes here.
        calldata_word.reverse();
        let calldata_word: [Expression<F>; N_BYTES_WORD] = calldata_word.try_into().unwrap();
        let calldata_word = cb.word_rlc(calldata_word);

        // Now that we have the address in the caller’s memory, decompose it to work out the
        // alignment.
        let address = cb.query_word_rlc();
        cb.require_equal(
            "memory address decomposition",
            from_bytes::expr(&address.cells),
            src_addr,
        );

        let address_align = MemoryWordAddress::construct(cb, address);
        let mask = MemoryMask::construct(cb, &address_align.shift_bits(), 0.expr());

        // For an internal call, the call data comes from memory，read memory word
        cb.condition(
            and::expr([
                data_offset.not_overflow(),
                not::expr(cb.curr.state.is_root.expr()),
            ]),
            |cb| {
                // Compare calldata with the memory value, except for out-of-bound bytes set to
                // zero. The MLOAD value is MSB-first, the reverse order of the buffer_reader.
                let mem_calldata_overlap: [Expression<F>; N_BYTES_WORD] = array_init(|i| {
                    let reversed_i = N_BYTES_WORD - 1 - i;
                    value.cells[i].expr() * buffer_reader.read_flag(reversed_i)
                });
                cb.require_equal(
                    "calldata equals memory data",
                    calldata_word.clone(),
                    cb.word_rlc(mem_calldata_overlap),
                );

                // Get the memory word the same way as MLOAD.
                // Check the bytes that are read from the left and right memory words.
                mask.require_equal_unaligned_word(cb, value.expr(), &value_left, &value_right);

                // Read the left and right words.
                cb.memory_lookup_word(
                    0.expr(),
                    address_align.addr_left(),
                    value_left.expr(),
                    value_left.expr(),
                    Some(src_id.expr()),
                );
                cb.memory_lookup_word(
                    0.expr(),
                    address_align.addr_right(),
                    value_right.expr(),
                    value_right.expr(),
                    Some(src_id.expr()),
                );
            },
        );

        // Add a lookup constraint for the 32-bytes that should have been pushed
        // to the stack.
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
            address_align,
            mask,
            value,
            value_left,
            value_right,
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
        let offset_not_overflow =
            self.data_offset
                .assign(region, offset, data_offset, F::from(call_data_length))?;

        let data_offset = if offset_not_overflow {
            data_offset.as_u64()
        } else {
            call_data_length
        };
        let src_addr_end = call_data_offset + call_data_length;
        let src_addr = call_data_offset
            .checked_add(data_offset)
            .unwrap_or(src_addr_end)
            .min(src_addr_end);

        let shift = src_addr % 32;
        self.address_align.assign(region, offset, src_addr)?;
        self.mask.assign(region, offset, shift, false)?;

        // prepare to fetch from memory bytes
        let mut value_left_bytes = [0u8; N_BYTES_WORD];
        let mut value_right_bytes = [0u8; N_BYTES_WORD];

        if !call.is_root && offset_not_overflow {
            // assign value_left, value_right word
            value_left_bytes = block.rws[step.rw_indices[4]]
                .memory_word_pair()
                .0
                .to_le_bytes();
            value_right_bytes = block.rws[step.rw_indices[5]]
                .memory_word_pair()
                .0
                .to_le_bytes();

            // Here we write exactly what is in the RW table.
            self.value_left
                .assign(region, offset, Some(value_left_bytes))?;
            self.value_right
                .assign(region, offset, Some(value_right_bytes))?;

            // The RW values were BE order (see bus-mapping), so go back to normal memory order.
            value_left_bytes.reverse();
            value_right_bytes.reverse();
        }

        // reconstruct the unaligned word.
        let value_bytes =
            MemoryMask::<F>::make_unaligned_word(shift, &value_left_bytes, &value_right_bytes);
        self.value.assign(region, offset, Some(value_bytes))?;

        let mut calldata_bytes = vec![0u8; N_BYTES_WORD];

        if offset_not_overflow {
            for (i, byte) in calldata_bytes.iter_mut().enumerate() {
                if call.is_root {
                    // Fetch from tx call data.
                    if src_addr + (i as u64) < tx.call_data_length as u64 {
                        *byte = tx.call_data[src_addr as usize + i];
                    }
                } else {
                    // Fetch from memory.
                    if src_addr.checked_add(i as u64).unwrap()
                        < call.call_data_offset + call.call_data_length
                    {
                        if i.checked_add(shift.try_into().unwrap()).unwrap() < 32 {
                            *byte = value_left_bytes[i + shift as usize];
                        } else {
                            // across to value_right
                            *byte = value_right_bytes[i + shift as usize - 32];
                        }
                    }
                }
            }
        }
        trace!("assign calldata_bytes {calldata_bytes:?}");

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
    use eth_types::{bytecode, Word};
    use mock::{generate_mock_call_bytecode, MockCallBytecodeParams, TestContext};

    fn test_bytecode(offset: Word) -> eth_types::Bytecode {
        bytecode! {
            PUSH32(offset)
            CALLDATALOAD
            STOP
        }
    }

    fn test_root_ok(offset: Word) {
        let bytecode = test_bytecode(offset);

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    fn test_internal_ok(call_data_length: usize, call_data_offset: usize, offset: Word) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = test_bytecode(offset);
        let code_a = generate_mock_call_bytecode(MockCallBytecodeParams {
            address: addr_b,
            pushdata: rand_bytes(32),
            call_data_length,
            call_data_offset,
            ..MockCallBytecodeParams::default()
        });

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
