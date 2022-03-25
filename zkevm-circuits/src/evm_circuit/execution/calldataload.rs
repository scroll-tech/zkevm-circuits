use std::convert::TryInto;

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{
    circuit::Region,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_WORD},
        step::ExecutionState,
        table::{CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            memory_gadget::BufferReaderGadget,
            Cell, MemoryAddress, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

// The offset in the RW indices that mark the start of memory lookups.
const OFFSET_RW_MEMORY_INDICES: usize = 5usize;

#[derive(Clone, Debug)]
pub(crate) struct CallDataLoadGadget<F> {
    /// Gadget to constrain the same context.
    same_context: SameContextGadget<F>,
    /// Transaction id from the tx context.
    tx_id: Cell<F>,
    /// The bytes offset in calldata, from which we load a 32-bytes word.
    offset: MemoryAddress<F>,
    /// The size of the call's data (tx input for a root call or calldata length
    /// of an internal call).
    calldata_length: Cell<F>,
    /// The offset from where call data begins. This is 0 for a root call since
    /// tx data starts at the first byte, but can be non-zero offset for an
    /// internal call.
    calldata_offset: Cell<F>,
    /// Parent call ID that makes a call to this internal call.
    caller_id: Cell<F>,
    /// Gadget to read from tx calldata, which we validate against the word
    /// pushed to stack.
    buffer_reader: BufferReaderGadget<F, N_BYTES_WORD, N_BYTES_MEMORY_ADDRESS>,
}

impl<F: Field> ExecutionGadget<F> for CallDataLoadGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATALOAD;

    const NAME: &'static str = "CALLDATALOAD";

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let offset = cb.query_rlc();

        // Pop the offset value from stack.
        cb.stack_pop(offset.expr());

        // Add a lookup constrain for TxId in the RW table.
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        let calldata_length = cb.query_cell();
        let calldata_offset = cb.query_cell();
        let caller_id = cb.query_cell();

        let src_addr = offset.expr() + calldata_offset.expr();
        let src_addr_end = calldata_length.expr() + calldata_offset.expr();

        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            cb.tx_context_lookup(
                tx_id.expr(),
                TxContextFieldTag::CallDataLength,
                None,
                calldata_length.expr(),
            );
            cb.require_equal(
                "if is_root then calldata_offset == 0",
                calldata_offset.expr(),
                0.expr(),
            );
        });
        cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallDataLength,
                calldata_length.expr(),
            );
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallDataOffset,
                calldata_offset.expr(),
            );
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallerId,
                caller_id.expr(),
            );
        });

        let buffer_reader = BufferReaderGadget::construct(cb, src_addr.clone(), src_addr_end);

        let mut calldata_word = (0..N_BYTES_WORD)
            .map(|idx| {
                // for a root call, the call data comes from tx's data field.
                cb.condition(
                    cb.curr.state.is_root.expr() * buffer_reader.read_flag(idx),
                    |cb| {
                        cb.tx_context_lookup(
                            tx_id.expr(),
                            TxContextFieldTag::CallData,
                            Some(src_addr.expr() + idx.expr()),
                            buffer_reader.byte(idx),
                        );
                    },
                );
                // for an internal call, the call data comes from memory.
                cb.condition(
                    (1.expr() - cb.curr.state.is_root.expr()) * buffer_reader.read_flag(idx),
                    |cb| {
                        cb.memory_lookup(
                            0.expr(),
                            src_addr.expr() + idx.expr(),
                            buffer_reader.byte(idx),
                            Some(caller_id.expr()),
                        );
                    },
                );
                buffer_reader.byte(idx)
            })
            .collect::<Vec<Expression<F>>>();

        // Since the stack items are in little endian form, we reverse the bytes
        // here.
        calldata_word.reverse();

        // Add a lookup constraint for the 32-bytes that should have been pushed
        // to the stack.
        let calldata_word: [Expression<F>; N_BYTES_WORD] = calldata_word.try_into().unwrap();
        cb.stack_push(RandomLinearCombination::random_linear_combine_expr(
            calldata_word,
            cb.power_of_randomness(),
        ));

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
            offset,
            calldata_length,
            calldata_offset,
            caller_id,
            tx_id,
            buffer_reader,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // set the value for bytes offset in calldata. This is where we start
        // reading bytes from.
        let data_offset = block.rws[step.rw_indices[0]].stack_value();

        // assign the calldata start and end cells.
        self.offset.assign(
            region,
            offset,
            Some(
                data_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        // assign the tx id.
        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;

        // assign to the buffer reader gadget.
        let (calldata_length, calldata_offset, caller_id) = if call.is_root {
            (tx.call_data_length as u64, 0u64, 0u64)
        } else {
            (
                call.call_data_length,
                call.call_data_offset,
                call.caller_id as u64,
            )
        };
        self.calldata_length
            .assign(region, offset, Some(F::from(calldata_length)))?;
        self.calldata_offset
            .assign(region, offset, Some(F::from(calldata_offset)))?;
        self.caller_id
            .assign(region, offset, Some(F::from(caller_id)))?;

        let mut calldata_bytes = vec![0u8; N_BYTES_WORD];
        let (src_addr, src_addr_end) = (
            data_offset.as_usize() + calldata_offset as usize,
            calldata_length as usize + calldata_offset as usize,
        );

        for (i, byte) in calldata_bytes.iter_mut().enumerate() {
            if call.is_root {
                // fetch from tx call data
                if src_addr + i < tx.call_data_length {
                    *byte = tx.call_data[src_addr + i];
                }
            } else {
                // fetch from memory
                if src_addr + i < call.call_data_length as usize {
                    *byte = block.rws[step.rw_indices[OFFSET_RW_MEMORY_INDICES + i]].memory_value();
                }
            }
        }
        self.buffer_reader.assign(
            region,
            offset,
            src_addr as u64,
            src_addr_end as u64,
            &calldata_bytes,
            &[true; N_BYTES_WORD],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use bus_mapping::evm::OpcodeId;
    use eth_types::{bytecode, Word};
    use halo2_proofs::arithmetic::BaseExt;
    use pairing::bn256::Fr;

    use crate::evm_circuit::{
        execution::calldataload::OFFSET_RW_MEMORY_INDICES,
        param::N_BYTES_WORD,
        step::ExecutionState,
        table::{CallContextFieldTag, RwTableTag},
        test::run_test_circuit_incomplete_fixed_table,
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };

    fn bytes_from_hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("invalid hex")
    }

    fn word_from_hex(s: &str) -> Word {
        Word::from_big_endian(&bytes_from_hex(s))
    }

    fn test_data() -> Vec<(Vec<u8>, usize, Word)> {
        vec![
            (
                bytes_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEE"),
                0,
                word_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEE"),
            ),
            (
                bytes_from_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
                31,
                word_from_hex("FF00000000000000000000000000000000000000000000000000000000000000"),
            ),
            (
                bytes_from_hex("a1bacf5488bfafc33bad736db41f06866eaeb35e1c1dd81dfc268357ec98563f"),
                16,
                word_from_hex("6eaeb35e1c1dd81dfc268357ec98563f00000000000000000000000000000000"),
            ),
        ]
    }

    fn test_ok(call_data: Vec<u8>, offset: Word, expected: Word, call_data_offset: Option<u64>) {
        let randomness = Fr::rand();
        let bytecode = bytecode! {
            #[start]
            PUSH32(offset)
            CALLDATALOAD
            STOP
        };
        let bytecode = Bytecode::new(bytecode.to_vec());
        let tx_id = 1;
        let (call_id, parent_call_id) = if call_data_offset.is_some() {
            (1, 0)
        } else {
            (2, 1)
        };
        let call_data_length = call_data.len();

        let mut rws_stack = vec![
            Rw::Stack {
                rw_counter: 1,
                is_write: true,
                call_id,
                stack_pointer: 1023,
                value: offset,
            },
            Rw::Stack {
                rw_counter: 2,
                is_write: false,
                call_id,
                stack_pointer: 1023,
                value: offset,
            },
        ];
        let mut rws_call_context = vec![Rw::CallContext {
            rw_counter: 3,
            is_write: false,
            call_id,
            field_tag: CallContextFieldTag::TxId,
            value: Word::one(),
        }];
        let mut rw_indices = vec![(RwTableTag::Stack, 1), (RwTableTag::CallContext, 0)];

        // if not root call, add calldata to memory.
        let mut rws_map = HashMap::new();
        let mut rw_counter = 4;
        // if call data offset is provided, then it is an internal call.
        if let Some(call_data_offset) = call_data_offset {
            let src_addr = offset.as_usize() + call_data_offset as usize;
            // handle call context rws.
            rws_call_context.append(&mut vec![
                Rw::CallContext {
                    is_write: false,
                    call_id,
                    rw_counter,
                    field_tag: CallContextFieldTag::CallDataLength,
                    value: Word::from(call_data_length as u64),
                },
                Rw::CallContext {
                    is_write: false,
                    call_id,
                    rw_counter: rw_counter + 1,
                    field_tag: CallContextFieldTag::CallDataOffset,
                    value: Word::from(call_data_offset),
                },
                Rw::CallContext {
                    is_write: false,
                    call_id,
                    rw_counter: rw_counter + 2,
                    field_tag: CallContextFieldTag::CallerId,
                    value: Word::from(parent_call_id as u64),
                },
            ]);
            rw_indices.append(&mut vec![
                (RwTableTag::CallContext, 1),
                (RwTableTag::CallContext, 2),
                (RwTableTag::CallContext, 3),
            ]);
            rw_counter += 3;

            assert_eq!(rw_indices.len(), OFFSET_RW_MEMORY_INDICES);

            // handle memory rws.
            let rws_memory = call_data
                .iter()
                .skip(src_addr)
                .take(N_BYTES_WORD)
                .enumerate()
                .map(|(idx, byte)| Rw::Memory {
                    call_id: parent_call_id,
                    memory_address: (src_addr + idx) as u64,
                    is_write: false,
                    byte: *byte,
                    rw_counter: rw_counter + idx,
                })
                .collect::<Vec<Rw>>();
            rw_counter += rws_memory.len();
            let mut extra_indices = (0..rws_memory.len())
                .map(|i| (RwTableTag::Memory, i))
                .collect();
            rw_indices.append(&mut extra_indices);
            rws_map.insert(RwTableTag::Memory, rws_memory);
        }
        rw_indices.push((RwTableTag::Stack, 2));
        rws_stack.push(Rw::Stack {
            rw_counter,
            is_write: true,
            call_id,
            stack_pointer: 1023,
            value: expected,
        });
        rws_map.insert(RwTableTag::Stack, rws_stack);
        rws_map.insert(RwTableTag::CallContext, rws_call_context);

        let gas_left = vec![OpcodeId::PUSH32, OpcodeId::CALLDATALOAD, OpcodeId::STOP]
            .iter()
            .map(|o| o.constant_gas_cost().as_u64())
            .sum();
        let steps = vec![
            ExecStep {
                execution_state: ExecutionState::PUSH,
                rw_indices: vec![(RwTableTag::Stack, 0)],
                rw_counter: 1,
                program_counter: 0,
                stack_pointer: 1024,
                gas_left,
                gas_cost: OpcodeId::PUSH32.constant_gas_cost().as_u64(),
                opcode: Some(OpcodeId::PUSH32),
                ..Default::default()
            },
            ExecStep {
                execution_state: ExecutionState::CALLDATALOAD,
                rw_indices,
                rw_counter: 2,
                program_counter: 33,
                stack_pointer: 1023,
                gas_left: gas_left - OpcodeId::PUSH32.constant_gas_cost().as_u64(),
                gas_cost: OpcodeId::CALLDATALOAD.constant_gas_cost().as_u64(),
                opcode: Some(OpcodeId::CALLDATALOAD),
                ..Default::default()
            },
            ExecStep {
                execution_state: ExecutionState::STOP,
                rw_counter: rw_counter + 1,
                program_counter: 34,
                stack_pointer: 1023,
                gas_left: 0,
                opcode: Some(OpcodeId::STOP),
                ..Default::default()
            },
        ];

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: tx_id,
                call_data_length: if call_data_offset.is_none() {
                    call_data.len()
                } else {
                    0
                },
                call_data: if call_data_offset.is_none() {
                    call_data
                } else {
                    vec![]
                },
                steps,
                calls: vec![Call {
                    id: call_id,
                    is_root: call_data_offset.is_none(),
                    is_create: false,
                    call_data_length: call_data_length as u64,
                    call_data_offset: call_data_offset.unwrap_or(0),
                    code_source: CodeSource::Account(bytecode.hash),
                    caller_id: parent_call_id,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            rws: RwMap(rws_map),
            bytecodes: vec![bytecode],
            ..Default::default()
        };

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn calldataload_gadget_root() {
        test_data()
            .iter()
            .for_each(|t| test_ok(t.0.clone(), Word::from(t.1), t.2, None));
    }

    #[test]
    fn calldataload_gadget_internal() {
        test_data()
            .iter()
            .for_each(|t| test_ok(t.0.clone(), Word::from(t.1), t.2, Some(0u64)));

        test_ok(
            bytes_from_hex("73ccaaba64c27c285a0ada6ffb1804dc959a99b99a5c0cba8a2bd5bd3937be6a3ef6f6ae8dac116faf671072c9d5958a"),
            Word::from(4u64),
            word_from_hex("04dc959a99b99a5c0cba8a2bd5bd3937be6a3ef6f6ae8dac116faf671072c9d5"),
            Some(10u64),
        );
    }
}
