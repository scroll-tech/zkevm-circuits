use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_MEMORY_WORD_SIZE,
        step::ExecutionState,
        table::{CallContextFieldTag, RwTableTag, TxLogFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget},
            sum, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use array_init::array_init;
use eth_types::Field;
use eth_types::{evm_types::GasCost, evm_types::OpcodeId, ToLittleEndian, ToScalar};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct LogGadget<F> {
    same_context: SameContextGadget<F>,
    // memory address
    memory_address: MemoryAddressGadget<F>,
    topics: [Cell<F>; 4],
    topic_selectors: [Cell<F>; 4],

    contract_address: Cell<F>,
    is_static_call: Cell<F>,
    is_persistent: Cell<F>,
    tx_id: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for LogGadget<F> {
    const NAME: &'static str = "LOG";

    const EXECUTION_STATE: ExecutionState = ExecutionState::LOG;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let mstart = cb.query_cell();
        let msize = cb.query_rlc();

        // Pop mstart_address, msize from stack
        cb.stack_pop(mstart.clone().expr());
        cb.stack_pop(msize.expr());

        // read tx id
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        // constrain not in static call
        let is_static_call = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static_call is false", is_static_call.expr());

        // check contract_address in CallContext & TxLog
        // use call context's  callee address as contract address
        let contract_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);
        let is_persistent = cb.call_context(None, CallContextFieldTag::IsPersistent);
        cb.condition(is_persistent.expr(), |cb| {
            cb.tx_log_lookup(
                tx_id.expr(),
                TxLogFieldTag::Address,
                0.expr(),
                contract_address.expr(),
            );
        });

        // constrain topics in logs
        let topics = array_init(|_| cb.query_cell());
        let topic_selectors: [Cell<F>; 4] = array_init(|_| cb.query_cell());
        for (idx, topic) in topics.iter().enumerate() {
            cb.condition(topic_selectors[idx].expr(), |cb| {
                cb.stack_pop(topic.expr());
            });
            cb.condition(topic_selectors[idx].expr() * is_persistent.expr(), |cb| {
                cb.tx_log_lookup(tx_id.expr(), TxLogFieldTag::Topic, idx.expr(), topic.expr());
            });
        }

        let opcode = cb.query_cell();
        let topic_count = opcode.expr() - OpcodeId::LOG0.as_u8().expr();

        // TOPIC_COUNT == Non zero topic selector count
        cb.require_equal(
            " sum of topic selectors = topic_count ",
            topic_count.clone(),
            sum::expr(topic_selectors.clone()),
        );

        // `topic_selectors` order must be from 1 --> 0
        for idx in 0..4 {
            cb.require_boolean("topic selector is bool ", topic_selectors[idx].expr());
            if idx > 0 {
                let selector_prev = topic_selectors[idx - 1].expr();
                // selector can transit from 1 to 0 only once as [1, 1 ..., 0]
                cb.require_boolean(
                    "Constrain topic selectors can only transit from 1 to 0",
                    selector_prev - topic_selectors[idx].expr(),
                );
            }
        }

        // check memory copy
        let memory_address = MemoryAddressGadget::construct(cb, mstart.clone(), msize.clone());

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_word_size.expr(),
            [memory_address.address()],
        );

        // If the iterative process has not yet finished, we constrain the next step to
        // be another `CopyToLog` while adding some additional
        // constraints to the auxiliary data.
        // Constrain the next step CopyToLog if length != 0
        cb.constrain_next_step(
            ExecutionState::CopyToLog,
            Some(memory_address.has_length()),
            |cb| {
                let next_src_addr = cb.query_cell();
                let next_bytes_left = cb.query_cell();
                let next_src_addr_end = cb.query_cell();
                let next_is_persistent = cb.query_bool();
                let next_tx_id = cb.query_cell();
                let next_data_start_index = cb.query_cell();

                cb.require_equal(
                    "next_src_addr = memory_offset",
                    next_src_addr.expr(),
                    mstart.expr(),
                );
                cb.require_equal(
                    "next_bytes_left = length",
                    next_bytes_left.expr(),
                    memory_address.length(),
                );
                cb.require_equal(
                    "next_src_addr_end = memory_offset + length",
                    next_src_addr_end.expr(),
                    mstart.expr() + memory_address.length(),
                );
                cb.require_equal(
                    "next_is_persistent = is_persistent",
                    next_is_persistent.expr(),
                    is_persistent.expr(),
                );
                cb.require_equal("next_tx_id = tx_id", next_tx_id.expr(), tx_id.expr());
                cb.require_zero(
                    "next_data_start_index starts with 0",
                    next_data_start_index.expr(),
                );
            },
        );

        let gas_cost = GasCost::LOG.as_u64().expr()
            + GasCost::LOG.as_u64().expr() * topic_count.clone()
            + 8.expr() * from_bytes::expr(&msize.cells)
            + memory_expansion.gas_cost();
        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr() + topic_count),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            log_id: Delta(is_persistent.expr()),
            gas_left: Delta(-gas_cost),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            topics,
            topic_selectors,
            contract_address,
            is_static_call,
            is_persistent,
            tx_id,
            memory_expansion,
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

        let [memory_start, msize] =
            [step.rw_indices[0], step.rw_indices[1]].map(|idx| block.rws[idx].stack_value());
        let memory_address =
            self.memory_address
                .assign(region, offset, memory_start, msize, block.randomness)?;

        // Memory expansion
        self.memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?;

        let opcode = step.opcode.unwrap();
        let topic_count = (opcode.as_u8() - OpcodeId::LOG0.as_u8()) as usize;
        assert!(topic_count <= 4);

        let mut rws_stack_index = 1;
        for i in 0..4 {
            let mut topic = Word::random_linear_combine([0; 32], block.randomness);
            if i < topic_count {
                rws_stack_index += 1;
                topic = Word::random_linear_combine(
                    block.rws[(RwTableTag::Stack, rws_stack_index)]
                        .stack_value()
                        .to_le_bytes(),
                    block.randomness,
                );
                self.topic_selectors[i].assign(region, offset, Some(F::one()))?;
            } else {
                self.topic_selectors[i].assign(region, offset, Some(F::zero()))?;
            }
            self.topics[i].assign(region, offset, Some(topic))?;
        }

        self.contract_address
            .assign(region, offset, call.callee_address.to_scalar())?;

        self.is_static_call
            .assign(region, offset, Some(F::from(call.is_static as u64)))?;
        self.is_persistent
            .assign(region, offset, Some(F::from(call.is_persistent as u64)))?;
        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::copy_to_log::test::make_log_copy_steps,
        step::ExecutionState,
        table::{CallContextFieldTag, RwTableTag, TxLogFieldTag},
        test::{rand_bytes, run_test_circuit_incomplete_fixed_table},
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };
    use eth_types::{
        evm_types::{gas_utils::memory_expansion_gas_cost, GasCost, OpcodeId},
        ToBigEndian, Word,
    };
    use halo2_proofs::arithmetic::BaseExt;
    use halo2_proofs::pairing::bn256::Fr;
    use std::convert::TryInto;

    // make dynamic byte code sequence base on topics
    fn make_log_byte_code(memory_start: Word, msize: Word, topics: &[Word]) -> Bytecode {
        let mut bytes: Vec<u8> = Vec::new();
        for topic in [topics, &[msize, memory_start]].concat() {
            bytes.push(OpcodeId::PUSH32.as_u8());
            bytes = [bytes, topic.to_be_bytes().to_vec()].concat();
        }

        let codes = [
            OpcodeId::LOG0,
            OpcodeId::LOG1,
            OpcodeId::LOG2,
            OpcodeId::LOG3,
            OpcodeId::LOG4,
        ];
        bytes.push(codes[topics.len()].as_u8());
        bytes.push(OpcodeId::STOP.as_u8());
        Bytecode::new(bytes)
    }

    fn test_ok(memory_start: Word, msize: Word, topics: &[Word], is_persistent: bool) {
        let randomness = Fr::rand();
        let bytecode = make_log_byte_code(memory_start, memory_start, topics);
        let call_id = 1;
        let tx_id = 1;
        let memory_data = rand_bytes(msize.as_usize());
        let contract_address = Word::zero();
        let log_id: usize = 0;
        let mut rws = RwMap(
            [
                (
                    RwTableTag::Stack,
                    vec![
                        Rw::Stack {
                            rw_counter: 1,
                            is_write: false,
                            call_id,
                            stack_pointer: 1015,
                            value: memory_start,
                        },
                        Rw::Stack {
                            rw_counter: 2,
                            is_write: false,
                            call_id,
                            stack_pointer: 1016,
                            value: msize,
                        },
                    ],
                ),
                (
                    RwTableTag::CallContext,
                    vec![
                        Rw::CallContext {
                            rw_counter: 3,
                            is_write: false,
                            call_id,
                            field_tag: CallContextFieldTag::TxId,
                            value: Word::one(),
                        },
                        Rw::CallContext {
                            rw_counter: 4,
                            is_write: false,
                            call_id,
                            field_tag: CallContextFieldTag::IsStatic,
                            value: Word::zero(),
                        },
                        Rw::CallContext {
                            rw_counter: 5,
                            is_write: false,
                            call_id,
                            field_tag: CallContextFieldTag::CalleeAddress,
                            value: contract_address,
                        },
                        Rw::CallContext {
                            rw_counter: 6,
                            is_write: false,
                            call_id,
                            field_tag: CallContextFieldTag::IsPersistent,
                            value: Word::from(is_persistent as u64),
                        },
                    ],
                ),
            ]
            .into(),
        );

        let mut rw_counter = 6;
        let mut stack_pointer = 1016;
        // append dynamic length of topic reads from stack
        let stack_rws: &mut Vec<_> = rws.0.entry(RwTableTag::Stack).or_insert_with(Vec::new);
        let mut txlog_rws: Vec<Rw> = Vec::new();

        if is_persistent {
            rw_counter += 1;
            txlog_rws.push(Rw::TxLog {
                rw_counter,
                is_write: true,
                tx_id,
                log_id: log_id.try_into().unwrap(),
                field_tag: TxLogFieldTag::Address,
                index: 0,
                value: contract_address,
            });
        }

        // rw_counter += 1;
        for (idx, topic) in topics.iter().enumerate() {
            stack_pointer += 1;
            rw_counter += 1;
            stack_rws.push(Rw::Stack {
                rw_counter,
                is_write: false,
                call_id,
                stack_pointer,
                value: *topic,
            });
            if is_persistent {
                rw_counter += 1;
                txlog_rws.push(Rw::TxLog {
                    rw_counter,
                    is_write: true,
                    tx_id,
                    log_id: log_id.try_into().unwrap(),
                    field_tag: TxLogFieldTag::Topic,
                    index: idx,
                    value: *topic,
                });
            }
        }

        rw_counter += 1;
        let log_rws: &mut Vec<_> = rws.0.entry(RwTableTag::TxLog).or_insert_with(Vec::new);
        log_rws.append(&mut txlog_rws);

        // dynamic length of topic writes to TxLog
        let curr_memory_word_size = (memory_start.as_u64() + memory_start.as_u64() + 31) / 32;
        let next_memory_word_size = if msize.is_zero() {
            curr_memory_word_size
        } else {
            std::cmp::max(
                curr_memory_word_size,
                (memory_start.as_u64() + msize.as_u64() + 31) / 32,
            )
        };

        let memory_expension_gas =
            memory_expansion_gas_cost(curr_memory_word_size, next_memory_word_size);
        let topic_count = topics.len();
        // dynamic calculate topic_count
        let gas_cost = GasCost::LOG.as_u64()
            + GasCost::LOG.as_u64() * topic_count as u64
            + 8 * msize.as_u64()
            + memory_expension_gas;
        let codes = [
            OpcodeId::LOG0,
            OpcodeId::LOG1,
            OpcodeId::LOG2,
            OpcodeId::LOG3,
            OpcodeId::LOG4,
        ];
        let program_counter = ((2 + topic_count) * 33) as u64;

        let stack_indices: Vec<(RwTableTag, usize)> = (0..2 + topic_count)
            .map(|idx| (RwTableTag::Stack, idx))
            .collect();
        let log_indices: Vec<(RwTableTag, usize)> = (0..1 + topic_count)
            .map(|idx| (RwTableTag::TxLog, idx))
            .collect();

        let mut steps = vec![ExecStep {
            rw_indices: [
                stack_indices.as_slice(),
                log_indices.as_slice(),
                &[
                    (RwTableTag::CallContext, 0),
                    (RwTableTag::CallContext, 1),
                    (RwTableTag::CallContext, 2),
                    (RwTableTag::CallContext, 3),
                ],
            ]
            .concat(),
            execution_state: ExecutionState::LOG,
            rw_counter: 1,
            program_counter,
            stack_pointer: 1015,
            gas_left: gas_cost,
            gas_cost,
            memory_size: curr_memory_word_size * 32,
            opcode: Some(codes[topic_count]),
            log_id,
            ..Default::default()
        }];

        // memory rows
        if !msize.is_zero() {
            make_log_copy_steps(
                call_id,
                &memory_data,
                memory_start.as_u64(),
                memory_start.as_u64(),
                msize.as_usize(),
                program_counter + 1,
                1015 + (2 + topic_count),
                next_memory_word_size * 32,
                &mut rw_counter,
                &mut rws,
                &mut steps,
                (log_id + 1).try_into().unwrap(),
                is_persistent,
                tx_id,
            );
        }

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter: program_counter + 1,
            stack_pointer: 1015 + (2 + topic_count),
            opcode: Some(OpcodeId::STOP),
            memory_size: next_memory_word_size * 32,
            log_id: is_persistent as usize,
            ..Default::default()
        });

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: tx_id,
                calls: vec![Call {
                    id: call_id,
                    is_root: false,
                    is_create: false,
                    is_persistent,
                    is_static: false,
                    code_source: CodeSource::Account(bytecode.hash),
                    ..Default::default()
                }],
                steps,
                ..Default::default()
            }],
            rws,
            bytecodes: vec![bytecode],
            ..Default::default()
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[ignore]
    #[test]
    fn log_gadget_simple() {
        // is_persistent = true cases
        // log1
        test_ok(Word::from(0x10), Word::from(2), &[Word::from(0xA0)], true);
        // log2
        test_ok(
            Word::from(0x10),
            Word::from(2),
            &[Word::from(0xA0), Word::from(0xef)],
            true,
        );
        // log3
        test_ok(
            Word::from(0x10),
            Word::from(2),
            &[Word::from(0xA0), Word::from(0xef), Word::from(0xb0)],
            true,
        );
        // log4
        test_ok(
            Word::from(0x10),
            Word::from(2),
            &[
                Word::from(0xA0),
                Word::from(0xef),
                Word::from(0xb0),
                Word::from(0x37),
            ],
            true,
        );
        // zero topic: log0
        test_ok(Word::from(0x10), Word::from(2), &[], true);
        // is_persistent = false cases
        // zero topic: log0
        test_ok(Word::from(0x10), Word::from(2), &[], false);
        // log1
        test_ok(Word::from(0x10), Word::from(2), &[Word::from(0xA0)], false);
        // log2
        test_ok(
            Word::from(0x10),
            Word::from(2),
            &[Word::from(0xA0), Word::from(0xef)],
            false,
        );
        // log3
        test_ok(
            Word::from(0x10),
            Word::from(2),
            &[Word::from(0xA0), Word::from(0xef), Word::from(0xb0)],
            false,
        );
        // log4
        test_ok(
            Word::from(0x10),
            Word::from(2),
            &[
                Word::from(0xA0),
                Word::from(0xef),
                Word::from(0xb0),
                Word::from(0x37),
            ],
            false,
        );
    }

    #[ignore]
    #[test]
    fn log_gadget_multi_step() {
        // is_persistent = true cases
        test_ok(
            Word::from(0x10),
            Word::from(128),
            &[Word::from(0x100)],
            true,
        );
        test_ok(
            Word::from(0x10),
            Word::from(128),
            &[Word::from(0xA0), Word::from(0xef)],
            true,
        );
        test_ok(
            Word::from(0x10),
            Word::from(128),
            &[Word::from(0xA0), Word::from(0xef), Word::from(0xb0)],
            true,
        );
        // is_persistent = false cases
        test_ok(
            Word::from(0x10),
            Word::from(128),
            &[Word::from(0x100)],
            false,
        );
        test_ok(
            Word::from(0x10),
            Word::from(128),
            &[Word::from(0xA0), Word::from(0xef)],
            false,
        );
        test_ok(
            Word::from(0x10),
            Word::from(128),
            &[Word::from(0xA0), Word::from(0xef), Word::from(0xb0)],
            false,
        );
    }
}
