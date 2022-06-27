use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        table::TxLogFieldTag,
        util::{
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::ComparisonGadget,
            memory_gadget::BufferReaderGadget,
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDetails, constants::MAX_COPY_BYTES};
use eth_types::Field;
use halo2_proofs::plonk::Error;

/// Multi-step gadget for copying data from memory to RW log
#[derive(Clone, Debug)]
pub(crate) struct CopyToLogGadget<F> {
    // The src memory address to copy from
    src_addr: Cell<F>,
    // The number of bytes left to copy
    bytes_left: Cell<F>,
    // The src address bound of the buffer
    src_addr_end: Cell<F>,
    // the call is persistent or not
    is_persistent: Cell<F>,
    // The tx id
    tx_id: Cell<F>,
    // the log data start index fetched from last step
    data_start_index: Cell<F>,
    // Buffer reader gadget
    buffer_reader: BufferReaderGadget<F, MAX_COPY_BYTES, N_BYTES_MEMORY_ADDRESS>,
    // The comparison gadget between num bytes copied and bytes_left
    finish_gadget: ComparisonGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for CopyToLogGadget<F> {
    const NAME: &'static str = "CopyToLogGadget";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CopyToLog;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let src_addr = cb.query_cell();
        let bytes_left = cb.query_cell();
        let src_addr_end = cb.query_cell();
        let is_persistent = cb.query_bool();
        let tx_id = cb.query_cell();
        let data_start_index = cb.query_cell();
        let buffer_reader = BufferReaderGadget::construct(cb, src_addr.expr(), src_addr_end.expr());

        // Copy bytes from src and dst
        for i in 0..MAX_COPY_BYTES {
            let read_flag = buffer_reader.read_flag(i);
            // Read bytes[i] from memory
            cb.condition(read_flag.clone(), |cb| {
                cb.memory_lookup(
                    0.expr(),
                    src_addr.expr() + i.expr(),
                    buffer_reader.byte(i),
                    None,
                )
            });

            // Write bytes[i] to log when selectors[i] != 0 and is_persistent = true
            cb.condition(buffer_reader.has_data(i) * is_persistent.expr(), |cb| {
                cb.tx_log_lookup(
                    tx_id.expr(),
                    cb.curr.state.log_id.expr(),
                    TxLogFieldTag::Data,
                    data_start_index.expr() + i.expr(),
                    buffer_reader.byte(i),
                )
            });
        }

        let copied_size = buffer_reader.num_bytes();
        let finish_gadget = ComparisonGadget::construct(cb, copied_size.clone(), bytes_left.expr());
        let (lt, finished) = finish_gadget.expr();
        // Constrain lt == 1 or finished == 1
        cb.add_constraint(
            "Constrain num_bytes <= bytes_left",
            (1.expr() - lt) * (1.expr() - finished.clone()),
        );

        // When finished == 0, constraint the CopyToLog state in next step
        cb.constrain_next_step(ExecutionState::CopyToLog, Some(1.expr() - finished), |cb| {
            let next_src_addr = cb.query_cell();
            let next_bytes_left = cb.query_cell();
            let next_src_addr_end = cb.query_cell();
            let next_is_persistent = cb.query_bool();
            let next_tx_id = cb.query_cell();
            let next_data_start_index = cb.query_cell();

            cb.require_equal(
                "next_src_addr == src_addr + copied_size",
                next_src_addr.expr(),
                src_addr.expr() + copied_size.clone(),
            );

            cb.require_equal(
                "next_bytes_left == bytes_left - copied_size",
                next_bytes_left.expr(),
                bytes_left.expr() - copied_size.clone(),
            );
            cb.require_equal(
                "next_src_addr_end == src_addr_end",
                next_src_addr_end.expr(),
                src_addr_end.expr(),
            );
            cb.require_equal(
                "next_is_persistent == is_persistent",
                next_is_persistent.expr(),
                is_persistent.expr(),
            );
            cb.require_equal("next_tx_id == tx_id", next_tx_id.expr(), tx_id.expr());
            cb.require_equal(
                "next_data_start_index == data_start_index + MAX_COPY_BYTES
                ",
                next_data_start_index.expr(),
                data_start_index.expr() + MAX_COPY_BYTES.expr(),
            );
        });

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            ..Default::default()
        };
        cb.require_step_state_transition(step_state_transition);

        Self {
            src_addr,
            bytes_left,
            src_addr_end,
            is_persistent,
            tx_id,
            data_start_index,
            buffer_reader,
            finish_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        // Read the auxiliary data.
        let aux = if step.aux_data.is_none() {
            // TODO: Handle error correctly returning err
            unreachable!("could not find aux_data for this step")
        } else {
            step.aux_data.unwrap()
        };

        // log won't use dst_addr
        assert!(aux.dst_addr() == 0u64);
        let (is_persistent, tx_id, data_start_index) = match aux.copy_details() {
            CopyDetails::Log((is_persistent, tx_id, data_index)) => {
                (is_persistent, tx_id, data_index)
            }
            _ => unreachable!("the data copy is not related to a LOG op"),
        };

        self.src_addr
            .assign(region, offset, Some(F::from(aux.src_addr())))?;
        self.bytes_left
            .assign(region, offset, Some(F::from(aux.bytes_left())))?;
        self.src_addr_end
            .assign(region, offset, Some(F::from(aux.src_addr_end())))?;
        self.is_persistent
            .assign(region, offset, Some(F::from(is_persistent as u64)))?;
        self.tx_id
            .assign(region, offset, Some(F::from(tx_id as u64)))?;
        self.data_start_index
            .assign(region, offset, Some(F::from(data_start_index as u64)))?;
        // Retrieve the bytes and selectors

        let mut rw_idx = 0;
        let mut bytes = vec![0u8; MAX_COPY_BYTES];
        let mut selectors = vec![false; MAX_COPY_BYTES];

        for idx in 0..std::cmp::min(aux.bytes_left() as usize, MAX_COPY_BYTES) {
            let src_addr = aux.src_addr() as usize + idx;
            selectors[idx] = true;
            bytes[idx] = if selectors[idx] && src_addr < aux.src_addr_end() as usize {
                let index = step.rw_indices[rw_idx];
                if is_persistent {
                    rw_idx += 2;
                } else {
                    rw_idx += 1;
                }

                block.rws[index].memory_value()
            } else {
                0
            };
        }

        self.buffer_reader.assign(
            region,
            offset,
            aux.src_addr(),
            aux.src_addr_end(),
            &bytes,
            &selectors,
        )?;

        let num_bytes_copied = std::cmp::min(aux.bytes_left(), MAX_COPY_BYTES as u64);
        self.finish_gadget.assign(
            region,
            offset,
            F::from(num_bytes_copied),
            F::from(aux.bytes_left()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use crate::evm_circuit::{
        step::ExecutionState,
        table::{RwTableTag, TxLogFieldTag},
        test::{rand_bytes, run_test_circuit_incomplete_fixed_table},
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };
    use crate::util::DEFAULT_RAND;
    use bus_mapping::{
        circuit_input_builder::{CopyDetails, StepAuxiliaryData},
        constants::MAX_COPY_BYTES,
    };
    use eth_types::{evm_types::OpcodeId, Word};
    use halo2_proofs::arithmetic::FieldExt;
    use halo2_proofs::pairing::bn256::Fr;
    use std::collections::HashMap;
    use std::convert::TryInto;

    #[allow(clippy::too_many_arguments)]
    fn make_log_copy_step(
        call_id: usize,
        src_addr: u64,
        src_addr_end: u64,
        bytes_left: usize,
        data_start_index: usize,
        program_counter: u64,
        stack_pointer: usize,
        memory_size: u64,
        rw_counter: usize,
        rws: &mut RwMap,
        bytes_map: &HashMap<u64, u8>,
        log_id: u64,
        is_persistent: bool,
        tx_id: usize,
    ) -> (ExecStep, usize) {
        let mut selectors = vec![0u8; MAX_COPY_BYTES];
        let mut rw_offset: usize = 0;
        let memory_rws: &mut Vec<_> = rws.0.entry(RwTableTag::Memory).or_insert_with(Vec::new);
        let mut txlog_rws: Vec<Rw> = Vec::new();
        let mut rw_indices: Vec<(RwTableTag, usize)> = Vec::new();
        let mut memory_index = 0;
        let mut log_data_index = 0;

        for (idx, selector) in selectors.iter_mut().enumerate() {
            if idx < bytes_left {
                *selector = 1;
                let addr = src_addr + idx as u64;
                let byte = if addr < src_addr_end {
                    assert!(bytes_map.contains_key(&addr));
                    memory_rws.push(Rw::Memory {
                        rw_counter: rw_counter + rw_offset,
                        is_write: false,
                        call_id,
                        memory_address: src_addr + idx as u64,
                        byte: bytes_map[&addr],
                    });
                    rw_indices.push((RwTableTag::Memory, memory_index + data_start_index));
                    memory_index += 1;
                    rw_offset += 1;
                    bytes_map[&addr]
                } else {
                    0
                };
                if is_persistent {
                    txlog_rws.push(Rw::TxLog {
                        rw_counter: rw_counter + rw_offset,
                        is_write: true,
                        tx_id,
                        log_id,
                        field_tag: TxLogFieldTag::Data,
                        index: data_start_index + idx,
                        value: Word::from(byte),
                    });
                    rw_indices.push((RwTableTag::TxLog, log_data_index + data_start_index));
                    log_data_index += 1;
                    rw_offset += 1;
                }
            }
        }
        let log_rws: &mut Vec<_> = rws.0.entry(RwTableTag::TxLog).or_insert_with(Vec::new);
        log_rws.extend(txlog_rws);

        let aux_data = StepAuxiliaryData::new(
            src_addr,
            Default::default(),
            bytes_left as u64,
            src_addr_end,
            CopyDetails::Log((is_persistent, tx_id, data_start_index)),
        );

        let step = ExecStep {
            execution_state: ExecutionState::CopyToLog,
            rw_indices,
            rw_counter,
            program_counter,
            stack_pointer,
            memory_size,
            gas_cost: 0,
            log_id: if is_persistent {
                log_id.try_into().unwrap()
            } else {
                0
            },
            aux_data: Some(aux_data),
            ..Default::default()
        };
        (step, rw_offset)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn make_log_copy_steps(
        call_id: usize,
        buffer: &[u8],
        buffer_addr: u64,
        src_addr: u64,
        length: usize,
        program_counter: u64,
        stack_pointer: usize,
        memory_size: u64,
        rw_counter: &mut usize,
        rws: &mut RwMap,
        steps: &mut Vec<ExecStep>,
        log_id: u64,
        is_persistent: bool,
        tx_id: usize,
    ) {
        let buffer_addr_end = buffer_addr + buffer.len() as u64;
        let bytes_map = (buffer_addr..buffer_addr_end)
            .zip(buffer.iter().copied())
            .collect();

        let mut copied = 0;
        while copied < length {
            let (step, rw_offset) = make_log_copy_step(
                call_id,
                src_addr + copied as u64,
                buffer_addr_end,
                length - copied,
                copied,
                program_counter,
                stack_pointer,
                memory_size,
                *rw_counter,
                rws,
                &bytes_map,
                log_id,
                is_persistent,
                tx_id,
            );
            steps.push(step);
            *rw_counter += rw_offset;
            copied += MAX_COPY_BYTES;
        }
    }

    fn test_ok_copy_to_log(src_addr: u64, src_addr_end: u64, length: usize, is_persistent: bool) {
        let randomness = Fr::from_u128(DEFAULT_RAND);
        let bytecode = Bytecode::new(vec![OpcodeId::STOP.as_u8()]);
        let call_id = 1;
        let mut rws = RwMap(Default::default());
        let mut rw_counter = 1;
        let mut steps = Vec::new();
        let tx_id = 1;
        let log_id = 0;
        let buffer = rand_bytes((src_addr_end - src_addr) as usize);
        let memory_size = (src_addr + length as u64 + 31) / 32 * 32;

        make_log_copy_steps(
            call_id,
            &buffer,
            src_addr,
            src_addr,
            length,
            0,
            1023,
            memory_size,
            &mut rw_counter,
            &mut rws,
            &mut steps,
            log_id,
            is_persistent,
            tx_id,
        );

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter: 0,
            stack_pointer: 1023,
            memory_size,
            opcode: Some(OpcodeId::STOP),
            ..Default::default()
        });

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                calls: vec![Call {
                    id: call_id,
                    is_root: false,
                    is_create: false,
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

    #[test]
    fn copy_to_log_simple() {
        // is_persistent = true
        test_ok_copy_to_log(0x10, 0x30, 0x2, true);
        test_ok_copy_to_log(0x100, 0x180, 0x40, true);
        // is_persistent = false
        test_ok_copy_to_log(0x10, 0x30, 0x2, false);
        test_ok_copy_to_log(0x100, 0x180, 0x40, false);
    }

    #[ignore = "skip"]
    #[test]
    fn copy_to_log_multi_step() {
        // is_persistent = true
        test_ok_copy_to_log(0x20, 0xA0, 80, true);
        test_ok_copy_to_log(0x10, 0xA0, 160, true);
        // is_persistent = false
        test_ok_copy_to_log(0x20, 0xA0, 80, false);
    }
}
