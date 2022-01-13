use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::MAX_MEMORY_SIZE_IN_BYTES,
        step::ExecutionState,
        table::TxContextFieldTag,
        util::{
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            math_gadget::ComparisonGadget,
            memory_gadget::BufferGetDataGadget,
            Cell,
        },
        witness::{Block, Call, ExecStep, OpcodeExtraData, Transaction},
    },
    util::Expr,
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

const MAX_COPY_BYTES: usize = 39;

/// Multi-step gadget for copying data from memory or Tx calldata to memory
#[derive(Clone, Debug)]
pub(crate) struct CopyToMemoryGadget<F> {
    // The src memory address to copy from
    src_addr: Cell<F>,
    // The dst memory address to copy to
    dst_addr: Cell<F>,
    // The number of bytes left to copy
    bytes_left: Cell<F>,
    // The src address bound of the buffer
    src_addr_end: Cell<F>,
    // Indicate whether src is from Tx Calldata
    from_tx: Cell<F>,
    // Transaction ID, optional, only used when src_is_tx == 1
    tx_id: Cell<F>,
    // Buffer get data gadget
    buffer_get_data:
        BufferGetDataGadget<F, MAX_COPY_BYTES, MAX_MEMORY_SIZE_IN_BYTES>,
    // The comparison gadget between num bytes copied and bytes_left
    finish_gadget: ComparisonGadget<F, 4>,
}

impl<F: FieldExt> ExecutionGadget<F> for CopyToMemoryGadget<F> {
    const NAME: &'static str = "COPYTOMEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CopyToMemory;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let src_addr = cb.query_cell();
        let dst_addr = cb.query_cell();
        let bytes_left = cb.query_cell();
        let src_addr_end = cb.query_cell();
        let from_tx = cb.query_bool();
        let tx_id = cb.query_cell();
        let buffer_get_data =
            BufferGetDataGadget::construct(cb, &src_addr, &src_addr_end);

        let from_memory = 1.expr() - from_tx.expr();
        let rw_counter = cb.curr.state.rw_counter.expr();
        let mut rw_counter_offset = 0.expr();
        // Copy bytes from src and dst
        for i in 0..MAX_COPY_BYTES {
            let read_flag = buffer_get_data.read_from_buffer(i);
            // Read bytes[i] from memory
            cb.condition(from_memory.clone() * read_flag.clone(), |cb| {
                cb.memory_lookup_with_counter(
                    rw_counter.clone() + rw_counter_offset.clone(),
                    0.expr(),
                    src_addr.expr() + i.expr(),
                    buffer_get_data.byte(i),
                )
            });
            rw_counter_offset =
                rw_counter_offset + from_memory.clone() * read_flag.clone();
            // Read bytes[i] from Tx
            cb.condition(from_tx.expr() * read_flag.clone(), |cb| {
                cb.tx_context_lookup(
                    tx_id.expr(),
                    TxContextFieldTag::CallData,
                    Some(src_addr.expr() + i.expr()),
                    buffer_get_data.byte(i),
                )
            });
            // Write bytes[i] to memory when selectors[i] != 0
            cb.condition(buffer_get_data.has_data(i), |cb| {
                cb.memory_lookup_with_counter(
                    rw_counter.clone() + rw_counter_offset.clone(),
                    1.expr(),
                    dst_addr.expr() + i.expr(),
                    buffer_get_data.byte(i),
                )
            });
            rw_counter_offset = rw_counter_offset + buffer_get_data.has_data(i);
        }

        let copied_size = buffer_get_data.num_bytes();
        let finish_gadget = ComparisonGadget::construct(
            cb,
            copied_size.clone(),
            bytes_left.expr(),
        );
        let (lt, finished) = finish_gadget.expr();
        cb.add_constraint(
            "Constrain num_bytes <= bytes_left",
            lt * finished.clone(),
        );

        // When finished == 0, constraint the CopyToMemory state in next step
        let next_src_addr = cb.query_cell_next_step();
        let next_dst_addr = cb.query_cell_next_step();
        let next_bytes_left = cb.query_cell_next_step();
        let next_src_addr_end = cb.query_cell_next_step();
        let next_from_tx = cb.query_cell_next_step();
        let next_tx_id = cb.query_cell_next_step();
        cb.condition(1.expr() - finished.clone(), |cb| {
            cb.require_next_state(ExecutionState::CopyToMemory);
            cb.add_constraint(
                "src_addr + copied_size == next_src_addr",
                src_addr.expr() + copied_size.clone() - next_src_addr.expr(),
            );
            cb.add_constraint(
                "dst_addr + copied_size == next_dst_addr",
                dst_addr.expr() + copied_size.clone() - next_dst_addr.expr(),
            );
            cb.add_constraint(
                "length == copied_size + next_length",
                bytes_left.expr()
                    - copied_size.clone()
                    - next_bytes_left.expr(),
            );
            cb.add_constraint(
                "src_addr_bound == next_src_addr_bound",
                src_addr_end.expr() - next_src_addr_end.expr(),
            );
            cb.add_constraint(
                "from_tx == next_from_tx",
                from_tx.expr() - next_from_tx.expr(),
            );
            cb.add_constraint(
                "tx_id == next_tx_id",
                tx_id.expr() - next_tx_id.expr(),
            );
        });

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(rw_counter_offset),
            program_counter: Delta(finished),
            ..Default::default()
        };
        cb.require_step_state_transition(step_state_transition);

        Self {
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            from_tx,
            tx_id,
            buffer_get_data,
            finish_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let OpcodeExtraData::CopyToMemory {
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            from_tx,
            selectors,
        } = step.extra_data.as_ref().unwrap();

        self.src_addr
            .assign(region, offset, Some(F::from(*src_addr)))?;
        self.dst_addr
            .assign(region, offset, Some(F::from(*dst_addr)))?;
        self.bytes_left
            .assign(region, offset, Some(F::from(*bytes_left)))?;
        self.src_addr_end.assign(
            region,
            offset,
            Some(F::from(*src_addr_end)),
        )?;
        self.from_tx
            .assign(region, offset, Some(F::from(*from_tx as u64)))?;
        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;

        // Retrieve the bytes
        assert_eq!(selectors.len(), MAX_COPY_BYTES);
        let mut rw_idx = 0;
        let mut bytes = vec![0u8; MAX_COPY_BYTES];
        for (idx, selector) in selectors.iter().enumerate() {
            let addr = *src_addr as usize + idx;
            bytes[idx] = if *selector == 1 && addr < *src_addr_end as usize {
                if *from_tx {
                    assert!(addr < tx.call_data.len());
                    println!("calldata[{}] = {}", idx, tx.call_data[addr]);
                    tx.call_data[addr]
                } else {
                    rw_idx += 1;
                    block.rws[step.rw_indices[rw_idx]].memory_value()
                }
            } else {
                0
            };
            if *selector == 1 {
                // increase rw_idx for write back to memory
                rw_idx += 1
            }
        }

        self.buffer_get_data.assign(
            region,
            offset,
            *src_addr,
            *src_addr_end,
            &bytes,
            selectors,
        )?;

        let num_bytes_copied =
            selectors.iter().fold(0, |acc, s| acc + (*s as u64));
        self.finish_gadget.assign(
            region,
            offset,
            F::from(num_bytes_copied),
            F::from(*bytes_left),
        )?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use crate::evm_circuit::{
        execution::memory_copy::MAX_COPY_BYTES,
        step::ExecutionState,
        test::{rand_bytes, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
        witness::{
            Block, Bytecode, Call, ExecStep, OpcodeExtraData, Rw, Transaction,
        },
    };
    use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;
    use std::collections::HashMap;

    #[allow(clippy::too_many_arguments)]
    fn make_memory_copy_step(
        call_id: usize,
        src_addr: u64,
        dst_addr: u64,
        src_addr_end: u64,
        bytes_left: usize,
        from_tx: bool,
        program_counter: u64,
        stack_pointer: usize,
        rw_counter: usize,
        rws: &mut Vec<Rw>,
        bytes_map: &HashMap<u64, u8>,
    ) -> (ExecStep, usize) {
        let mut selectors = vec![0u8; MAX_COPY_BYTES];
        let mut rw_offset: usize = 0;
        let rw_idx_start = rws.len();
        for (idx, selector) in selectors.iter_mut().enumerate() {
            if idx < bytes_left {
                *selector = 1;
                let addr = src_addr + idx as u64;
                let byte = if addr < src_addr_end {
                    assert!(bytes_map.contains_key(&addr));
                    if !from_tx {
                        rws.push(Rw::Memory {
                            rw_counter: rw_counter + rw_offset,
                            is_write: false,
                            call_id,
                            memory_address: src_addr + idx as u64,
                            byte: bytes_map[&addr],
                        });
                        rw_offset += 1;
                        println!("{:?}", rws.last());
                    }
                    bytes_map[&addr]
                } else {
                    0
                };
                rws.push(Rw::Memory {
                    rw_counter: rw_counter + rw_offset,
                    is_write: true,
                    call_id,
                    memory_address: dst_addr + idx as u64,
                    byte,
                });
                println!("{:?}", rws.last());
                rw_offset += 1;
            }
        }
        let rw_idx_end = rws.len();
        let extra_data = OpcodeExtraData::CopyToMemory {
            src_addr,
            dst_addr,
            bytes_left: bytes_left as u64,
            src_addr_end,
            from_tx,
            selectors,
        };
        let step = ExecStep {
            execution_state: ExecutionState::CopyToMemory,
            rw_indices: (rw_idx_start..rw_idx_end).collect(),
            rw_counter,
            program_counter,
            stack_pointer,
            gas_cost: 0,
            extra_data: Some(extra_data),
            ..Default::default()
        };
        (step, rw_offset)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn make_memory_copy_steps(
        call_id: usize,
        buffer: &[u8],
        buffer_addr: u64,
        src_addr: u64,
        dst_addr: u64,
        length: usize,
        from_tx: bool,
        program_counter: u64,
        stack_pointer: usize,
        rw_counter: &mut usize,
        rws: &mut Vec<Rw>,
        steps: &mut Vec<ExecStep>,
    ) {
        let buffer_addr_end = buffer_addr + buffer.len() as u64;
        let bytes_map = (buffer_addr..buffer_addr_end)
            .zip(buffer.iter().copied())
            .collect();
        println!("buffer_addr = {}", buffer_addr);
        println!("buffer_addr_end = {}", buffer_addr_end);
        println!("src_addr = {}", src_addr);
        println!("{:?}", bytes_map);

        let mut copied = 0;
        while copied < length {
            println!("src_addr = {}", src_addr + copied as u64);
            println!("dst_addr = {}", dst_addr + copied as u64);
            println!("length = {}", length - copied);
            let (step, rw_offset) = make_memory_copy_step(
                call_id,
                src_addr + copied as u64,
                dst_addr + copied as u64,
                buffer_addr_end,
                length - copied,
                from_tx,
                program_counter,
                stack_pointer,
                *rw_counter,
                rws,
                &bytes_map,
            );
            println!("step = {:?}", step);
            steps.push(step);
            *rw_counter += rw_offset;
            copied += MAX_COPY_BYTES;
            //println!("rw_counter = {:?}", rw_counter);
        }
    }

    fn test_ok_from_memory(
        src_addr: u64,
        dst_addr: u64,
        src_addr_end: u64,
        length: usize,
    ) {
        let randomness = Fp::rand();
        let bytecode =
            Bytecode::new(vec![OpcodeId::STOP.as_u8(), OpcodeId::STOP.as_u8()]);
        let call_id = 1;
        let mut rws = Vec::new();
        let mut rw_counter = 1;
        let mut steps = Vec::new();
        let buffer = rand_bytes((src_addr_end - src_addr) as usize);

        make_memory_copy_steps(
            call_id,
            &buffer,
            src_addr,
            src_addr,
            dst_addr,
            length,
            false,
            0,
            1024,
            &mut rw_counter,
            &mut rws,
            &mut steps,
        );

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter: 1,
            stack_pointer: 1024,
            opcode: Some(OpcodeId::STOP),
            ..Default::default()
        });
        //println!("step = {:?}", steps.last());

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                calls: vec![Call {
                    id: call_id,
                    is_root: true,
                    is_create: false,
                    opcode_source:
                        RandomLinearCombination::random_linear_combine(
                            bytecode.hash.to_le_bytes(),
                            randomness,
                        ),
                    ..Default::default()
                }],
                steps,
                ..Default::default()
            }],
            rws,
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    fn test_ok_from_tx(
        calldata_length: usize,
        src_addr: u64,
        dst_addr: u64,
        length: usize,
    ) {
        let randomness = Fp::rand();
        let bytecode =
            Bytecode::new(vec![OpcodeId::STOP.as_u8(), OpcodeId::STOP.as_u8()]);
        let call_id = 1;
        let mut rws = Vec::new();
        let mut rw_counter = 1;
        let calldata = rand_bytes(calldata_length);
        let mut steps = Vec::new();
        println!("calldata_length = {}", calldata_length);
        println!("calldata = {:?}", calldata);
        println!("src_addr = {}", src_addr);
        println!("dst_addr = {}", dst_addr);

        make_memory_copy_steps(
            call_id,
            &calldata,
            0,
            src_addr,
            dst_addr,
            length,
            true,
            0,
            1024,
            &mut rw_counter,
            &mut rws,
            &mut steps,
        );

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter: 1,
            stack_pointer: 1024,
            opcode: Some(OpcodeId::STOP),
            ..Default::default()
        });

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                call_data: calldata,
                call_data_length: calldata_length,
                calls: vec![Call {
                    id: call_id,
                    is_root: true,
                    is_create: false,
                    opcode_source:
                        RandomLinearCombination::random_linear_combine(
                            bytecode.hash.to_le_bytes(),
                            randomness,
                        ),
                    ..Default::default()
                }],
                steps,
                ..Default::default()
            }],
            rws,
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn copy_to_memory_simple() {
        test_ok_from_memory(0x40, 0xA0, 0x70, 5);
        test_ok_from_tx(32, 5, 0x40, 5);
    }

    #[test]
    fn copy_to_memory_multi_step() {
        test_ok_from_memory(0x40, 0xA0, 0x80, 50);
        test_ok_from_tx(128, 10, 0x40, 90);
    }

    #[test]
    fn copy_to_memory_out_of_bound() {
        test_ok_from_memory(0x40, 0xA0, 0x60, 45);
        test_ok_from_tx(32, 5, 0x40, 45);
    }
}
