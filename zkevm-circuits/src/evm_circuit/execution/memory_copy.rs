use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::MAX_MEMORY_SIZE_IN_BYTES,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            math_gadget::{ComparisonGadget},
            memory_gadget::BufferGetDataGadget,
            sum, Cell,
        },
        witness::{Block, Call, ExecStep, OpcodeExtraData, Transaction},
    },
    util::Expr,
};
use array_init::array_init;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

const MAX_COPY_BYTES: usize = 40;

#[derive(Clone, Debug)]
pub(crate) struct CopyMemoryToMemoryGadget<F> {
    //same_context: SameContextGadget<F>,
    // The src memory address to copy from
    src_addr: Cell<F>,
    // The dst memory address to copy to
    dst_addr: Cell<F>,
    // The number of bytes left to copy
    bytes_left: Cell<F>,
    // The src address bound of the buffer
    src_addr_end: Cell<F>,
    //
    buffer_get_data: BufferGetDataGadget<F, MAX_COPY_BYTES, MAX_MEMORY_SIZE_IN_BYTES>,
    // The comparison gadget between num bytes copied and bytes_left
    finish_gadget: ComparisonGadget<F, 4>,
}

impl<F: FieldExt> ExecutionGadget<F> for CopyMemoryToMemoryGadget<F> {
    const NAME: &'static str = "COPYMEMORYTOMEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CopyMemoryToMemory;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let src_type = cb.query_cell();
        let src_addr = cb.query_cell();
        let dst_addr = cb.query_cell();
        let bytes_left = cb.query_cell();
        let src_addr_end = cb.query_cell();
        let buffer_get_data = BufferGetDataGadget::construct(
            cb, &src_addr, &src_addr_end,
        );

        let rw_counter = cb.curr.state.rw_counter.expr();
        let mut rw_counter_offset = 0.expr();
        // Copy bytes from src and dst
        for i in 0..MAX_COPY_BYTES {
            let read_flag = buffer_get_data.read_from_buffer(i);
            // Read bytes[i] from memory when selectors[i] != 0 &&
            // bound_dist[i] != 0
            cb.condition(read_flag.clone(), |cb| {
                cb.memory_lookup_with_counter(
                    rw_counter.clone() + rw_counter_offset.clone(),
                    0.expr(),
                    src_addr.expr() + i.expr(),
                    buffer_get_data.byte(i),
                )
            });
            rw_counter_offset = rw_counter_offset + read_flag;
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
        let finish_gadget =
            ComparisonGadget::construct(cb, copied_size.clone(), bytes_left.expr());
        let (lt, finished) = finish_gadget.expr();
        cb.add_constraint(
            "Constrain num_bytes <= bytes_left",
            lt * finished.clone(),
        );

        // When finished == 0, constraint the states in next step
        let next_opcode = cb.query_cell_next_step();
        let next_src_addr = cb.query_cell_next_step();
        let next_dst_addr = cb.query_cell_next_step();
        let next_bytes_left = cb.query_cell_next_step();
        let next_src_addr_end = cb.query_cell_next_step();
        cb.condition(1.expr() - finished, |cb| {
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
                bytes_left.expr() - copied_size.clone() - next_bytes_left.expr(),
            );
            cb.add_constraint(
                "src_addr_bound == next_src_addr_bound",
                src_addr_end.expr() - next_src_addr_end.expr(),
            );
            // cb.add_constraint(
            //     "next_exec_state == CopyMemoryToMemory",
            //     next_opcode.expr() - ExecutionState::CopyMemoryToMemory.as_u64().expr(),
            // )
        });

        // let step_state_transition = StepStateTransition {
        //     rw_counter: Delta(rw_counter_delta),
        //     ..Default::default()
        // };
        // let same_context = SameContextGadget::construct(
        //     cb,
        //     opcode,
        //     step_state_transition,
        //     None,
        // );

        Self {
            //same_context,
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            buffer_get_data,
            finish_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        //self.same_context.assign_exec_step(region, offset, step)?;
        let OpcodeExtraData::CopyMemoryToMemory {
            src_addr,
            dst_addr,
            bytes_left,
            src_addr_end,
            selectors,
        } = step.extra_data.as_ref().unwrap();

        self.src_addr
            .assign(region, offset, Some(F::from(*src_addr)))?;
        self.dst_addr
            .assign(region, offset, Some(F::from(*dst_addr)))?;
        self.bytes_left.assign(region, offset, Some(F::from(*bytes_left)))?;
        self.src_addr_end.assign(
            region,
            offset,
            Some(F::from(*src_addr_end)),
        )?;

        assert_eq!(selectors.len(), MAX_COPY_BYTES);
        let mut rw_idx = 0;
        let mut bytes = vec![0u8; MAX_COPY_BYTES];
        for (idx, selector) in selectors.iter().enumerate() {
            let oob = *src_addr + idx as u64 >= *src_addr_end;
            bytes[idx] = if *selector == 0 || oob {
                0
            } else {
                let b = block.rws[step.rw_indices[rw_idx]].memory_value();
                rw_idx += 1;
                b
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
mod test {
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

    fn new_memory_copy_step(
        call_id: usize,
        src_addr: u64,
        dst_addr: u64,
        src_addr_end: u64,
        bytes_left: usize,
        rws: &mut Vec<Rw>,
        rw_counter: usize,
    ) -> (ExecStep, usize) {
        let mut selectors = vec![0u8; MAX_COPY_BYTES];
        let mut rw_offset: usize = 0;
        let rw_idx_start = rws.len();
        for (idx, selector) in selectors.iter_mut().enumerate() {
            if idx < bytes_left {
                *selector = 1;
                let byte = if idx as u64 + src_addr < src_addr_end {
                    let b = rand_bytes(1)[0];
                    rws.push(Rw::Memory {
                        rw_counter: rw_counter + rw_offset,
                        is_write: false,
                        call_id,
                        memory_address: src_addr + idx as u64,
                        byte: b,
                    });
                    rw_offset += 1;
                    //println!("{:?}", rws.last());
                    b
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
                //println!("{:?}", rws.last());
                rw_offset += 1;
            }
        }
        let rw_idx_end = rws.len();
        let extra_data = OpcodeExtraData::CopyMemoryToMemory {
            src_addr,
            dst_addr,
            bytes_left: bytes_left as u64,
            src_addr_end,
            selectors,
        };
        let step = ExecStep {
            execution_state: ExecutionState::CopyMemoryToMemory,
            rw_indices: (rw_idx_start..rw_idx_end).collect(),
            rw_counter,
            gas_cost: 0,
            extra_data: Some(extra_data),
            ..Default::default()
        };
        (step, rw_offset)
    }

    fn test_ok(
        src_addr: u64,
        dst_addr: u64,
        src_addr_bound: u64,
        length: usize,
    ) {
        let randomness = Fp::rand();
        let bytecode = Bytecode::new(vec![OpcodeId::STOP.as_u8()]);
        let call_id = 1;
        let mut rws = Vec::new();
        let mut rw_counter = 1;
        let mut steps = Vec::new();
        let mut copied = 0;

        while copied < length {
            println!("src_addr = {}", src_addr + copied as u64);
            println!("dst_addr = {}", src_addr + copied as u64);
            println!("length = {}", length - copied);
            let (step, rw_offset) = new_memory_copy_step(
                call_id,
                src_addr + copied as u64,
                dst_addr + copied as u64,
                src_addr_bound,
                length - copied,
                &mut rws,
                rw_counter,
            );
            //println!("step = {:?}", step);
            steps.push(step);
            rw_counter += rw_offset;
            copied += std::cmp::min(length, MAX_COPY_BYTES);
            //println!("rw_counter = {:?}", rw_counter);
        }

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter: 0,
            stack_pointer: 1024,
            opcode: Some(OpcodeId::STOP),
            ..Default::default()
        });

        let block = Block {
            randomness,
            txs: vec![Transaction {
                calls: vec![Call {
                    id: call_id,
                    is_root: true,
                    is_create: false,
                    opcode_source:
                        RandomLinearCombination::random_linear_combine(
                            bytecode.hash.to_le_bytes(),
                            randomness,
                        ),
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
    fn memory_copy_simple() {
        test_ok(0x40, 0xA0, 0x70, 5)
    }

    #[test]
    fn memory_copy_multi_step() {
        test_ok(0x40, 0xA0, 0x70, 43)
    }

    #[test]
    fn memory_copy_out_of_bound() {
        test_ok(0x40, 0xA0, 0x45, 43)
    }
}
