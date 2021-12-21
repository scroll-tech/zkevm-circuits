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
            math_gadget::{ComparisonGadget, IsZeroGadget, LtGadget},
            sum, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction, OpcodeExtraData},
    },
    util::Expr,
};
use array_init::array_init;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

const MAX_COPY_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub(crate) struct CopyMemoryToMemoryGadget<F> {
    //same_context: SameContextGadget<F>,
    // The following fields are the states of CopyMemoryToMemory
    // The src memory address to copy from
    src_addr: Cell<F>,
    // The dst memory address to copy to
    dst_addr: Cell<F>,
    // The length to be copied in bytes
    length: Cell<F>,
    // The src address bound of the buffer
    src_addr_bound: Cell<F>,
    // The LT gadget to check if src_addr is less than src_addr_bound
    src_addr_lt_gadget: LtGadget<F, MAX_MEMORY_SIZE_IN_BYTES>,

    // The following fields are used for data copy
    // The bytes that are copied
    bytes: [Cell<F>; MAX_COPY_BYTES],
    // The selectors that indicate if the bytes contain real data
    selectors: [Cell<F>; MAX_COPY_BYTES],
    // The distrance of the addr to the src_addr_bound
    bound_dist: [Cell<F>; MAX_COPY_BYTES],
    // Check if bound_dist is zero
    bound_dist_is_zero: [IsZeroGadget<F>; MAX_COPY_BYTES],
    // The comparison gadget between sum(selectors) and length
    copied_cmp_gadget: ComparisonGadget<F, 4>,
}

impl<F: FieldExt> ExecutionGadget<F> for CopyMemoryToMemoryGadget<F> {
    const NAME: &'static str = "COPYMEMORYTOMEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CopyMemoryToMemory;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let src_addr = cb.query_cell();
        let dst_addr = cb.query_cell();
        let length = cb.query_cell();
        let src_addr_bound = cb.query_cell();

        let bytes = array_init(|_| cb.query_byte());
        let selectors = array_init(|_| cb.query_bool());
        let bound_dist = array_init(|_| cb.query_cell());
        let bound_dist_is_zero = array_init(|idx| {
            IsZeroGadget::construct(cb, bound_dist[idx].expr())
        });

        // Constraints on selectors
        for idx in 0..MAX_COPY_BYTES {
            let selector_prev = if idx == 0 {
                // First selector will always be 1
                1.expr()
            } else {
                selectors[idx - 1].expr()
            };
            // selector can transit from 1 to 0 only once as [1, 1, 1, ...,
            // 0, 0, 0]
            cb.require_boolean(
                "Constrain selector can only transit from 1 to 0",
                selector_prev - selectors[idx].expr(),
            );
            // byte should be 0 when selector is 0
            cb.require_zero(
                "Constrain byte == 0 when selector == 0",
                bytes[idx].expr() * (1.expr() - selectors[idx].expr()),
            );
        }

        // Define bound_dist[i] = max(src_addr_bound - src_addr - i, 0)
        // The purpose of bound_dist is to track if the access to src buffer
        // is out of bound. When bound_dist[i] == 0, it indicates OOB error
        // and so bytes[i] has to be 0 correspondingly.
        // Because the bound_dist is decreasing by at most 1 each time, we can
        // use this property to reduce the use of LtGadget by adding constraints
        // to the diff between two consecutive bound_dists.

        // Constraints on bound_dist[0]
        //   bound_dist[0] == 0 || src_addr + bound_dist[0] == src_addr_bound
        //   src_addr < src_addr_bound when bound_dist[0] != 0
        cb.add_constraint(
            "Constrain bound_dist[0] == 0 or offset+bound_dist[0] == buffer_size",
            bound_dist[0].expr() * (
                src_addr.expr() + bound_dist[0].expr() - src_addr_bound.expr()),
        );
        let src_addr_lt_gadget =
            LtGadget::construct(cb, src_addr.expr(), src_addr_bound.expr());
        cb.add_constraint(
            "Constrain src_addr < src_addr_bound when bound_dist[0] != 0",
            bound_dist_is_zero[0].expr()
                * (1.expr() - src_addr_lt_gadget.expr()),
        );
        // Constraints on bound_dist[1..MAX_COPY_BYTES]
        //   diff == 0 / 1 where diff = bound_dist[idx - 1] - bound_dist[idx]
        //   diff == 1 when bound_dist[idx - 1] != 0
        //   diff == 0 when bound_dist[idx - 1] == 0
        for idx in 1..MAX_COPY_BYTES {
            let diff = bound_dist[idx - 1].expr() - bound_dist[idx].expr();
            cb.require_boolean(
                "Constrain bound_dist[i - 1] - bound_dist[i] == 0 / 1",
                diff.clone(),
            );
            cb.add_constraint(
                "Constrain diff == 1 when bound_dist[i - 1] != 0",
                (1.expr() - bound_dist_is_zero[idx - 1].expr())
                    * (1.expr() - diff.expr()),
            );
            cb.add_constraint(
                "Constrain diff == 0 when bound_dist[i - 1] == 0",
                bound_dist_is_zero[idx - 1].expr() * diff.expr(),
            )
        }

        // Constraints on bytes
        for i in 0..MAX_COPY_BYTES {
            // Read bytes[i] from memory when selectors[i] != 0 &&
            // bound_dist[i] != 0
            cb.condition(
                selectors[i].expr() * (1.expr() - bound_dist_is_zero[i].expr()),
                |cb| {
                    cb.memory_lookup(
                        0.expr(),
                        src_addr.expr() + i.expr(),
                        bytes[i].expr()
                    )
                },
            );
            // Write bytes[i] to memory when selectors[i] != 0
            cb.condition(selectors[i].expr(), |cb| {
                cb.memory_lookup(
                1.expr(),
                dst_addr.expr() + i.expr(),
                bytes[i].expr(),
                )
            });
            cb.add_constraint(
                "Constrain bytes[i] == 0 when selectors[i] == 0",
                (1.expr() - selectors[i].expr()) * bytes[i].expr(),
            );
            cb.add_constraint(
                "Constrain bytes[i] == 0 when bound_dist[i] == 0",
                bound_dist_is_zero[i].expr() * bytes[i].expr(),
            )
        }

        let copied_size = sum::expr(&selectors);
        let copied_cmp_gadget = ComparisonGadget::construct(
            cb, copied_size.clone(), length.expr(),
        );
        let (lt, finished) = copied_cmp_gadget.expr();
        cb.add_constraint(
            "Constrain sum(selectors) <= length",
            lt * finished.clone(),
        );

        // When finished == 0, constraint the states in next step
        let next_opcode = cb.query_cell_next_step();
        let next_src_addr = cb.query_cell_next_step();
        let next_dst_addr = cb.query_cell_next_step();
        let next_length = cb.query_cell_next_step();
        let next_src_addr_bound = cb.query_cell_next_step();
        cb.condition(1.expr() - finished, |cb| {
            cb.add_constraint(
                "Constrain src_addr + copied_size == next_src_addr",
                src_addr.expr() + copied_size.clone() - next_src_addr.expr(),
            );
            cb.add_constraint(
                "Constrain dst_addr + copied_size == next_dst_addr",
                dst_addr.expr() + copied_size.clone() - next_dst_addr.expr(),
            );
            cb.add_constraint(
                "Constrain length == copied_size + next_length",
                length.expr() - copied_size.clone() - next_length.expr(),
            );
            cb.add_constraint(
                "Constrain src_addr_bound == next_src_addr_bound",
                src_addr_bound.expr() - next_src_addr_bound.expr(),
            );
            // cb.add_constraint(
            //     "Constrain next_exec_state == CopyMemoryToMemory",
            //     next_opcode.expr() - ExecutionState::CopyMemoryToMemory.as_u64().expr(),
            // )
        });

        let rw_counter_delta = MAX_COPY_BYTES.expr()
            - sum::expr(bound_dist_is_zero.iter().map(|ex| ex.expr()))
            + sum::expr(&selectors);
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
            length,
            src_addr_bound,
            src_addr_lt_gadget,
            bytes,
            selectors,
            bound_dist,
            bound_dist_is_zero,
            copied_cmp_gadget,
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
            length,
            src_addr_bound,
            selectors,
        } = step.extra_data.as_ref().unwrap();

        self.src_addr.assign(region, offset, Some(F::from(*src_addr)))?;
        self.dst_addr.assign(region, offset, Some(F::from(*dst_addr)))?;
        self.length.assign(region, offset,Some(F::from(*length)))?;
        self.src_addr_bound.assign(
            region,
            offset,
            Some(F::from(*src_addr_bound)),
        )?;
        self.src_addr_lt_gadget.assign(
            region, offset, F::from(*src_addr), F::from(*src_addr_bound),
        )?;

        assert_eq!(selectors.len(), MAX_COPY_BYTES);
        let mut rw_idx = 0;
        for idx in 0..MAX_COPY_BYTES {
            self.selectors[idx].assign(region, offset, Some(F::from(selectors[idx] as u64)))?;
            let oob = *src_addr + idx as u64 >= *src_addr_bound;
            let bound_dist = if oob.clone() {
                F::zero()
            } else {
                F::from(*src_addr_bound - *src_addr - idx as u64)
            };
            self.bound_dist[idx].assign(
                region,
                offset,
                Some(bound_dist),
            )?;
            self.bound_dist_is_zero[idx].assign(
                region,
                offset,
                bound_dist,
            )?;
            let byte = if selectors[idx] == 0 || oob.clone() {
                F::zero()
            } else {
                let b =
                    F::from(block.rws[step.rw_indices[rw_idx]].memory_value() as u64);
                rw_idx += 1;
                b
            };
            self.bytes[idx].assign(region, offset, Some(byte))?;

            if selectors[idx] == 1 {
                // increase rw_idx for write back to memory
                rw_idx += 1
            }
        }

        let num_bytes_copied = selectors.iter().fold(0, |acc, s| acc + (*s as u64));
        self.copied_cmp_gadget.assign(
            region,
            offset,
            F::from(num_bytes_copied),
            F::from(*length),
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
        witness::{Block, Bytecode, Call, ExecStep, Rw, Transaction, OpcodeExtraData},
    };
    use bus_mapping::{
        eth_types::ToLittleEndian,
        evm::OpcodeId,
    };
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;

    fn new_memory_copy_step(
        call_id: usize,
        src_addr: u64,
        dst_addr: u64,
        src_addr_bound: u64,
        length: usize,
        rws: &mut Vec<Rw>,
        rw_counter: usize,
    ) -> ExecStep {
        let mut selectors = vec![0u8; MAX_COPY_BYTES];
        let rw_idx_start = rws.len();
        for idx in 0..MAX_COPY_BYTES {
            if idx < length {
                selectors[idx] = 1;
                let byte = if idx as u64 + src_addr < src_addr_bound {
                    let b = rand_bytes(1)[0];
                    rws.push(Rw::Memory {
                        rw_counter: rw_counter + idx * 2,
                        is_write: false,
                        call_id: call_id,
                        memory_address: src_addr + idx as u64,
                        byte: b,
                    });
                    //println!("{:?}", rws.last());
                    b
                } else {
                    0
                };
                rws.push(Rw::Memory {
                    rw_counter: rw_counter + idx * 2 + 1,
                    is_write: true,
                    call_id: call_id,
                    memory_address: dst_addr + idx as u64,
                    byte: byte,
                });
                //println!("{:?}", rws.last());
            }
        }
        let rw_idx_end = rws.len();
        let extra_data = OpcodeExtraData::CopyMemoryToMemory {
            src_addr: src_addr,
            dst_addr: dst_addr,
            length: length as u64,
            src_addr_bound: src_addr_bound,
            selectors: selectors,
        };
        let step = ExecStep {
            execution_state: ExecutionState::CopyMemoryToMemory,
            rw_indices: (rw_idx_start..rw_idx_end).collect(),
            rw_counter: rw_counter,
            gas_cost: 0,
            extra_data: Some(extra_data),
            ..Default::default()
        };
        step
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
            let step = new_memory_copy_step(
                call_id,
                src_addr + copied as u64,
                dst_addr + copied as u64,
                src_addr_bound,
                length - copied,
                &mut rws,
                rw_counter);
            //println!("step = {:?}", step);
            steps.push(step);
            rw_counter += MAX_COPY_BYTES * 2;
            copied += std::cmp::min(length, MAX_COPY_BYTES);
            //println!("rw_counter = {:?}", rw_counter);
        }

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter: rw_counter,
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
                steps: steps,
                ..Default::default()
            }],
            rws: rws,
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
        test_ok(0x40, 0xA0, 0x45, 8)
    }
}
