use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
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
    },
    util::Expr,
};
use array_init::array_init;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

const MAX_COPY_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub(crate) struct CopyMemoryToMemoryGadget<F> {
    same_context: SameContextGadget<F>,
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
    // The compare gadget between sum(selectors) and length
    copied_comp_gadget: ComparisonGadget<F, 4>,
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
        let copied_comp_gadget = ComparisonGadget::construct(
            cb, copied_size.clone(), length.expr(),
        );
        let (lt, finished) = copied_comp_gadget.expr();
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
            cb.add_constraint(
                "Constrain next_opcode == COPYMEMORYTOMEMORY",
                next_opcode.expr() - ExecutionState::CopyMemoryToMemory.as_u64().expr(),
            )
        });

        let rw_counter_delta = MAX_COPY_BYTES.expr()
            - sum::expr(bound_dist_is_zero.iter().map(|ex| ex.expr()))
            + sum::expr(&selectors);
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(rw_counter_delta),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            src_addr,
            dst_addr,
            length,
            src_addr_bound,
            src_addr_lt_gadget,
            bytes,
            selectors,
            bound_dist,
            bound_dist_is_zero,
            copied_comp_gadget,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{
            Block, Bytecode, Call, ExecStep, Rw, Transaction,
        },
        step::ExecutionState,
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;
}
