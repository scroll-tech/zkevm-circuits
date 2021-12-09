use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        param::MAX_MEMORY_SIZE_IN_BYTES,
        step::ExecutionState,
        util::{
            Cell,
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            math_gadget::{ComparisonGadget, IsZeroGadget, LtGadget},
            sum,
        },
    },
    util::Expr,
};
use array_init::array_init;
use halo2::{arithmetic::FieldExt, circuit::{Region}, plonk::Error};

const MAX_COPY_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub(crate) struct CopyMemoryToMemoryGadget<F> {
    src_addr: Cell<F>,
    dst_addr: Cell<F>,
    length: Cell<F>,
    src_addr_bound: Cell<F>,
    src_addr_lt_gadget: LtGadget<F, MAX_MEMORY_SIZE_IN_BYTES>,
    bytes: [Cell<F>; MAX_COPY_BYTES],
    selectors: [Cell<F>; MAX_COPY_BYTES],
    bound_dist: [Cell<F>; MAX_COPY_BYTES],
    bound_dist_is_zero: [IsZeroGadget<F>; MAX_COPY_BYTES],
    copied_comp_gadget: ComparisonGadget<F, 4>,
}

impl<F: FieldExt> ExecutionGadget<F> for CopyMemoryToMemoryGadget<F> {
    const NAME: &'static str = "COPYMEMORYTOMEMORY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::COPYMEMORYTOMEMORY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let src_addr = cb.query_cell();
        let dst_addr = cb.query_cell();
        let length = cb.query_cell();
        let src_addr_bound = cb.query_cell();

        let bytes = cb.query_cells(true);
        let selectors = array_init(|_| cb.query_bool());
        let bound_dist = cb.query_cells(false);
        let bound_dist_is_zero = array_init(|idx| {
            IsZeroGadget::construct(cb, bound_dist[idx].expr())
        });

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
        let src_addr_lt_gadget = LtGadget::construct(cb, src_addr.expr(), src_addr_bound.expr());
        cb.add_constraint(
            "Constrain src_addr < src_addr_bound when bound_dist[0] != 0",
            bound_dist_is_zero[0].expr() * (1.expr() - src_addr_lt_gadget.expr()),
        );
        // Constraints on bound_dist[1..MAX_COPY_BYTES]
        //   diff == 0 / 1 where diff = bound_dist[idx - 1] - bound_dist[idx]
        //   diff == 1 when bound_dist[idx - 1] != 0
        //   diff == 0 when bound_dist[idx - 1] == 0
        for idx in 1..MAX_COPY_BYTES {
            let diff = bound_dist[idx - 1] - bound_dist[idx];
            cb.require_boolean(
                "Constrain bound_dist[i - 1] - bound_dist[i] == 0 / 1",
                diff.clone(),
            );
            cb.add_constraint(
                "Constrain diff == 1 when bound_dist[i - 1] != 0",
                (1.expr() - bound_dist_is_zero[idx - 1].expr()) * (1.expr() - diff.expr()),
            );
            cb.add_constraint(
                "Constrain diff == 0 when bound_dist[i - 1] == 0",
                bound_dist_is_zero[idx - 1].expr() * diff.expr(),
            )
        }

        // Constraints on bytes[0..MAX_COPY_BYTES]
        for i in 0..MAX_COPY_BYTES {
            // Read bytes[i] from memory when selectors[i] != 0 & bound_dist[i] != 0
            cb.condition(
                selectors[i].expr() * (1.expr() - bound_dist_is_zero[i].expr()),
                |cb| {cb.memory_lookup(
                    0.expr(),
                    src_addr.expr() + i.expr(),
                    bytes[i].expr())
                },
            );
            // Write bytes[i] to memory when selectors[i] != 0
            cb.condition(
                selectors[i].expr(),
                |cb| {cb.memory_lookup(
                    1.expr(),
                    dst_addr.expr() + i.expr(),
                    bytes[i].expr())
                },
            );
            cb.add_constraint(
                "Constrain bytes[i] == 0 when selectors[i] == 0",
                (1.expr() - selectors[i].expr()) * bytes[i].expr(),
            );
            cb.add_constraint(
                "Constrain bytes[i] == 0 when bound_dist[i] == 0",
                bound_dist_is_zero[i].expr() * bytes[i].expr(),
            )
        }

        let copied_size = sum::expr(selectors);
        let copied_comp_gadget = ComparisonGadget::construct(
            cb, copied_size, length.expr(),
        );
        let (lt, finished) = copied_comp_gadget.expr();
        cb.add_constraint(
            "Constrain sum(selectors) <= length",
            lt * finished,
        );

        // When finished == 0, constraint the states in next step

        // cb.add_constraint(

        // )

        Self {
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
