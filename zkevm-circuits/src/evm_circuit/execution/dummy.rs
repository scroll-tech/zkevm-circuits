use std::marker::PhantomData;

use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    util::{constraint_builder::EVMConstraintBuilder, CachedRegion, Word},
    witness::{Block, Call, ExecStep, Transaction},
};

use eth_types::{Field, ToLittleEndian};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct DummyGadget<F, const N_POP: usize, const N_PUSH: usize, const S: ExecutionState> {
    pops: [Word<F>; N_POP],
    pushes: [Word<F>; N_PUSH],
    _marker: PhantomData<F>,
}

impl<F: Field, const N_POP: usize, const N_PUSH: usize, const S: ExecutionState> ExecutionGadget<F>
    for DummyGadget<F, N_POP, N_PUSH, S>
{
    const NAME: &'static str = "DUMMY";

    const EXECUTION_STATE: ExecutionState = S;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let pops: [Word<F>; N_POP] = [(); N_POP].map(|_| cb.query_word_rlc());
        let pushes: [Word<F>; N_PUSH] = [(); N_PUSH].map(|_| cb.query_word_rlc());
        for _pop in pops.iter() {
            // cb.stack_pop(pop.expr());
        }
        for _push in pushes.iter() {
            // cb.stack_push(push.expr());
        }
        Self {
            pops,
            pushes,
            _marker: PhantomData,
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
        let full_dummy = true;
        if full_dummy {
            return Ok(());
        }
        // this happens if some opcodes are in the
        // process of being implemented but are still
        // using DummyGadget.
        // See `bus-mapping/src/evm/opcodes.rs`
        if step.rw_indices.len() != N_POP + N_PUSH {
            // log::warn!("DummyGadget: wrong number of rw indices for {:?}",
        }

        for i in 0..N_POP {
            let value = block.rws[step.rw_indices[i]].stack_value();
            self.pops[i].assign(region, offset, Some(value.to_le_bytes()))?;
        }
        for i in 0..N_PUSH {
            let value = block.rws[step.rw_indices[N_POP + i]].stack_value();
            self.pushes[i].assign(region, offset, Some(value.to_le_bytes()))?;
        }
        Ok(())
    }
}
