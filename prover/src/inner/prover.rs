use crate::{
    common,
    config::INNER_DEGREE,
    io::serialize_vk,
    utils::{chunk_trace_to_witness_block, gen_rng},
    zkevm::circuit::TargetCircuit,
    Proof,
};
use anyhow::Result;
use eth_types::l2_types::BlockTrace;
use std::marker::PhantomData;

mod mock;

#[derive(Debug)]
pub struct Prover<C: TargetCircuit> {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Prover,
    phantom: PhantomData<C>,
}

impl<C: TargetCircuit> From<common::Prover> for Prover<C> {
    fn from(inner: common::Prover) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }
}

impl<C: TargetCircuit> Prover<C> {
    pub fn from_params_dir(params_dir: &str) -> Self {
        common::Prover::from_params_dir(params_dir, &[*INNER_DEGREE]).into()
    }

    pub fn load_or_gen_inner_proof(
        &mut self,
        name: &str,
        id: &str,
        block_traces: Vec<BlockTrace>,
        output_dir: Option<&str>,
    ) -> Result<Proof> {
        let filename = format!("{id}_{name}");
        match output_dir.and_then(|output_dir| Proof::from_json_file(output_dir, &filename).ok()) {
            Some(proof) => Ok(proof),
            None => {
                assert!(!block_traces.is_empty());

                let rng = gen_rng();
                let witness_block = chunk_trace_to_witness_block(block_traces)?;
                let result = self
                    .inner
                    .gen_inner_snark::<C>(id, rng, &witness_block)
                    .map(|snark| {
                        let raw_vk = serialize_vk(self.inner.pk(id).unwrap().get_vk());
                        Proof::from_snark(snark, raw_vk)
                    });

                if let (Some(output_dir), Ok(proof)) = (output_dir, &result) {
                    proof.dump(output_dir, &filename)?;
                }

                result
            }
        }
    }
}
