use super::Prover;
use crate::{
    config::INNER_DEGREE,
    utils::metric_of_witness_block,
    zkevm::circuit::{block_traces_to_witness_block, TargetCircuit},
};
use anyhow::bail;
use eth_types::l2_types::BlockTrace;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use zkevm_circuits::witness::Block;

impl<C: TargetCircuit> Prover<C> {
    pub fn mock_prove_target_circuit(block_trace: &BlockTrace) -> anyhow::Result<()> {
        Self::mock_prove_target_circuit_batch(&[block_trace.clone()])
    }

    pub fn mock_prove_target_circuit_batch(block_traces: &[BlockTrace]) -> anyhow::Result<()> {
        let witness_block = block_traces_to_witness_block(block_traces)?;
        Self::mock_prove_witness_block(&witness_block)
    }

    pub fn mock_prove_witness_block(witness_block: &Block<Fr>) -> anyhow::Result<()> {
        log::info!(
            "mock proving batch, batch metric {:?}",
            metric_of_witness_block(witness_block)
        );
        let (circuit, instance) = C::from_witness_block(witness_block)?;
        let prover = MockProver::<Fr>::run(*INNER_DEGREE, &circuit, instance)?;
        if let Err(errs) = prover.verify_par() {
            log::error!("err num: {}", errs.len());
            for err in &errs {
                log::error!("{}", err);
            }
            bail!("{:#?}", errs);
        }
        log::info!(
            "mock prove done. batch metric: {:?}",
            metric_of_witness_block(witness_block),
        );
        Ok(())
    }
}
