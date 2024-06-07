use super::TargetCircuit;
use crate::config::INNER_DEGREE;
use anyhow::bail;
use halo2_proofs::halo2curves::bn256::Fr;
use zkevm_circuits::{super_circuit::params::ScrollSuperCircuit, witness};

pub struct SuperCircuit {}

impl TargetCircuit for SuperCircuit {
    type Inner = ScrollSuperCircuit;

    fn from_witness_block(
        witness_block: &witness::Block,
    ) -> anyhow::Result<(Self::Inner, Vec<Vec<Fr>>)>
    where
        Self: Sized,
    {
        let (k, inner, instance) = Self::Inner::build_from_witness_block(witness_block.clone())?;
        if k > *INNER_DEGREE {
            bail!(
                "circuit not enough: INNER_DEGREE = {}, less than k needed: {}",
                *INNER_DEGREE,
                k
            );
        }
        Ok((inner, instance))
    }
}
