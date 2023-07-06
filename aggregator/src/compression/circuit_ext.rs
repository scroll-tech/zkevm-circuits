//! CircuitExt implementation for compression circuit.

use halo2_proofs::{halo2curves::bn256::Fr, plonk::Selector};
use snark_verifier_sdk::CircuitExt;

use crate::ACC_LEN;

use super::circuit::CompressionCircuit;

impl CircuitExt<Fr> for CompressionCircuit {
    fn num_instance(&self) -> Vec<usize> {
        // re-expose inner public input
        let snark_pi_len: usize = self.snark.instances.iter().map(|x| x.len()).sum();

        // if the snark is not fresh, the snark_pi already contains elements for the accumulator
        vec![snark_pi_len + ACC_LEN * self.is_fresh as usize]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.flattened_instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        // the accumulator are the first 12 cells in the instance
        Some((0..ACC_LEN).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        config.gate().basic_gates[0]
            .iter()
            .map(|gate| gate.q_enable)
            .collect()
    }
}
