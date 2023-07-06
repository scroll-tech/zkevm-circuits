use halo2_proofs::{halo2curves::bn256::Fr, plonk::Selector};
use snark_verifier_sdk::CircuitExt;

use crate::constants::{ACC_LEN, DIGEST_LEN};

use super::AggregationCircuit;

impl CircuitExt<Fr> for AggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        // 12 elements from accumulator
        // 32 elements from batch's public_input_hash
        vec![ACC_LEN + DIGEST_LEN]
    }

    // 12 elements from accumulator
    // 32 elements from batch's public_input_hash
    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.flattened_instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        // the accumulator are the first 12 cells in the instance
        Some((0..ACC_LEN).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        // - advice columns from flex gate
        // - selector from RLC gate
        config.0.flex_gate().basic_gates[0]
            .iter()
            .map(|gate| gate.q_enable)
            .into_iter()
            .chain([config.0.rlc_config.selector].iter().cloned())
            .collect()
    }
}
