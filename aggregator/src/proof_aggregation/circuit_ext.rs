use halo2_proofs::{halo2curves::bn256::Fr, plonk::Selector};
use snark_verifier_sdk::CircuitExt;

use crate::{param::LIMBS, AggregationCircuit};

impl CircuitExt<Fr> for AggregationCircuit {
    fn num_instance(&self) -> Vec<usize> {
        // accumulator [..lhs, ..rhs]
        let acc_len = 4 * LIMBS;
        // public input
        let public_input_agg_instance_len = self.batch_hash_circuit.num_instance()[0];

        vec![public_input_agg_instance_len + acc_len]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.flattened_instances.clone()]
    }

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        // the accumulator are the first 12 cells in the instance
        Some((0..4 * LIMBS).map(|idx| (0, idx)).collect())
    }

    fn selectors(config: &Self::Config) -> Vec<Selector> {
        config.0.gate().basic_gates[0]
            .iter()
            .map(|gate| gate.q_enable)
            .collect()
    }
}
