use eth_types::Field;
use snark_verifier_sdk::CircuitExt;

use crate::BatchHashCircuit;

impl<F: Field> CircuitExt<F> for BatchHashCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        vec![self.instances()[0].len()]
    }

    /// Compute the public inputs for this circuit.
    fn instances(&self) -> Vec<Vec<F>> {
        let public_input = self.public_input();

        let first_chunk_prev_state_root = public_input
            .first_chunk_prev_state_root
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64));

        let last_chunk_post_state_root = public_input
            .last_chunk_post_state_root
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64));

        let last_chunk_withdraw_root = public_input
            .last_chunk_withdraw_root
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64));

        let batch_public_input_hash = public_input
            .batch_public_input_hash
            .as_bytes()
            .iter()
            .map(|&x| F::from(x as u64));

        let chain_id_bytes = public_input.chain_id.to_le_bytes();
        let chain_id = chain_id_bytes.iter().map(|x| F::from(*x as u64));

        vec![first_chunk_prev_state_root
            .chain(last_chunk_post_state_root)
            .chain(last_chunk_withdraw_root)
            .chain(batch_public_input_hash)
            .chain(chain_id)
            .collect()]
    }
}
