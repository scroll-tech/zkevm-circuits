use std::iter;

use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::CircuitExt;

use crate::{ACC_LEN, CHAIN_ID_LEN};

use super::MockChunkCircuit;

impl CircuitExt<Fr> for MockChunkCircuit {
    /// 64 elements from digest
    fn num_instance(&self) -> Vec<usize> {
        let acc_len = if self.is_fresh { 0 } else { ACC_LEN };
        vec![64 + CHAIN_ID_LEN + acc_len]
    }

    /// return vec![data hash | public input hash]
    fn instances(&self) -> Vec<Vec<Fr>> {
        let acc_len = if self.is_fresh { 0 } else { ACC_LEN };
        vec![iter::repeat(0)
            .take(acc_len)
            .chain(
                self.chain_id
                    .to_be_bytes()
                    .iter()
                    .chain(
                        self.chunk
                            .data_hash
                            .as_bytes()
                            .iter()
                            .chain(self.chunk.public_input_hash().as_bytes().iter()),
                    )
                    .copied(),
            )
            .map(|x| Fr::from(x as u64))
            .collect()]
    }
}
