use std::iter;

use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier_sdk::CircuitExt;

use crate::{constants::DIGEST_LEN, ACC_LEN};

use super::MockChunkCircuit;

impl CircuitExt<Fr> for MockChunkCircuit {
    /// 32 elements from digest
    fn num_instance(&self) -> Vec<usize> {
        let acc_len = if self.is_fresh { 0 } else { ACC_LEN };
        vec![DIGEST_LEN + acc_len]
    }

    /// return vec![data hash | public input hash]
    fn instances(&self) -> Vec<Vec<Fr>> {
        let acc_len = if self.is_fresh { 0 } else { ACC_LEN };
        vec![iter::repeat(0)
            .take(acc_len)
            .chain(self.chunk.public_input_hash().as_bytes().iter().copied())
            .map(|x| Fr::from(x as u64))
            .collect()]
    }
}
