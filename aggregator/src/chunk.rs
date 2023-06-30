//! This module implements `Chunk` related data types.
//! A chunk is a list of blocks.
use eth_types::H256;
use ethers_core::utils::keccak256;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use rand::Rng;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, Snark};

use crate::chunk::dummy_circuit::DummyChunkHashCircuit;

/// Implements a dummy circuit for the chunk
pub(crate) mod dummy_circuit;
/// Implements a dummy circuit ext for the chunk
pub(crate) mod dummy_circuit_ext;

#[derive(Default, Debug, Clone, Copy)]
/// A chunk is a set of continuous blocks.
/// A ChunkHash consists of 4 hashes, representing the changes incurred by this chunk of blocks:
/// - state root before this chunk
/// - state root after this chunk
/// - the withdraw root of this chunk
/// - the data hash of this chunk
pub struct ChunkHash {
    /// Chain identifier
    pub(crate) chain_id: u64,
    /// state root before this chunk
    pub(crate) prev_state_root: H256,
    /// state root after this chunk
    pub(crate) post_state_root: H256,
    /// the withdraw root of this chunk
    pub(crate) withdraw_root: H256,
    /// the data hash of this chunk
    pub(crate) data_hash: H256,
}

impl ChunkHash {
    /// Sample a chunk hash from random (for testing)
    #[cfg(test)]
    pub(crate) fn mock_chunk_hash<R: rand::RngCore>(r: &mut R) -> Self {
        let mut prev_state_root = [0u8; 32];
        r.fill_bytes(&mut prev_state_root);
        let mut post_state_root = [0u8; 32];
        r.fill_bytes(&mut post_state_root);
        let mut withdraw_root = [0u8; 32];
        r.fill_bytes(&mut withdraw_root);
        let mut data_hash = [0u8; 32];
        r.fill_bytes(&mut data_hash);
        Self {
            chain_id: 0,
            prev_state_root: prev_state_root.into(),
            post_state_root: post_state_root.into(),
            withdraw_root: withdraw_root.into(),
            data_hash: data_hash.into(),
        }
    }

    /// Build a dummy chunk from a real chunk.
    /// The dummy chunk will act as a consecutive chunk of the real chunk
    pub(crate) fn dummy_chunk_hash(previous_chunk: &Self) -> Self {
        Self {
            chain_id: previous_chunk.chain_id,
            prev_state_root: previous_chunk.post_state_root,
            post_state_root: previous_chunk.post_state_root,
            withdraw_root: previous_chunk.withdraw_root,
            data_hash: [0u8; 32].into(),
        }
    }

    /// Generate a dummy snark, as well as the pk. Require the chunk hash to be a dummy one
    pub(crate) fn dummy_snark(
        &self,
        param: &ParamsKZG<Bn256>,
        rng: &mut (impl Rng + Send),
    ) -> (ProvingKey<G1Affine>, Snark) {
        // make sure self is dummy or we will not generate a snark
        assert!(self.is_dummy());
        let dummy_circuit = DummyChunkHashCircuit::new(*self);
        let pk = gen_pk(param, &dummy_circuit, None);
        let snark = gen_snark_shplonk(&param, &pk, dummy_circuit, rng, None::<String>);
        (pk, snark)
    }

    pub(crate) fn is_dummy(&self) -> bool {
        if self.prev_state_root != self.post_state_root || self.data_hash != [0u8; 32].into() {
            false
        } else {
            true
        }
    }

    /// Public input hash for a given chunk is defined as
    ///  keccak( chain id || prev state root || post state root || withdraw root || data hash )
    pub fn public_input_hash(&self) -> H256 {
        let preimage = self.extract_hash_preimage();
        keccak256::<&[u8]>(preimage.as_ref()).into()
    }

    /// Extract the preimage for the hash
    ///  chain id || prev state root || post state root || withdraw root || data hash
    pub fn extract_hash_preimage(&self) -> Vec<u8> {
        [
            self.chain_id.to_be_bytes().as_ref(),
            self.prev_state_root.as_bytes(),
            self.post_state_root.as_bytes(),
            self.withdraw_root.as_bytes(),
            self.data_hash.as_bytes(),
        ]
        .concat()
    }
}
