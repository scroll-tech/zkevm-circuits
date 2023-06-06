use eth_types::H256;
use ethers_core::utils::keccak256;

use super::chunk::ChunkHash;

#[derive(Default, Debug, Clone)]
/// A batch is a set of continuous chunks.
/// A BatchHash consists of 2 hashes.
pub struct BatchHash {
    pub(crate) data_hash: H256,
    pub(crate) public_input_hash: H256,
}

impl BatchHash {
    /// Build Batch hash from a list of chunks
    pub(crate) fn construct(chunk_hashes: &[ChunkHash]) -> Self {
        // sanity: the chunks are continuous
        for i in 0..chunk_hashes.len() - 1 {
            assert_eq!(
                chunk_hashes[i].post_state_root,
                chunk_hashes[i + 1].prev_state_root,
            );
            assert_eq!(chunk_hashes[i].chain_id, chunk_hashes[i + 1].chain_id,)
        }

        // batch's data hash is build as
        //  keccak( chunk[0].data_hash || ... || chunk[k-1].data_hash)
        let preimage = chunk_hashes
            .iter()
            .flat_map(|chunk_hash| chunk_hash.data_hash.0.iter())
            .cloned()
            .collect::<Vec<_>>();
        let data_hash = keccak256(preimage);

        // public input hash is build as
        //  keccak(
        //      chain_id ||
        //      chunk[0].prev_state_root ||
        //      chunk[k-1].post_state_root ||
        //      chunk[k-1].withdraw_root ||
        //      batch_data_hash )
        let preimage = [
            chunk_hashes[0].chain_id.to_le_bytes().as_ref(),
            chunk_hashes[0].prev_state_root.as_bytes(),
            chunk_hashes.last().unwrap().post_state_root.as_bytes(),
            chunk_hashes.last().unwrap().withdraw_root.as_bytes(),
            data_hash.as_slice(),
        ]
        .concat();
        let public_input_hash = keccak256(preimage);

        Self {
            data_hash: data_hash.into(),
            public_input_hash: public_input_hash.into(),
        }
    }
}
