//! This module implements `Chunk` related data types.
//! A chunk is a list of blocks.
use eth_types::{base64, l2_types::BlockTrace, ToBigEndian, H256};
use ethers_core::utils::keccak256;
use serde::{Deserialize, Serialize};
use std::iter;
use zkevm_circuits::witness::Block;

#[derive(Default, Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// A chunk is a set of continuous blocks.
/// ChunkInfo is metadata of chunk, with following fields:
/// - state root before this chunk
/// - state root after this chunk
/// - the withdraw root after this chunk
/// - the data hash of this chunk
/// - the tx data hash of this chunk
/// - flattened L2 tx bytes
/// - if the chunk is padded (en empty but valid chunk that is padded for aggregation)
pub struct ChunkInfo {
    /// Chain identifier
    pub chain_id: u64,
    /// state root before this chunk
    pub prev_state_root: H256,
    /// state root after this chunk
    pub post_state_root: H256,
    /// the withdraw root after this chunk
    pub withdraw_root: H256,
    /// the data hash of this chunk
    pub data_hash: H256,
    /// Flattened L2 tx bytes (RLP-signed) in this chunk.
    #[serde(with = "base64")]
    pub tx_bytes: Vec<u8>,
    /// if the chunk is a padded chunk
    pub is_padding: bool,
}

impl ChunkInfo {
    /// Construct by block traces
    pub fn from_block_traces(traces: &[BlockTrace]) -> Self {
        let data_bytes = iter::empty()
            .chain(
                // header part
                traces.iter().flat_map(|b| b.da_encode_header()),
            )
            .chain(
                // l1 msg hashes
                traces.iter().flat_map(|b| {
                    b.transactions
                        .iter()
                        .filter(|tx| tx.is_l1_tx())
                        .flat_map(|tx| tx.tx_hash.to_fixed_bytes())
                }),
            )
            .collect::<Vec<u8>>();

        let data_hash = H256(keccak256(data_bytes));
        log::debug!(
            "chunk-hash: data hash = {}",
            hex::encode(data_hash.to_fixed_bytes())
        );

        let tx_bytes = traces
            .iter()
            .flat_map(|b| {
                b.transactions
                    .iter()
                    .filter(|tx| !tx.is_l1_tx())
                    .flat_map(|tx| tx.to_eth_tx(None, None, None, None).rlp().to_vec())
            })
            .collect::<Vec<u8>>();

        let post_state_root = traces
            .last()
            .expect("at least 1 block needed")
            .header
            .state_root;
        let withdraw_root = traces.last().unwrap().withdraw_trie_root;
        let chain_id = traces.first().unwrap().chain_id;
        let prev_state_root = traces.first().unwrap().storage_trace.root_before;

        Self {
            chain_id,
            prev_state_root,
            post_state_root,
            withdraw_root,
            data_hash,
            tx_bytes,
            is_padding: false,
        }
    }
    /// Construct by a witness block.
    pub fn from_witness_block(block: &Block, is_padding: bool) -> Self {
        // <https://github.com/scroll-tech/zkevm-circuits/blob/25dd32aa316ec842ffe79bb8efe9f05f86edc33e/bus-mapping/src/circuit_input_builder.rs#L690>

        let mut total_l1_popped = block.start_l1_queue_index;
        log::debug!("chunk-hash: start_l1_queue_index = {}", total_l1_popped);
        let data_bytes = iter::empty()
            .chain(block.context.ctxs.iter().flat_map(|(b_num, b_ctx)| {
                let num_l2_txs = block
                    .txs
                    .iter()
                    .filter(|tx| !tx.tx_type.is_l1_msg() && tx.block_number == *b_num)
                    .count() as u64;
                let num_l1_msgs = block
                    .txs
                    .iter()
                    .filter(|tx| tx.tx_type.is_l1_msg() && tx.block_number == *b_num)
                    // tx.nonce alias for queue_index for l1 msg tx
                    .map(|tx| tx.nonce)
                    .max()
                    .map_or(0, |max_queue_index| max_queue_index - total_l1_popped + 1);
                total_l1_popped += num_l1_msgs;

                let num_txs = (num_l2_txs + num_l1_msgs) as u16;
                log::debug!(
                    "chunk-hash: [block {}] total_l1_popped = {}, num_l1_msgs = {}, num_l2_txs = {}, num_txs = {}",
                    b_num,
                    total_l1_popped,
                    num_l1_msgs,
                    num_l2_txs,
                    num_txs,
                );

                // https://github.com/scroll-tech/da-codec/blob/b842a0f961ad9180e16b50121ef667e15e071a26/encoding/codecv2/codecv2.go#L97
                iter::empty()
                    // Block Values
                    .chain(b_ctx.number.as_u64().to_be_bytes())
                    .chain(b_ctx.timestamp.as_u64().to_be_bytes())
                    .chain(b_ctx.base_fee.to_be_bytes())
                    .chain(b_ctx.gas_limit.to_be_bytes())
                    .chain(num_txs.to_be_bytes())
            }))
            // Tx Hashes (excluding L2 txs)
            .chain(block.txs
                .iter()
                .filter(|tx| tx.tx_type.is_l1_msg())
                .flat_map(|tx| tx.hash.to_fixed_bytes())
            )
            .collect::<Vec<u8>>();

        let data_hash = H256(keccak256(data_bytes));
        log::debug!(
            "chunk-hash: data hash = {}",
            hex::encode(data_hash.to_fixed_bytes())
        );

        let tx_bytes = block
            .txs
            .iter()
            .filter(|tx| !tx.tx_type.is_l1_msg())
            .flat_map(|tx| tx.rlp_signed.to_vec())
            .collect::<Vec<u8>>();

        let post_state_root = block
            .context
            .ctxs
            .last_key_value()
            .map(|(_, b_ctx)| b_ctx.state_root)
            .unwrap_or(block.prev_state_root);

        Self {
            chain_id: block.chain_id,
            prev_state_root: block.prev_state_root,
            post_state_root,
            withdraw_root: H256(block.withdraw_root.to_be_bytes()),
            data_hash,
            tx_bytes: tx_bytes.to_vec(),
            is_padding,
        }
    }

    /// The keccak256 hash of the flattened RLP-encoded signed tx bytes over all L2 txs in this
    /// chunk.
    pub(crate) fn tx_bytes_hash(&self) -> H256 {
        H256(keccak256(&self.tx_bytes))
    }

    #[cfg(test)]
    pub(crate) fn mock_chunk_infos(txs_data: &[Vec<u8>]) -> Vec<Self> {
        use crate::MAX_AGG_SNARKS;

        assert!(txs_data.len() <= MAX_AGG_SNARKS);
        let state_roots: [H256; MAX_AGG_SNARKS + 1] = (0..=MAX_AGG_SNARKS)
            .map(|i| {
                let i = i as u8;
                let mut state_root = [0u8; 32];
                state_root[31] = i;
                state_root.into()
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("should not fail");

        txs_data
            .iter()
            .enumerate()
            .map(|(i, tx_data)| {
                let withdraw_root = {
                    let mut root = [0u8; 32];
                    root[31] = 255 - (i as u8);
                    root.into()
                };
                let data_hash = {
                    let mut root = [0u8; 32];
                    root[0] = 255 - (i as u8);
                    root.into()
                };
                ChunkInfo {
                    chain_id: 123456,
                    prev_state_root: state_roots[i],
                    post_state_root: state_roots[i + 1],
                    withdraw_root,
                    data_hash,
                    tx_bytes: tx_data.to_vec(),
                    is_padding: false,
                }
            })
            .collect::<Vec<_>>()
    }

    /// Sample a chunk info from random (for testing)
    #[cfg(test)]
    pub(crate) fn mock_random_chunk_info_for_testing<R: rand::RngCore>(r: &mut R) -> Self {
        use eth_types::Address;
        use ethers_core::types::TransactionRequest;
        use rand::{
            distributions::{Distribution, Standard},
            Rng,
        };

        let mut prev_state_root = [0u8; 32];
        r.fill_bytes(&mut prev_state_root);
        let mut post_state_root = [0u8; 32];
        r.fill_bytes(&mut post_state_root);
        let mut withdraw_root = [0u8; 32];
        r.fill_bytes(&mut withdraw_root);
        let mut data_hash = [0u8; 32];
        r.fill_bytes(&mut data_hash);

        const N_TXS: usize = 10;
        const N_SENDERS: usize = 2;
        const N_RECIPIENTS: usize = 3;
        let senders = (0..N_SENDERS)
            .map(|_| Address::random_using(r))
            .collect::<Vec<_>>();
        let recipients = (0..N_RECIPIENTS)
            .map(|_| Address::random_using(r))
            .collect::<Vec<_>>();
        const N_TX_DATA_LEN: usize = 1024;
        struct TxDataByte(u8);
        impl Distribution<TxDataByte> for Standard {
            fn sample<R: rand::prelude::Rng + ?Sized>(&self, rng: &mut R) -> TxDataByte {
                match rng.gen_range(0..5) {
                    0 => TxDataByte(0),
                    1 => TxDataByte(4),
                    2 => TxDataByte(127),
                    3 => TxDataByte(255),
                    _ => TxDataByte(rng.gen()),
                }
            }
        }

        let mut txs = Vec::with_capacity(N_TXS);
        for _ in 0..N_TXS {
            let i = r.gen_range(0..N_SENDERS * N_RECIPIENTS);
            txs.push(
                TransactionRequest::new()
                    .from(senders[i % N_SENDERS])
                    .to(recipients[i % N_RECIPIENTS])
                    .data(
                        (0..N_TX_DATA_LEN)
                            .map(|_| {
                                let tx_data_byte: TxDataByte = rand::random();
                                tx_data_byte.0
                            })
                            .collect::<Vec<_>>(),
                    ),
            )
        }

        Self {
            chain_id: 0,
            prev_state_root: prev_state_root.into(),
            post_state_root: post_state_root.into(),
            withdraw_root: withdraw_root.into(),
            data_hash: data_hash.into(),
            tx_bytes: txs.iter().flat_map(|tx| tx.rlp_unsigned()).collect(),
            is_padding: false,
        }
    }

    /// Build a padded chunk from previous one
    #[cfg(test)]
    pub(crate) fn mock_padded_chunk_info_for_testing(previous_chunk: &Self) -> Self {
        assert!(
            !previous_chunk.is_padding,
            "previous chunk is padded already"
        );
        Self {
            chain_id: previous_chunk.chain_id,
            prev_state_root: previous_chunk.prev_state_root,
            post_state_root: previous_chunk.post_state_root,
            withdraw_root: previous_chunk.withdraw_root,
            data_hash: previous_chunk.data_hash,
            tx_bytes: previous_chunk.tx_bytes.clone(),
            is_padding: true,
        }
    }

    /// Public input hash for a given chunk is defined as
    /// keccak(
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     chunk data hash ||
    ///     chunk txdata hash
    /// )
    pub fn public_input_hash(&self) -> H256 {
        let preimage = self.extract_hash_preimage();
        keccak256::<&[u8]>(preimage.as_ref()).into()
    }

    /// Extract the preimage for the hash
    ///
    /// [
    ///     chain id ||
    ///     prev state root ||
    ///     post state root ||
    ///     withdraw root ||
    ///     chunk data hash ||
    ///     chunk txdata hash
    /// ]
    pub fn extract_hash_preimage(&self) -> Vec<u8> {
        [
            self.chain_id.to_be_bytes().as_ref(),
            self.prev_state_root.as_bytes(),
            self.post_state_root.as_bytes(),
            self.withdraw_root.as_bytes(),
            self.data_hash.as_bytes(),
            self.tx_bytes_hash().as_bytes(),
        ]
        .concat()
    }
}
