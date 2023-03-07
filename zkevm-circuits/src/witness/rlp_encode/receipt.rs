use ethers_core::utils::rlp::{self, Encodable};
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

use crate::{evm_circuit::witness::Receipt, impl_expr};

use super::{
    common::{handle_address, handle_bytes, handle_prefix, handle_u256},
    witness_gen::{RlpDataType, RlpWitnessGen, RlpWitnessRow},
};

/// Tags used to tags rows in the RLP circuit for a tx receipt.
#[derive(Clone, Copy, Debug)]
pub enum RlpReceiptTag {
    /// Denotes the prefix bytes indicating the "length of length" and/or
    /// "length" of the tx receipt's RLP-encoding.
    Prefix = 1,
    /// Denotes the byte for the receipt's status.
    Status,
    /// Denotes the bytes representing the cumulative gas used.
    CumulativeGasUsed,
    /// Denotes the bytes prefixing the bloom filter bytes.
    BloomPrefix,
    /// Denotes the 256-bytes representing bloom filter.
    Bloom,
    /// Denotes the bytes prefixing the list of logs.
    LogsPrefix,
    /// Denotes the bytes prefixing a single log.
    LogPrefix,
    /// Denotes the byte prefixing the log.address.
    LogAddressPrefix,
    /// Denotes the 20-bytes representing the log.address.
    LogAddress,
    /// Denotes the bytes prefixing log.topics.
    LogTopicsPrefix,
    /// Denotes the bytes prefixing a single log.topic.
    LogTopicPrefix,
    /// Denotes the bytes representing a single log.topic.
    LogTopic,
    /// Denotes the bytes prefixing log.data.
    LogDataPrefix,
    /// Denotes the bytes representing log.data.
    LogData,
}

impl_expr!(RlpReceiptTag);

/// Denotes the number of possible tag values for a tx receipt row.
pub const N_RECEIPT_TAGS: usize = 14;

impl<F: FieldExt> RlpWitnessGen<F> for Receipt {
    fn gen_witness(&self, randomness: F) -> Vec<RlpWitnessRow<F>> {
        let rlp_data = rlp::encode(self);

        let mut rows = Vec::with_capacity(rlp_data.len());

        let idx = handle_prefix(
            self.id,
            rlp_data.as_ref(),
            &mut rows,
            RlpDataType::Receipt,
            RlpReceiptTag::Prefix as u8,
            0,
        );
        let idx = handle_u256(
            randomness,
            self.id,
            rlp_data.as_ref(),
            &mut rows,
            RlpDataType::Receipt,
            RlpReceiptTag::Status as u8,
            self.status.into(),
            idx,
        );
        let idx = handle_u256(
            randomness,
            self.id,
            rlp_data.as_ref(),
            &mut rows,
            RlpDataType::Receipt,
            RlpReceiptTag::CumulativeGasUsed as u8,
            self.cumulative_gas_used.into(),
            idx,
        );
        let idx = handle_bytes(
            randomness,
            self.id,
            rlp_data.as_ref(),
            &mut rows,
            RlpDataType::Receipt,
            RlpReceiptTag::BloomPrefix as u8,
            RlpReceiptTag::Bloom as u8,
            self.bloom.as_bytes(),
            idx,
        );
        let idx = self.handle_logs(randomness, rlp_data.as_ref(), &mut rows, idx);

        assert!(
            idx == rlp_data.len(),
            "RLP data mismatch: idx != len(rlp_data)"
        );
        rows
    }
}

impl Receipt {
    fn handle_logs<F: FieldExt>(
        &self,
        randomness: F,
        rlp_data: &[u8],
        rows: &mut Vec<RlpWitnessRow<F>>,
        mut idx: usize,
    ) -> usize {
        idx = handle_prefix(
            self.id,
            rlp_data,
            rows,
            RlpDataType::Receipt,
            RlpReceiptTag::LogsPrefix as u8,
            idx,
        );
        for log in self.logs.iter() {
            idx = handle_prefix(
                self.id,
                rlp_data,
                rows,
                RlpDataType::Receipt,
                RlpReceiptTag::LogPrefix as u8,
                idx,
            );

            // start of aux tag index and length assignment (0).
            let aux_tag_start0 = idx;
            idx = handle_address(
                self.id,
                rlp_data,
                rows,
                RlpDataType::Receipt,
                RlpReceiptTag::LogAddressPrefix as u8,
                RlpReceiptTag::LogAddress as u8,
                log.address,
                idx,
            );
            idx = handle_prefix(
                self.id,
                rlp_data,
                rows,
                RlpDataType::Receipt,
                RlpReceiptTag::LogTopicsPrefix as u8,
                idx,
            );

            // start of aux tag index and length assignment (1).
            let aux_tag_start1 = idx;
            for topic in log.topics.iter() {
                idx = handle_bytes(
                    randomness,
                    self.id,
                    rlp_data,
                    rows,
                    RlpDataType::Receipt,
                    RlpReceiptTag::LogTopicPrefix as u8,
                    RlpReceiptTag::LogTopic as u8,
                    topic.as_bytes(),
                    idx,
                );
            }
            // assign aux tag index and length (1).
            let aux_tag_length1 = idx - aux_tag_start1;
            for (aux_idx, row) in rows
                .iter_mut()
                .skip(aux_tag_start1)
                .take(aux_tag_length1)
                .enumerate()
            {
                row.aux_tag_length[1] = aux_tag_length1;
                row.aux_tag_index[1] = aux_tag_length1 - aux_idx;
            }

            idx = handle_bytes(
                randomness,
                self.id,
                rlp_data,
                rows,
                RlpDataType::Receipt,
                RlpReceiptTag::LogDataPrefix as u8,
                RlpReceiptTag::LogData as u8,
                log.data.as_ref(),
                idx,
            );

            // assign aux tag index and length (0).
            let aux_tag_length0 = idx - aux_tag_start0;
            for (aux_idx, row) in rows
                .iter_mut()
                .skip(aux_tag_start0)
                .take(aux_tag_length0)
                .enumerate()
            {
                row.aux_tag_length[0] = aux_tag_length0;
                row.aux_tag_index[0] = aux_tag_length0 - aux_idx;
            }
        }
        idx
    }
}
