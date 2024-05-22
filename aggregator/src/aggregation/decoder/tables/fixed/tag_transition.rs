use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::{tables::fixed::FixedLookupTag, witgen::ZstdTag};

use super::FixedLookupValues;

pub struct RomTagTransition {
    /// The current tag.
    pub tag: ZstdTag,
    /// The tag that will be processed after the current tag is finished processing.
    pub tag_next: ZstdTag,
    /// The maximum number of bytes that are needed to represent the current tag.
    pub max_len: u64,
    /// Whether this tag is processed from back-to-front or not.
    pub is_reverse: bool,
    /// Whether this tag belongs to a ``block`` in zstd or not.
    pub is_block: bool,
}

impl FixedLookupValues for RomTagTransition {
    fn values() -> Vec<[Value<Fr>; 7]> {
        use ZstdTag::{
            BlockHeader, FrameContentSize, FrameHeaderDescriptor, Null, ZstdBlockLiteralsHeader,
            ZstdBlockLiteralsRawBytes, ZstdBlockSequenceData, ZstdBlockSequenceFseCode,
            ZstdBlockSequenceHeader,
        };

        [
            (FrameHeaderDescriptor, FrameContentSize),
            (FrameContentSize, BlockHeader),
            (BlockHeader, ZstdBlockLiteralsHeader),
            (ZstdBlockLiteralsHeader, ZstdBlockLiteralsRawBytes),
            (ZstdBlockLiteralsRawBytes, ZstdBlockSequenceHeader),
            (ZstdBlockSequenceHeader, ZstdBlockSequenceFseCode),
            (ZstdBlockSequenceHeader, ZstdBlockSequenceData),
            (ZstdBlockSequenceFseCode, ZstdBlockSequenceFseCode),
            (ZstdBlockSequenceFseCode, ZstdBlockSequenceData),
            (ZstdBlockSequenceData, BlockHeader), // multi-block
            (ZstdBlockSequenceData, Null),
            (Null, Null),
        ]
        .map(|(tag, tag_next)| {
            [
                Value::known(Fr::from(FixedLookupTag::TagTransition as u64)),
                Value::known(Fr::from(tag as u64)),
                Value::known(Fr::from(tag_next as u64)),
                Value::known(Fr::from(tag.max_len())),
                Value::known(Fr::from(tag.is_reverse())),
                Value::known(Fr::from(tag.is_block())),
                Value::known(Fr::zero()), // unused
            ]
        })
        .to_vec()
    }
}
