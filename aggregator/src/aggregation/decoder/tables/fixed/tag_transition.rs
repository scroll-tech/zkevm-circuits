use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::{tables::fixed::FixedLookupTag, witgen::{ZstdTag, lookup_max_tag_len}};

use super::FixedLookupValues;

pub struct RomTagTransition {
    /// The current tag.
    tag: ZstdTag,
    /// The tag that will be processed after the current tag is finished processing.
    tag_next: ZstdTag,
    /// The maximum number of bytes that are needed to represent the current tag.
    max_len: u64,
    /// Whether this tag outputs a decoded byte or not.
    is_output: bool,
    /// Whether this tag is processed from back-to-front or not.
    is_reverse: bool,
    /// Whether this tag belongs to a ``block`` in zstd or not.
    is_block: bool,
}

impl FixedLookupValues for RomTagTransition {
    fn values() -> Vec<[Value<Fr>; 7]> {
        use ZstdTag::{
            BlockHeader, FrameContentSize, FrameHeaderDescriptor, ZstdBlockLiteralsHeader,
            ZstdBlockLiteralsRawBytes, ZstdBlockSequenceHeader, ZstdBlockSequenceFseCode, ZstdBlockSequenceData, Null,
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
            (ZstdBlockSequenceData, Null),
        ]
        .map(|(tag, tag_next)| {
            [
                Value::known(Fr::from(FixedLookupTag::TagTransition as u64)),
                Value::known(Fr::from(tag as u64)),
                Value::known(Fr::from(tag_next as u64)),
                Value::known(Fr::from(lookup_max_tag_len(tag))),
                Value::known(Fr::from(tag.is_output())),
                Value::known(Fr::from(tag.is_reverse())),
                Value::known(Fr::from(tag.is_block())),
            ]
        })
        .to_vec()
    }
}
