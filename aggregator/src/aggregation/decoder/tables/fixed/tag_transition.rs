use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::{tables::fixed::FixedLookupTag, witgen::ZstdTag};

use super::FixedLookupValues;

pub struct RomTagTransition;

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
