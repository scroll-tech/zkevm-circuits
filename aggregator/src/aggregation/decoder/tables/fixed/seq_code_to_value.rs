use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::witgen::FseTableKind;

use super::{FixedLookupTag, FixedLookupValues};

#[derive(Clone, Debug)]
pub struct RomSeqCodeToValue {
    /// The FSE table kind (LLT, MOT, MLT)
    pub table_kind: FseTableKind,
    /// The code decoded from the FSE table before.
    pub code: u64,
    /// The baseline for code-to-value.
    pub baseline: u64,
    /// The number of bits to read now for code-to-value.
    pub nb: u64,
}

impl From<(FseTableKind, u64, u64, u64)> for RomSeqCodeToValue {
    fn from(v: (FseTableKind, u64, u64, u64)) -> Self {
        Self {
            table_kind: v.0,
            code: v.1,
            baseline: v.2,
            nb: v.3,
        }
    }
}

pub trait CodeToValue {
    fn code_to_value() -> Vec<RomSeqCodeToValue>;
}

pub struct LiteralLengthCodes;
pub struct MatchLengthCodes;
pub struct MatchOffsetCodes;

impl CodeToValue for LiteralLengthCodes {
    fn code_to_value() -> Vec<RomSeqCodeToValue> {
        (0..16)
            .map(|i| (i, i, 0))
            .chain([
                (16, 16, 1),
                (17, 18, 1),
                (18, 20, 1),
                (19, 22, 1),
                (20, 24, 2),
                (21, 28, 2),
                (22, 32, 3),
                (23, 40, 3),
                (24, 48, 4),
                (25, 64, 6),
                (26, 128, 7),
                (27, 256, 8),
                (28, 512, 9),
                (29, 1024, 10),
                (30, 2048, 11),
                (31, 4096, 12),
                (32, 8192, 13),
                (33, 16384, 14),
                (34, 32768, 15),
                (35, 65536, 16),
            ])
            .map(|tuple| (FseTableKind::LLT, tuple.0, tuple.1, tuple.2).into())
            .collect()
    }
}

impl CodeToValue for MatchLengthCodes {
    fn code_to_value() -> Vec<RomSeqCodeToValue> {
        (0..32)
            .map(|i| (i, i + 3, 0))
            .chain([
                (32, 35, 1),
                (33, 37, 1),
                (34, 39, 1),
                (35, 41, 1),
                (36, 43, 2),
                (37, 47, 2),
                (38, 51, 3),
                (39, 59, 3),
                (40, 67, 4),
                (41, 83, 4),
                (42, 99, 5),
                (43, 131, 7),
                (44, 259, 8),
                (45, 515, 9),
                (46, 1027, 10),
                (47, 2051, 11),
                (48, 4099, 12),
                (49, 8195, 13),
                (50, 16387, 14),
                (51, 32771, 15),
                (52, 65539, 16),
            ])
            .map(|tuple| (FseTableKind::MLT, tuple.0, tuple.1, tuple.2).into())
            .collect()
    }
}

impl CodeToValue for MatchOffsetCodes {
    // N <- 31 for Match Offset Codes.
    fn code_to_value() -> Vec<RomSeqCodeToValue> {
        (0..32)
            .map(|i| (FseTableKind::MOT, i, 1 << i, i).into())
            .collect()
    }
}

impl FixedLookupValues for RomSeqCodeToValue {
    fn values() -> Vec<[Value<Fr>; 7]> {
        std::iter::empty()
            .chain(LiteralLengthCodes::code_to_value())
            .chain(MatchOffsetCodes::code_to_value())
            .chain(MatchLengthCodes::code_to_value())
            .map(|row| {
                [
                    Value::known(Fr::from(FixedLookupTag::SeqCodeToValue as u64)),
                    Value::known(Fr::from(row.table_kind as u64)),
                    Value::known(Fr::from(row.code)),
                    Value::known(Fr::from(row.baseline)),
                    Value::known(Fr::from(row.nb)),
                    Value::known(Fr::zero()),
                    Value::known(Fr::zero()),
                ]
            })
            .collect()
    }
}
