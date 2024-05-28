use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::{
    tables::fixed::FixedLookupTag,
    witgen::{FseTableKind, ZstdTag},
};

use super::FixedLookupValues;

/// The possible orders are:
///
/// - (1, 1, 1):
///     - SequenceHeader > FseCode > FseCode (LLT)
///     - FseCode > FseCode > FseCode (MOT)
///     - FseCode > FseCode > SequenceData (MLT)
/// - (1, 1, 0):
///     - SequenceHeader > FseCode > FseCode (LLT)
///     - FseCode > FseCode > SequenceData (MOT)
/// - (1, 0, 1):
///     - SequenceHeader > FseCode > FseCode (LLT)
///     - FseCode > FseCode > SequenceData (MLT)
/// - (0, 1, 1):
///     - SequenceHeader > FseCode > FseCode (MOT)
///     - FseCode > FseCode > SequenceData (MLT)
/// - (1, 0, 0):
///     - SequenceHeader > FseCode > SequenceData (LLT)
/// - (0, 1, 0):
///     - SequenceHeader > FseCode > SequenceData (MOT)
/// - (0, 0, 1):
///     - SequenceHeader > FseCode > SequenceData (MLT)
pub struct RomSeqTagOrder {
    /// Boolean flag to mark if LLT is Fse_Compressed_Mode or Predefined_Mode.
    pub cmode_llt: bool,
    /// Boolean flag to mark if MOT is Fse_Compressed_Mode or Predefined_Mode.
    pub cmode_mot: bool,
    /// Boolean flag to mark if MLT is Fse_Compressed_Mode or Predefined_Mode.
    pub cmode_mlt: bool,
    /// Tag that was handled before the current tag.
    pub tag_prev: ZstdTag,
    /// Tag currently being handled.
    pub tag_curr: ZstdTag,
    /// Tag that will be handled after the current tag.
    pub tag_next: ZstdTag,
    /// The FSE table that we expect with the current tag.
    pub fse_table: FseTableKind,
}

impl FixedLookupValues for RomSeqTagOrder {
    fn values() -> Vec<[Value<Fr>; 7]> {
        use FseTableKind::{LLT, MLT, MOT};
        use ZstdTag::{
            ZstdBlockSequenceData as SeqData, ZstdBlockSequenceFseCode as FseCode,
            ZstdBlockSequenceHeader as SeqHeader,
        };

        [
            // (1, 1, 1)
            (1, 1, 1, SeqHeader, FseCode, FseCode, LLT),
            (1, 1, 1, FseCode, FseCode, FseCode, MOT),
            (1, 1, 1, FseCode, FseCode, SeqData, MLT),
            // (1, 1, 0)
            (1, 1, 0, SeqHeader, FseCode, FseCode, LLT),
            (1, 1, 0, FseCode, FseCode, SeqData, MOT),
            // (1, 0, 1)
            (1, 0, 1, SeqHeader, FseCode, FseCode, LLT),
            (1, 0, 1, FseCode, FseCode, SeqData, MLT),
            // (0, 1, 1)
            (0, 1, 1, SeqHeader, FseCode, FseCode, MOT),
            (0, 1, 1, FseCode, FseCode, SeqData, MLT),
            // (1, 0, 0)
            (1, 0, 0, SeqHeader, FseCode, SeqData, LLT),
            // (0, 1, 0)
            (0, 1, 0, SeqHeader, FseCode, SeqData, MOT),
            // (0, 0, 1)
            (0, 0, 1, SeqHeader, FseCode, SeqData, MLT),
        ]
        .map(
            |(cmode_llt, cmode_mot, cmode_mlt, tag_prev, tag_curr, tag_next, table_kind)| {
                let cmode_lc = 4 * cmode_llt + 2 * cmode_mot + cmode_mlt;
                [
                    Value::known(Fr::from(FixedLookupTag::SeqTagOrder as u64)),
                    Value::known(Fr::from(cmode_lc)),
                    Value::known(Fr::from(tag_prev as u64)),
                    Value::known(Fr::from(tag_curr as u64)),
                    Value::known(Fr::from(tag_next as u64)),
                    Value::known(Fr::from(table_kind as u64)),
                    Value::known(Fr::zero()),
                ]
            },
        )
        .to_vec()
    }
}
