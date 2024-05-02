use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::witgen::FseTableKind;

use super::{FixedLookupTag, FixedLookupValues};

pub struct RomFseTableTransition {
    /// The block index on the previous FSE table.
    block_idx_prev: u64,
    /// The block index on the current FSE table.
    block_idx_curr: u64,
    /// The FSE table previously decoded.
    table_kind_prev: u64,
    /// The FSE table currently decoded.
    table_kind_curr: u64,
}

impl FixedLookupValues for RomFseTableTransition {
    fn values() -> Vec<[Value<Fr>; 7]> {
        [
            vec![[
                Value::known(Fr::from(FixedLookupTag::FseTableTransition as u64)),
                Value::known(Fr::zero()), // block_idx_prev
                Value::known(Fr::one()),  // block_idx_curr
                Value::known(Fr::zero()), // table_kind_prev
                Value::known(Fr::from(FseTableKind::LLT as u64)),
                Value::known(Fr::zero()),
                Value::known(Fr::zero()),
            ]],
            [
                (1, 1, FseTableKind::LLT, FseTableKind::MOT),
                (1, 1, FseTableKind::MOT, FseTableKind::MLT),
                // TODO: add more for multi-block scenario
            ]
            .map(
                |(block_idx_prev, block_idx_curr, table_kind_prev, table_kind_curr)| {
                    [
                        Value::known(Fr::from(FixedLookupTag::FseTableTransition as u64)),
                        Value::known(Fr::from(block_idx_prev)),
                        Value::known(Fr::from(block_idx_curr)),
                        Value::known(Fr::from(table_kind_prev as u64)),
                        Value::known(Fr::from(table_kind_curr as u64)),
                        Value::known(Fr::zero()),
                        Value::known(Fr::zero()),
                    ]
                },
            )
            .to_vec(),
        ]
        .concat()
    }
}
