use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use super::{FixedLookupTag, FixedLookupValues};

pub struct RomFseTableTransition {
    /// The block index on the previous FSE table.
    pub block_idx_prev: u64,
    /// The block index on the current FSE table.
    pub block_idx_curr: u64,
    /// The FSE table previously decoded.
    pub table_kind_prev: u64,
    /// The FSE table currently decoded.
    pub table_kind_curr: u64,
}

impl FixedLookupValues for RomFseTableTransition {
    fn values() -> Vec<[Value<Fr>; 7]> {
        use crate::witgen::{
            FseTableKind::{LLT, MLT, MOT},
            N_MAX_BLOCKS,
        };

        (1..N_MAX_BLOCKS)
            .flat_map(|block_idx_curr| {
                let table_kind_prev = if block_idx_curr == 1 { None } else { Some(MLT) };
                [
                    (block_idx_curr - 1, block_idx_curr, table_kind_prev, LLT),
                    (block_idx_curr, block_idx_curr, Some(LLT), MOT),
                    (block_idx_curr, block_idx_curr, Some(MOT), MLT),
                ]
            })
            .map(
                |(block_idx_prev, block_idx_curr, table_kind_prev, table_kind_curr)| {
                    [
                        Value::known(Fr::from(FixedLookupTag::FseTableTransition as u64)),
                        Value::known(Fr::from(block_idx_prev)),
                        Value::known(Fr::from(block_idx_curr)),
                        Value::known(table_kind_prev.map_or(Fr::zero(), |v| Fr::from(v as u64))),
                        Value::known(Fr::from(table_kind_curr as u64)),
                        Value::known(Fr::zero()),
                        Value::known(Fr::zero()),
                    ]
                },
            )
            .collect()
    }
}
