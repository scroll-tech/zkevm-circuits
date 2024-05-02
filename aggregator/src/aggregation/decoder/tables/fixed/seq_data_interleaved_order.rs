use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::{
    tables::fixed::{FixedLookupTag, FixedLookupValues},
    witgen::FseTableKind,
};

pub struct RomSeqDataInterleavedOrder {
    /// FSE table used in the previous bitstring.
    table_kind_prev: FseTableKind,
    /// FSE table used in the current bitstring.
    table_kind_curr: FseTableKind,
    /// Boolean flag to indicate whether we are initialising the FSE state.
    is_init_state: bool,
    /// Boolean flag to indicate whether we are updating the FSE state.
    is_update_state: bool,
}

impl FixedLookupValues for RomSeqDataInterleavedOrder {
    fn values() -> Vec<[Value<Fr>; 7]> {
        use FseTableKind::{LLT, MLT, MOT};

        [
            // init stat (LLT)
            vec![[
                Value::known(Fr::from(FixedLookupTag::SeqDataInterleavedOrder as u64)),
                Value::known(Fr::zero()),           // table_kind_prev
                Value::known(Fr::from(LLT as u64)), // table_kind_curr
                Value::known(Fr::one()),            // is_init_state
                Value::known(Fr::zero()),           // is_update_state
                Value::known(Fr::zero()),
                Value::known(Fr::zero()),
            ]],
            [
                (LLT, MOT, true, false), // init state (MOT)
                (MOT, MLT, true, false), // init state (MLT)
                (MLT, MOT, false, false),
                (MOT, MLT, false, false),
                (MLT, LLT, false, false),
                (LLT, LLT, false, true),
                (LLT, MLT, false, true),
                (MLT, MOT, false, true),
                (MOT, MOT, false, false),
            ]
            .map(
                |(table_kind_prev, table_kind_curr, is_init_state, is_update_state)| {
                    [
                        Value::known(Fr::from(FixedLookupTag::SeqDataInterleavedOrder as u64)),
                        Value::known(Fr::from(table_kind_prev as u64)),
                        Value::known(Fr::from(table_kind_curr as u64)),
                        Value::known(Fr::from(is_init_state as u64)),
                        Value::known(Fr::from(is_update_state as u64)),
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
