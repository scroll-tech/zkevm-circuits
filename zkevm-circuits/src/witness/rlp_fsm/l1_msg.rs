use halo2_proofs::{arithmetic::FieldExt, circuit::Value};

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    util::Challenges,
    witness::{
        tx::L1MsgTx,
        Format::L1MsgHash,
        Tag::{BeginList, Data, EndList, GasLimit, Nonce, Sender, To, TxType, Value as TxValue},
    },
};

use super::{RlpFsmWitnessGen, RomTableRow};

impl<F: FieldExt> RlpFsmWitnessGen<F> for L1MsgTx {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<super::RlpFsmWitnessRow<F>> {
        unimplemented!()
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<super::DataTable<F>> {
        unimplemented!()
    }
}

pub fn rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    vec![
        (TxType, BeginList, 1, L1MsgHash).into(),
        (BeginList, Sender, 0, L1MsgHash).into(),
        (Sender, To, N_BYTES_ACCOUNT_ADDRESS, L1MsgHash).into(),
        (To, Nonce, N_BYTES_ACCOUNT_ADDRESS, L1MsgHash).into(),
        (Nonce, GasLimit, N_BYTES_U64, L1MsgHash).into(),
        (GasLimit, TxValue, N_BYTES_U64, L1MsgHash).into(),
        (TxValue, Data, N_BYTES_WORD, L1MsgHash).into(),
        (Data, EndList, 2usize.pow(24), L1MsgHash).into(),
    ]
}
