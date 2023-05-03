use halo2_proofs::{arithmetic::FieldExt, circuit::Value};

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    util::Challenges,
    witness::{
        tx::{SignedTxPreEip155, TxPreEip155},
        Format::{TxHashPreEip155, TxSignPreEip155},
        Tag::{
            BeginList, Data, EndList, Gas, GasPrice, Nonce, SigR, SigS, SigV, To, Value as TxValue,
        },
    },
};

use super::{RlpFsmWitnessGen, RomTableRow};

impl<F: FieldExt> RlpFsmWitnessGen<F> for TxPreEip155 {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<super::RlpFsmWitnessRow<F>> {
        unimplemented!()
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<super::DataTable<F>> {
        unimplemented!()
    }
}

impl<F: FieldExt> RlpFsmWitnessGen<F> for SignedTxPreEip155 {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<super::RlpFsmWitnessRow<F>> {
        unimplemented!()
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<super::DataTable<F>> {
        unimplemented!()
    }
}

pub fn tx_sign_rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxSignPreEip155).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxSignPreEip155).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxSignPreEip155).into(),
        (Gas, To, N_BYTES_U64, TxSignPreEip155).into(),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, TxSignPreEip155).into(),
        (TxValue, Data, N_BYTES_WORD, TxSignPreEip155).into(),
        (Data, EndList, 2usize.pow(24), TxSignPreEip155).into(),
        (EndList, BeginList, 0, TxSignPreEip155).into(),
    ]
}

pub fn tx_hash_rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxHashPreEip155).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxHashPreEip155).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxHashPreEip155).into(),
        (Gas, To, N_BYTES_U64, TxHashPreEip155).into(),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, TxHashPreEip155).into(),
        (TxValue, Data, N_BYTES_WORD, TxHashPreEip155).into(),
        (Data, SigV, 2usize.pow(24), TxHashPreEip155).into(),
        (SigV, SigR, N_BYTES_U64, TxHashPreEip155).into(),
        (SigR, SigS, N_BYTES_WORD, TxHashPreEip155).into(),
        (SigS, EndList, N_BYTES_WORD, TxHashPreEip155).into(),
        (EndList, BeginList, 0, TxHashPreEip155).into(),
    ]
}
