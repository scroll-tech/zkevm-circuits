use ethers_core::utils::rlp;
use halo2_proofs::{arithmetic::FieldExt, circuit::Value};

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    util::Challenges,
    witness::{
        tx::{SignedTxEip155, TxEip155},
        Format::{TxHashEip155, TxSignEip155},
        Tag::{
            BeginList, ChainId, Data, EndList, Gas, GasPrice, Nonce, SigR, SigS, SigV, To,
            Value as TxValue, Zero1, Zero2,
        },
    },
};

use super::{DataTable, RlpFsmWitnessGen, RlpFsmWitnessRow, RomTableRow};

impl<F: FieldExt> RlpFsmWitnessGen<F> for TxEip155 {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<RlpFsmWitnessRow<F>> {
        let transaction = self.0.clone();

        unimplemented!()
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<DataTable<F>> {
        let tx_id = self.0.id as u64;
        let rlp_encoding = rlp::encode(self);
        let n = rlp_encoding.len();
        let r = challenges.keccak_input();
        let mut bytes_rlc = Value::known(F::zero());
        rlp_encoding
            .as_ref()
            .iter()
            .enumerate()
            .map(|(i, &byte_value)| {
                bytes_rlc = bytes_rlc * r + Value::known(F::from(byte_value as u64));
                DataTable {
                    tx_id,
                    format: TxSignEip155,
                    byte_idx: i + 1,
                    byte_rev_idx: n - i,
                    byte_value,
                    bytes_rlc,
                }
            })
            .collect()
    }
}

impl<F: FieldExt> RlpFsmWitnessGen<F> for SignedTxEip155 {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<RlpFsmWitnessRow<F>> {
        let transaction = self.0.tx.clone();
        let signature = self.0.signature.clone();

        unimplemented!()
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<super::DataTable<F>> {
        let tx_id = self.0.tx.id as u64;
        let rlp_encoding = rlp::encode(self);
        let n = rlp_encoding.len();
        let r = challenges.keccak_input();
        let mut bytes_rlc = Value::known(F::zero());
        rlp_encoding
            .as_ref()
            .iter()
            .enumerate()
            .map(|(i, &byte_value)| {
                bytes_rlc = bytes_rlc * r + Value::known(F::from(byte_value as u64));
                DataTable {
                    tx_id,
                    format: TxHashEip155,
                    byte_idx: i + 1,
                    byte_rev_idx: n - i,
                    byte_value,
                    bytes_rlc,
                }
            })
            .collect()
    }
}

pub fn tx_sign_rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxSignEip155).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxSignEip155).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxSignEip155).into(),
        (Gas, To, N_BYTES_U64, TxSignEip155).into(),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, TxSignEip155).into(),
        (TxValue, Data, N_BYTES_WORD, TxSignEip155).into(),
        (Data, ChainId, 2usize.pow(24), TxSignEip155).into(),
        (ChainId, Zero1, N_BYTES_U64, TxSignEip155).into(),
        (Zero1, Zero2, 1, TxSignEip155).into(),
        (Zero2, EndList, 1, TxSignEip155).into(),
        (EndList, BeginList, 0, TxSignEip155).into(),
    ]
}

pub fn tx_hash_rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxHashEip155).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxHashEip155).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxHashEip155).into(),
        (Gas, To, N_BYTES_U64, TxHashEip155).into(),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, TxHashEip155).into(),
        (TxValue, Data, N_BYTES_WORD, TxHashEip155).into(),
        (Data, SigV, 2usize.pow(24), TxHashEip155).into(),
        (SigV, SigR, N_BYTES_U64, TxHashEip155).into(),
        (SigR, SigS, N_BYTES_WORD, TxHashEip155).into(),
        (SigS, EndList, N_BYTES_WORD, TxHashEip155).into(),
        (EndList, BeginList, 0, TxHashEip155).into(),
    ]
}
