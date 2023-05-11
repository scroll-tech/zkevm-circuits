use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    witness::{
        Format::L1MsgHash,
        RomTableRow,
        Tag::{BeginList, Data, EndList, GasLimit, Nonce, Sender, To, TxType, Value as TxValue},
    },
};
use ethers_core::utils::rlp::Encodable;

#[derive(Clone, Debug)]
pub struct L1MsgTx;

impl Encodable for L1MsgTx {
    fn rlp_append(&self, s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}

pub fn rom_table_rows() -> Vec<RomTableRow> {
    vec![
        (TxType, BeginList, 1, L1MsgHash, vec![1]).into(),
        (BeginList, Sender, 0, L1MsgHash, vec![2]).into(),
        (Sender, To, N_BYTES_ACCOUNT_ADDRESS, L1MsgHash, vec![3]).into(),
        (To, Nonce, N_BYTES_ACCOUNT_ADDRESS, L1MsgHash, vec![4]).into(),
        (Nonce, GasLimit, N_BYTES_U64, L1MsgHash, vec![5]).into(),
        (GasLimit, TxValue, N_BYTES_U64, L1MsgHash, vec![6]).into(),
        (TxValue, Data, N_BYTES_WORD, L1MsgHash, vec![7]).into(),
        (Data, EndList, 2usize.pow(24), L1MsgHash, vec![8]).into(),
        (EndList, BeginList, 0, L1MsgHash, vec![]).into(),
    ]
}
