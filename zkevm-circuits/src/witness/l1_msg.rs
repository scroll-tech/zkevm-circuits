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
