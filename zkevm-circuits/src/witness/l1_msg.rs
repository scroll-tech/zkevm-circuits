use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    witness::{
        Format::L1MsgHash,
        RomTableRow,
        Tag::{BeginList, Data, EndList, Gas, Nonce, Sender, To, TxType, Value as TxValue},
    },
};
use ethers_core::utils::rlp::Encodable;

#[derive(Clone, Debug)]
pub struct L1MsgTx;

impl Encodable for L1MsgTx {
    fn rlp_append(&self, _s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}

pub fn rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (TxType, BeginList, 1, vec![1]),
        (BeginList, Nonce, 8, vec![2]),
        (Nonce, Gas, N_BYTES_U64, vec![3]),
        (Gas, To, N_BYTES_U64, vec![4]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![5]),
        (TxValue, Data, N_BYTES_WORD, vec![6]),
        (Data, Sender, 2usize.pow(24), vec![7]),
        (Sender, EndList, N_BYTES_ACCOUNT_ADDRESS, vec![8]),
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, L1MsgHash, row.3).into())
        .collect()
}
