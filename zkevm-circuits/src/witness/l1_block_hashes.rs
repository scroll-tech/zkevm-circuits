use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    witness::{
        rlp_fsm::{MAX_TAG_LENGTH_OF_LIST, N_BYTES_CALLDATA},
        Format::L1BlockHashesHash,
        RomTableRow,
        Tag::{BeginList, Data, EndList, Gas, Nonce, Sender, To, TxType, Value as TxValue},
    },
};
use ethers_core::utils::rlp::Encodable;

#[derive(Clone, Debug)]
pub struct L1BlockHashesTx;

impl Encodable for L1BlockHashesTx {
    fn rlp_append(&self, _s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}

pub fn rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (TxType, BeginList, 1, vec![1]),
        (BeginList, Nonce, MAX_TAG_LENGTH_OF_LIST, vec![2]),
        (Nonce, Gas, N_BYTES_U64, vec![3]),
        (Gas, To, N_BYTES_U64, vec![4]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![5]),
        (TxValue, Data, N_BYTES_WORD, vec![6]),
        (Data, Sender, N_BYTES_CALLDATA, vec![7]),
        (Sender, EndList, N_BYTES_ACCOUNT_ADDRESS, vec![8]),
        (EndList, EndList, 0, vec![9]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, L1BlockHashesHash, row.3).into())
        .collect()
}
