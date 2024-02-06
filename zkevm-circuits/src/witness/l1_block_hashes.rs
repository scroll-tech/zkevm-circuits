use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_WORD},
    witness::{
        rlp_fsm::{MAX_TAG_LENGTH_OF_LIST, N_BYTES_CALLDATA},
        Format::L1BlockHashesHash,
        RomTableRow,
        Tag::{BeginList, Sender, LastAppliedL1Block, Data, EndList, 
          BlockRangeHash, FirstAppliedL1Block, To, TxType, BeginVector, EndVector},
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
        (BeginList, FirstAppliedL1Block, MAX_TAG_LENGTH_OF_LIST, vec![2]),
        (FirstAppliedL1Block, LastAppliedL1Block, N_BYTES_WORD, vec![3]),
        (LastAppliedL1Block, BeginVector, N_BYTES_WORD, vec![4, 5]),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![8]), // 
        (BeginVector, BlockRangeHash, MAX_TAG_LENGTH_OF_LIST, vec![6, 7]),
        (BlockRangeHash, EndVector, N_BYTES_WORD, vec![8]),
        (
            BlockRangeHash,
            BlockRangeHash,
            N_BYTES_WORD,
            vec![6, 7],
        ), 
        (EndVector, To, 0, vec![9]),
        (To, Data, N_BYTES_ACCOUNT_ADDRESS, vec![10]),
        (Data, Sender, N_BYTES_CALLDATA, vec![11]),
        (Sender, EndList, N_BYTES_ACCOUNT_ADDRESS, vec![12]),
        (EndList, EndList, 0, vec![13]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, L1BlockHashesHash, row.3).into())
        .collect()
}
