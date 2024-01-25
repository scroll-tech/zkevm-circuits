//! Witness for all circuits.
//! The `Block<F>` is the witness struct post-processed from geth traces and
//! used to generate witnesses for circuits.

mod block;
pub use block::{
    block_apply_mpt_state, block_convert, block_convert_with_l1_queue_index,
    block_mocking_apply_mpt, Block, BlockContext, BlockContexts,
};

mod bytecode;
pub use bytecode::Bytecode;

mod call;
pub use call::Call;

mod mpt;
pub use mpt::{MptUpdate, MptUpdateRow, MptUpdates, WithdrawProof};

mod receipt;
pub use receipt::Receipt;

pub(crate) mod rlp_fsm;
pub use rlp_fsm::{
    DataTable, Format, RlpFsmWitnessGen, RlpFsmWitnessRow, RlpTable, RlpTag, RomTableRow, State,
    StateMachine, Tag,
};

mod rw;
pub use rw::{Rw, RwMap, RwRow};

mod step;
pub use step::ExecStep;

mod l1_msg;
mod tx;

pub use tx::Transaction;

mod zstd;
pub use zstd::{
    FseAuxiliaryTableData, FseSymbol, FseTableData, FseTableRow, HuffmanCodesData, TagRomTableRow,
    ZstdTag, N_BITS_PER_BYTE, N_BITS_SYMBOL, N_BITS_ZSTD_TAG, N_BLOCK_HEADER_BYTES, N_MAX_SYMBOLS,
};
