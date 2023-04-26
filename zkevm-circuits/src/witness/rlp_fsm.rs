use ethers_core::utils::rlp::Encodable;
use gadgets::{impl_expr, util::Expr};
use halo2_proofs::{arithmetic::FieldExt, circuit::Value, plonk::Expression};
use strum_macros::EnumIter;

use crate::util::Challenges;

mod common;
mod eip155;
mod eip1559;
mod eip2930;
mod l1_msg;
mod pre_eip155;

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum Tag {
    BeginList = 2,
    EndList,
    BeginVector,
    EndVector,
    // Pre EIP-155
    Nonce,
    GasPrice,
    Gas,
    To,
    Value,
    Data,
    // EIP-155
    ChainId,
    Zero1,
    Zero2,
    SigV,
    SigR,
    SigS,
    // EIP-2718
    TxType,
    // EIP-2930
    AccessListAddress,
    AccessListStorageKey,
    // EIP-1559
    MaxPriorityFeePerGas,
    MaxFeePerGas,
    // L1MsgHash
    GasLimit,
    Sender,
}

impl From<Tag> for usize {
    fn from(value: Tag) -> Self {
        value as usize
    }
}

impl Tag {
    pub fn is_list(&self) -> bool {
        match &self {
            Self::BeginList | Self::BeginVector | Self::EndList | Self::EndVector => true,
            _ => false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum RlpTag {
    Len,
    RLC,
    Tag(Tag),
}

impl RlpTag {
    pub fn is_output(&self) -> bool {
        match &self {
            Self::RLC => true,
            _ => false,
        }
    }
}

impl From<RlpTag> for usize {
    fn from(value: RlpTag) -> Self {
        match value {
            RlpTag::Len => 0,
            RlpTag::RLC => 1,
            RlpTag::Tag(tag) => usize::from(tag),
        }
    }
}

pub struct RomTableRow<F>(pub [Value<F>; 5]);

impl<F: FieldExt> From<(Tag, Tag, usize, Format)> for RomTableRow<F> {
    fn from(value: (Tag, Tag, usize, Format)) -> Self {
        Self([
            Value::known(F::from(usize::from(value.0) as u64)),
            Value::known(F::from(usize::from(value.1) as u64)),
            Value::known(F::from(value.2 as u64)),
            Value::known(F::from(u64::from(value.0.is_list()))),
            Value::known(F::from(usize::from(value.3) as u64)),
        ])
    }
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum Format {
    TxSignEip155 = 0,
    TxHashEip155,
    TxSignPreEip155,
    TxHashPreEip155,
    L1MsgHash,
}

impl From<Format> for usize {
    fn from(value: Format) -> Self {
        value as usize
    }
}

impl Format {
    pub fn rom_table_rows<F: FieldExt>(&self) -> Vec<RomTableRow<F>> {
        match self {
            Self::TxSignEip155 => eip155::tx_sign_rom_table_rows(),
            Self::TxHashEip155 => eip155::tx_hash_rom_table_rows(),
            Self::TxSignPreEip155 => pre_eip155::tx_sign_rom_table_rows(),
            Self::TxHashPreEip155 => pre_eip155::tx_hash_rom_table_rows(),
            Self::L1MsgHash => l1_msg::rom_table_rows(),
        }
    }
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum State {
    DecodeTagStart = 0,
    Bytes,
    LongBytes,
    LongList,
    End,
}

impl From<State> for usize {
    fn from(value: State) -> Self {
        value as usize
    }
}

impl_expr!(Tag);
impl_expr!(Format);
impl_expr!(State);
impl<F: FieldExt> Expr<F> for RlpTag {
    fn expr(&self) -> Expression<F> {
        match self {
            Self::Tag(tag) => tag.expr(),
            rlp_tag => Expression::Constant(F::from(usize::from(*rlp_tag) as u64)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DataTable<F: FieldExt> {
    pub tx_id: u64,
    pub format: Format,
    pub byte_idx: usize,
    pub byte_rev_idx: usize,
    pub byte_value: u8,
    pub bytes_rlc: Value<F>,
}

#[derive(Clone, Copy, Debug)]
pub struct RlpTable<F: FieldExt> {
    pub tx_id: u64,
    pub format: Format,
    pub rlp_tag: RlpTag,
    pub tag_value_acc: Value<F>,
    pub is_output: bool,
    pub is_none: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct StateMachine<F: FieldExt> {
    pub state: State,
    pub tag: Tag,
    pub tag_next: Tag,
    pub byte_idx: usize,
    pub byte_rev_idx: usize,
    pub byte_value: u8,
    pub tag_idx: usize,
    pub tag_length: usize,
    pub depth: usize,
    pub bytes_rlc: Value<F>,
}

/// Represents the witness in a single row of the RLP circuit.
#[derive(Clone, Debug)]
pub struct RlpFsmWitnessRow<F: FieldExt> {
    pub rlp_table: RlpTable<F>,
    pub state_machine: StateMachine<F>,
}

/// The RlpFsmWitnessGen trait is implemented by data types who's RLP encoding can
/// be verified by the RLP-encoding circuit.
pub trait RlpFsmWitnessGen<F: FieldExt>: Encodable + Sized {
    /// Generate witness to the RLP-encoding verifier circuit, as a vector of
    /// RlpFsmWitnessRow.
    fn gen_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<RlpFsmWitnessRow<F>>;
}
