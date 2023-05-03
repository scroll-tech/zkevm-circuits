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

/// RLP tags
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum Tag {
    /// Tag that marks the beginning of a list
    /// whose value gives the length of bytes of this list.
    BeginList = 2,
    /// Tag that marks the ending of a list and
    /// it does not consume any byte.
    EndList,
    /// Special case of BeginList in which each item's key is
    /// an increasing integer starting from 1.
    BeginVector,
    /// Special case of EndList
    EndVector,

    // Pre EIP-155
    /// Nonce
    Nonce,
    /// Gas price
    GasPrice,
    /// Gas limit
    Gas,
    /// To
    To,
    /// Value
    Value,
    /// Data
    Data,
    // EIP-155
    /// Chain ID
    ChainId,
    /// One byte whose value is zero
    Zero1,
    /// One byte whose value is zero
    Zero2,
    /// Signature v
    SigV,
    /// Signature r
    SigR,
    /// Signature s
    SigS,

    // EIP-2718
    /// Tx type
    TxType,
    // EIP-2930
    /// Address in access_list
    AccessListAddress,
    /// Storage key in access_list
    AccessListStorageKey,

    // EIP-1559
    /// Max priority fee per gas
    MaxPriorityFeePerGas,
    /// Max fee per gas
    MaxFeePerGas,

    // L1MsgHash
    /// Gas limit
    GasLimit,
    /// Sender
    Sender,
}

impl From<Tag> for usize {
    fn from(value: Tag) -> Self {
        value as usize
    }
}

impl Tag {
    /// If the tag is related to list
    pub fn is_list(&self) -> bool {
        match &self {
            Self::BeginList | Self::BeginVector | Self::EndList | Self::EndVector => true,
            _ => false,
        }
    }
}

/// RLP tags
#[derive(Clone, Copy, Debug)]
pub enum RlpTag {
    /// Length of RLP bytes
    Len,
    /// RLC of RLP bytes
    RLC,
    /// Tag
    Tag(Tag),
}

impl RlpTag {
    /// If this tag is for output
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

/// Read-only Memory table row.
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

/// Format that we are able to decode
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum Format {
    /// Sign for EIP155 tx
    TxSignEip155 = 0,
    /// Hash for EIP155 tx
    TxHashEip155,
    /// Sign for Pre-EIP155 tx
    TxSignPreEip155,
    /// Hash for Pre-EIP155 tx
    TxHashPreEip155,
    /// L1 Msg
    L1MsgHash,
}

impl From<Format> for usize {
    fn from(value: Format) -> Self {
        value as usize
    }
}

impl Format {
    /// The ROM table for format
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

/// All possible states of RLP decoding state machine
#[derive(Clone, Copy, Debug, EnumIter)]
pub enum State {
    /// Start
    DecodeTagStart = 0,
    /// Bytes
    Bytes,
    /// Long bytes
    LongBytes,
    /// Long list
    LongList,
    /// End
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

/// Data table holds the raw RLP bytes
#[derive(Clone, Copy, Debug)]
pub struct DataTable<F: FieldExt> {
    /// The index of tx to be decoded
    pub tx_id: u64,
    /// The format of format to be decoded
    pub format: Format,
    /// The index of raw RLP bytes (starting from 1)
    pub byte_idx: usize,
    /// The reverse index of raw RLP bytes (ends at 1)
    pub byte_rev_idx: usize,
    /// The byte value
    pub byte_value: u8,
    /// RLC of raw RLP bytes up to `byte_idx`
    pub bytes_rlc: Value<F>,
}

/// RLP table that is connected to the state machine in the RLP circuit.
#[derive(Clone, Copy, Debug)]
pub struct RlpTable<F: FieldExt> {
    /// The index of tx we decoded
    pub tx_id: u64,
    /// The format of format we decoded
    pub format: Format,
    /// The RLP tag we decoded
    pub rlp_tag: RlpTag,
    /// The tag's accumulated value
    pub tag_value_acc: Value<F>,
    /// If current row is for output
    pub is_output: bool,
    /// If current tag's value is None.
    pub is_none: bool,
}

/// State Machine
#[derive(Clone, Copy, Debug)]
pub struct StateMachine<F: FieldExt> {
    /// Current state
    pub state: State,
    /// Current tag to be decoded
    pub tag: Tag,
    /// Next tag to be decoded
    pub tag_next: Tag,
    /// The index of current byte we are reading
    pub byte_idx: usize,
    /// The reverse index of current byte we are reading
    pub byte_rev_idx: usize,
    /// The value of current byte we are reading
    pub byte_value: u8,
    /// The index of the actual bytes of tag
    pub tag_idx: usize,
    /// The length of the actual bytes of tag
    pub tag_length: usize,
    /// The depth
    pub depth: usize,
    /// The RLC of bytes up to `byte_idx`
    pub bytes_rlc: Value<F>,
}

/// Represents the witness in a single row of the RLP circuit.
#[derive(Clone, Debug)]
pub struct RlpFsmWitnessRow<F: FieldExt> {
    /// Witness to the RLP table.
    pub rlp_table: RlpTable<F>,
    /// The state machine witness.
    pub state_machine: StateMachine<F>,
}

/// The RlpFsmWitnessGen trait is implemented by data types who's RLP encoding can
/// be verified by the RLP-encoding circuit.
pub trait RlpFsmWitnessGen<F: FieldExt>: Encodable + Sized {
    /// Generate witness to the RLP state machine, as a vector of RlpFsmWitnessRow.
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<RlpFsmWitnessRow<F>>;

    /// Generate witness to the Data table that RLP circuit does lookup into.
    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<DataTable<F>>;
}
