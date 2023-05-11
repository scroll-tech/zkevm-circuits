use eth_types::Field;
use gadgets::{impl_expr, util::Expr};
use halo2_proofs::{arithmetic::FieldExt, circuit::Value, plonk::Expression};
use strum_macros::EnumIter;

use crate::util::Challenges;

/// RLP tags
#[derive(Default, Clone, Copy, Debug, EnumIter, PartialEq, Eq)]
pub enum Tag {
    #[default]
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
    // TODO: merge zero1 and zero2 into one tag
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

    /// If the tag is BeginList or BeginVector
    pub fn is_begin(&self) -> bool {
        match &self {
            Self::BeginList | Self::BeginVector => true,
            _ => false,
        }
    }

    /// If the tag is EndList or EndVector
    pub fn is_end(&self) -> bool {
        match &self {
            Self::EndList | Self::EndVector => true,
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

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    witness::{
        l1_msg,
        Format::{TxHashEip155, TxHashEip1559, TxHashPreEip155, TxSignEip155, TxSignPreEip155},
        Tag::{
            AccessListAddress, AccessListStorageKey, BeginList, BeginVector, ChainId, Data,
            EndList, EndVector, Gas, GasPrice, MaxFeePerGas, MaxPriorityFeePerGas, Nonce, SigR,
            SigS, SigV, To, TxType, Value as TxValue, Zero1, Zero2,
        },
    },
};

fn eip155_tx_sign_rom_table_rows() -> Vec<RomTableRow> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxSignEip155, vec![1]).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxSignEip155, vec![2]).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxSignEip155, vec![3]).into(),
        (Gas, To, N_BYTES_U64, TxSignEip155, vec![4]).into(),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, TxSignEip155, vec![5]).into(),
        (TxValue, Data, N_BYTES_WORD, TxSignEip155, vec![6]).into(),
        (Data, ChainId, 2usize.pow(24), TxSignEip155, vec![7]).into(),
        (ChainId, Zero1, N_BYTES_U64, TxSignEip155, vec![8]).into(),
        (Zero1, Zero2, 1, TxSignEip155, vec![9]).into(),
        (Zero2, EndList, 1, TxSignEip155, vec![10]).into(),
        (EndList, BeginList, 0, TxSignEip155, vec![]).into(),
    ]
}

fn eip155_tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxHashEip155, vec![1]).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxHashEip155, vec![2]).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxHashEip155, vec![3]).into(),
        (Gas, To, N_BYTES_U64, TxHashEip155, vec![4]).into(),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, TxHashEip155, vec![5]).into(),
        (TxValue, Data, N_BYTES_WORD, TxHashEip155, vec![6]).into(),
        (Data, SigV, 2usize.pow(24), TxHashEip155, vec![7]).into(),
        (SigV, SigR, N_BYTES_U64, TxHashEip155, vec![8]).into(),
        (SigR, SigS, N_BYTES_WORD, TxHashEip155, vec![9]).into(),
        (SigS, EndList, N_BYTES_WORD, TxHashEip155, vec![10]).into(),
        (EndList, BeginList, 0, TxHashEip155, vec![]).into(),
    ]
}

pub fn pre_eip155_tx_sign_rom_table_rows() -> Vec<RomTableRow> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxSignPreEip155, vec![1]).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxSignPreEip155, vec![2]).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxSignPreEip155, vec![3]).into(),
        (Gas, To, N_BYTES_U64, TxSignPreEip155, vec![4]).into(),
        (
            To,
            TxValue,
            N_BYTES_ACCOUNT_ADDRESS,
            TxSignPreEip155,
            vec![5],
        )
            .into(),
        (TxValue, Data, N_BYTES_WORD, TxSignPreEip155, vec![6]).into(),
        (Data, EndList, 2usize.pow(24), TxSignPreEip155, vec![7]).into(),
        (EndList, BeginList, 0, TxSignPreEip155, vec![]).into(),
    ]
}

pub fn pre_eip155_tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    vec![
        (BeginList, Nonce, N_BYTES_U64, TxHashPreEip155, vec![1]).into(),
        (Nonce, GasPrice, N_BYTES_U64, TxHashPreEip155, vec![2]).into(),
        (GasPrice, Gas, N_BYTES_WORD, TxHashPreEip155, vec![3]).into(),
        (Gas, To, N_BYTES_U64, TxHashPreEip155, vec![4]).into(),
        (
            To,
            TxValue,
            N_BYTES_ACCOUNT_ADDRESS,
            TxHashPreEip155,
            vec![5],
        )
            .into(),
        (TxValue, Data, N_BYTES_WORD, TxHashPreEip155, vec![6]).into(),
        (Data, SigV, 2usize.pow(24), TxHashPreEip155, vec![7]).into(),
        (SigV, SigR, N_BYTES_U64, TxHashPreEip155, vec![8]).into(),
        (SigR, SigS, N_BYTES_WORD, TxHashPreEip155, vec![9]).into(),
        (SigS, EndList, N_BYTES_WORD, TxHashPreEip155, vec![10]).into(),
        (EndList, BeginList, 0, TxHashPreEip155, vec![]).into(),
    ]
}

pub fn eip1559_tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    vec![
        (TxType, BeginList, 1, TxHashEip1559, vec![1]).into(),
        (BeginList, ChainId, 8, TxHashEip1559, vec![2]).into(),
        (ChainId, Nonce, N_BYTES_U64, TxHashEip1559, vec![3]).into(),
        (
            Nonce,
            MaxPriorityFeePerGas,
            N_BYTES_U64,
            TxHashEip1559,
            vec![4],
        )
            .into(),
        (
            MaxPriorityFeePerGas,
            MaxFeePerGas,
            N_BYTES_WORD,
            TxHashEip1559,
            vec![5],
        )
            .into(),
        (MaxFeePerGas, Gas, N_BYTES_WORD, TxHashEip1559, vec![6]).into(),
        (Gas, To, N_BYTES_U64, TxHashEip1559, vec![7]).into(),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, TxHashEip1559, vec![8]).into(),
        (TxValue, Data, N_BYTES_WORD, TxHashEip1559, vec![9]).into(),
        (
            Data,
            BeginVector,
            2usize.pow(24),
            TxHashEip1559,
            vec![10, 11],
        )
            .into(),
        (BeginVector, EndVector, 8, TxHashEip1559, vec![21]).into(), // access_list is none
        (BeginVector, BeginList, 8, TxHashEip1559, vec![12]).into(),
        (BeginList, AccessListAddress, 8, TxHashEip1559, vec![13]).into(),
        (
            AccessListAddress,
            BeginVector,
            N_BYTES_ACCOUNT_ADDRESS,
            TxHashEip1559,
            vec![14, 15],
        )
            .into(),
        (BeginVector, EndVector, 8, TxHashEip1559, vec![18]).into(), /* access_list.storage_keys
                                                                      * is none */
        (
            BeginVector,
            AccessListStorageKey,
            8,
            TxHashEip1559,
            vec![16, 17],
        )
            .into(),
        (
            AccessListStorageKey,
            EndVector,
            N_BYTES_WORD,
            TxHashEip1559,
            vec![18],
        )
            .into(), // finished parsing storage keys
        (
            AccessListStorageKey,
            AccessListStorageKey,
            N_BYTES_WORD,
            TxHashEip1559,
            vec![16, 17],
        )
            .into(), // keep parsing storage_keys
        (EndVector, EndList, 0, TxHashEip1559, vec![19, 20]).into(),
        (EndList, EndVector, 0, TxHashEip1559, vec![21]).into(), // finished parsing access_list
        (EndList, BeginList, 0, TxHashEip1559, vec![12]).into(), // parse another access_list entry
        (EndVector, EndList, 0, TxHashEip1559, vec![22]).into(),
        (EndList, BeginList, 0, TxHashEip1559, vec![]).into(),
    ]
}

/// Read-only Memory table row.
#[derive(Debug, Clone)]
pub struct RomTableRow {
    pub(crate) tag: Tag,
    pub(crate) tag_next: Tag,
    pub(crate) tag_next_idx: Vec<usize>,
    pub(crate) max_length: usize,
    pub(crate) is_list: bool,
    pub(crate) format: Format,
}

impl From<(Tag, Tag, usize, Format, Vec<usize>)> for RomTableRow {
    fn from(value: (Tag, Tag, usize, Format, Vec<usize>)) -> Self {
        Self {
            tag: value.0,
            tag_next: value.1,
            tag_next_idx: value.4,
            max_length: value.2,
            is_list: value.0.is_list(),
            format: value.3,
        }
    }
}

impl RomTableRow {
    pub(crate) fn values<F: Field>(&self) -> Vec<Value<F>> {
        vec![
            Value::known(F::from(usize::from(self.tag) as u64)),
            Value::known(F::from(usize::from(self.tag_next) as u64)),
            Value::known(F::from(self.max_length as u64)),
            Value::known(F::from(self.is_list as u64)),
            Value::known(F::from(usize::from(self.format) as u64)),
        ]
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
    /// Sign for EIP1559 tx
    TxSignEip1559,
    /// Hash for EIP1559 tx
    TxHashEip1559,
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
    pub fn rom_table_rows(&self) -> Vec<RomTableRow> {
        match self {
            TxSignEip155 => eip155_tx_sign_rom_table_rows(),
            TxHashEip155 => eip155_tx_hash_rom_table_rows(),
            TxSignPreEip155 => pre_eip155_tx_sign_rom_table_rows(),
            TxHashPreEip155 => pre_eip155_tx_hash_rom_table_rows(),
            TxHashEip1559 => eip1559_tx_hash_rom_table_rows(),
            TxSignEip1559 => unimplemented!(),
            Self::L1MsgHash => l1_msg::rom_table_rows(),
        }
    }
}

/// All possible states of RLP decoding state machine
#[derive(Clone, Copy, Debug, EnumIter, PartialEq, Eq)]
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
pub trait RlpFsmWitnessGen<F: FieldExt>: Sized {
    /// Generate witness to the RLP state machine, as a vector of RlpFsmWitnessRow.
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<RlpFsmWitnessRow<F>>;

    /// Generate witness to the Data table that RLP circuit does lookup into.
    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<DataTable<F>>;
}

#[derive(Clone)]
pub(crate) struct SmState<F: Field> {
    pub(crate) tag: Tag,
    pub(crate) state: State,
    pub(crate) byte_idx: usize,
    pub(crate) depth: usize,
    pub(crate) tag_idx: usize,
    pub(crate) tag_length: usize,
    pub(crate) tag_value_acc: Value<F>,
}
