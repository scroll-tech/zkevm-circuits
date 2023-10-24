use eth_types::{Address, Field, H160, U256};
use gadgets::{impl_expr, util::Expr};
use halo2_proofs::{arithmetic::FieldExt, circuit::Value, plonk::Expression};
use strum_macros::EnumIter;

use crate::util::Challenges;

pub(crate) trait ValueTagLength {
    fn tag_length(&self) -> u32;
}

impl ValueTagLength for u64 {
    fn tag_length(&self) -> u32 {
        // note that 0_u64 is encoded as [0x80] in RLP
        // see the relevant code at https://github.com/paritytech/parity-common/blob/master/rlp/src/impls.rs#L208
        (64 - self.leading_zeros() + 7) / 8
    }
}

impl ValueTagLength for usize {
    fn tag_length(&self) -> u32 {
        // usize is treated as same as u64
        (*self as u64).tag_length()
    }
}

impl ValueTagLength for U256 {
    fn tag_length(&self) -> u32 {
        // note that U256::zero() is encoded as [0x80] in RLP
        // see the relevant code at https://github.com/paritytech/parity-common/blob/impl-rlp-v0.3.0/primitive-types/src/lib.rs#L117
        (256 - self.leading_zeros() + 7) / 8
    }
}

impl ValueTagLength for H160 {
    fn tag_length(&self) -> u32 {
        20
    }
}

impl ValueTagLength for Option<Address> {
    fn tag_length(&self) -> u32 {
        if self.is_none() {
            0
        } else {
            self.unwrap().tag_length()
        }
    }
}

impl ValueTagLength for Vec<u8> {
    fn tag_length(&self) -> u32 {
        self.len() as u32
    }
}

// return the tag length of the top-level BeginList tag
pub(crate) fn get_rlp_len_tag_length(rlp_bytes: &[u8]) -> u32 {
    let begin_list_byte = if rlp_bytes[0] < 0xc0 {
        // it's eip2718 (first byte is transaction type)
        rlp_bytes[1]
    } else {
        rlp_bytes[0]
    };

    assert!(begin_list_byte >= 0xc0);
    if begin_list_byte < 0xf8 {
        // list
        1
    } else {
        // long_list
        (begin_list_byte - 0xf7).into()
    }
}

/// RLP tags
#[derive(Default, Clone, Copy, Debug, EnumIter, PartialEq, Eq)]
pub enum Tag {
    #[default]
    /// Tag that marks the beginning of a list
    /// whose value gives the length of bytes of this list.
    BeginList = 4,
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
    /// Sender
    Sender,
}

impl From<Tag> for usize {
    fn from(value: Tag) -> Self {
        value as usize
    }
}

impl From<Tag> for RlpTag {
    fn from(value: Tag) -> Self {
        Self::Tag(value)
    }
}

impl Tag {
    /// If the tag is related to list
    pub fn is_list(&self) -> bool {
        matches!(
            self,
            Self::BeginList | Self::BeginVector | Self::EndList | Self::EndVector
        )
    }

    /// If the tag is BeginList or BeginVector
    pub fn is_begin(&self) -> bool {
        matches!(self, Self::BeginList | Self::BeginVector)
    }

    /// If the tag is EndList or EndVector
    pub fn is_end(&self) -> bool {
        matches!(self, Self::EndList | Self::EndVector)
    }
}

/// RLP tags
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RlpTag {
    /// Length of RLP bytes
    Len,
    /// RLC of RLP bytes
    RLC,
    /// GasCost of RLP bytes
    GasCost,
    /// Null never occurs in RLP table
    Null,
    /// Tag
    Tag(Tag),
}

impl RlpTag {
    /// If this tag is for output
    pub fn is_output(&self) -> bool {
        matches!(self, Self::RLC)
    }
}

impl From<RlpTag> for usize {
    fn from(value: RlpTag) -> Self {
        match value {
            RlpTag::Len => 0,
            RlpTag::RLC => 1,
            RlpTag::Null => 2,
            RlpTag::GasCost => 3,
            RlpTag::Tag(tag) => usize::from(tag),
        }
    }
}

use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    witness::{
        l1_msg,
        Format::{
            TxHashEip155, TxHashEip1559, TxHashEip2930, TxHashPreEip155, TxSignEip155,
            TxSignEip1559, TxSignEip2930, TxSignPreEip155,
        },
        Tag::{
            AccessListAddress, AccessListStorageKey, BeginList, BeginVector, ChainId, Data,
            EndList, EndVector, Gas, GasPrice, MaxFeePerGas, MaxPriorityFeePerGas, Nonce, SigR,
            SigS, SigV, To, TxType, Value as TxValue, Zero1, Zero2,
        },
    },
};

// The number of bytes of list can not be larger than 2^24 = 2^(8*3).
// This const is meant to be the maximum of tag_length for representing a `LongList`.
// For example, [0xf9, 0xff, 0xff] has tag_length = 2 and has 0xffff bytes inside.
pub(crate) const MAX_TAG_LENGTH_OF_LIST: usize = 3;
pub(crate) const N_BYTES_CALLDATA: usize = 1 << 24;

fn eip155_tx_sign_rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (BeginList, Nonce, MAX_TAG_LENGTH_OF_LIST, vec![1]),
        (Nonce, GasPrice, N_BYTES_U64, vec![2]),
        (GasPrice, Gas, N_BYTES_WORD, vec![3]),
        (Gas, To, N_BYTES_U64, vec![4]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![5]),
        (TxValue, Data, N_BYTES_WORD, vec![6]),
        (Data, ChainId, N_BYTES_CALLDATA, vec![7]),
        (ChainId, Zero1, N_BYTES_U64, vec![8]),
        (Zero1, Zero2, 1, vec![9]),
        (Zero2, EndList, 1, vec![10]),
        (EndList, EndList, 0, vec![11]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, TxSignEip155, row.3).into())
        .collect()
}

fn eip155_tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (BeginList, Nonce, MAX_TAG_LENGTH_OF_LIST, vec![1]),
        (Nonce, GasPrice, N_BYTES_U64, vec![2]),
        (GasPrice, Gas, N_BYTES_WORD, vec![3]),
        (Gas, To, N_BYTES_U64, vec![4]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![5]),
        (TxValue, Data, N_BYTES_WORD, vec![6]),
        (Data, SigV, N_BYTES_CALLDATA, vec![7]),
        (SigV, SigR, N_BYTES_U64, vec![8]),
        (SigR, SigS, N_BYTES_WORD, vec![9]),
        (SigS, EndList, N_BYTES_WORD, vec![10]),
        (EndList, EndList, 0, vec![11]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, TxHashEip155, row.3).into())
        .collect()
}

pub fn pre_eip155_tx_sign_rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (BeginList, Nonce, MAX_TAG_LENGTH_OF_LIST, vec![1]),
        (Nonce, GasPrice, N_BYTES_U64, vec![2]),
        (GasPrice, Gas, N_BYTES_WORD, vec![3]),
        (Gas, To, N_BYTES_U64, vec![4]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![5]),
        (TxValue, Data, N_BYTES_WORD, vec![6]),
        (Data, EndList, N_BYTES_CALLDATA, vec![7]),
        (EndList, EndList, 0, vec![8]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, TxSignPreEip155, row.3).into())
        .collect()
}

pub fn pre_eip155_tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (BeginList, Nonce, MAX_TAG_LENGTH_OF_LIST, vec![1]),
        (Nonce, GasPrice, N_BYTES_U64, vec![2]),
        (GasPrice, Gas, N_BYTES_WORD, vec![3]),
        (Gas, To, N_BYTES_U64, vec![4]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![5]),
        (TxValue, Data, N_BYTES_WORD, vec![6]),
        (Data, SigV, N_BYTES_CALLDATA, vec![7]),
        (SigV, SigR, N_BYTES_U64, vec![8]),
        (SigR, SigS, N_BYTES_WORD, vec![9]),
        (SigS, EndList, N_BYTES_WORD, vec![10]),
        (EndList, EndList, 0, vec![11]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, TxHashPreEip155, row.3).into())
        .collect()
}

pub fn eip2930_tx_sign_rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (TxType, BeginList, 1, vec![1]),
        (BeginList, ChainId, MAX_TAG_LENGTH_OF_LIST, vec![2]),
        (ChainId, Nonce, N_BYTES_U64, vec![3]),
        (Nonce, GasPrice, N_BYTES_U64, vec![4]),
        (GasPrice, Gas, N_BYTES_WORD, vec![5]),
        (Gas, To, N_BYTES_U64, vec![6]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![7]),
        (TxValue, Data, N_BYTES_WORD, vec![8]),
        (Data, BeginVector, N_BYTES_CALLDATA, vec![9, 10]),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![20]), // access_list is none
        (BeginVector, BeginList, MAX_TAG_LENGTH_OF_LIST, vec![11]),
        (
            BeginList,
            AccessListAddress,
            MAX_TAG_LENGTH_OF_LIST,
            vec![12],
        ),
        (
            AccessListAddress,
            BeginVector,
            N_BYTES_ACCOUNT_ADDRESS,
            vec![13, 14],
        ),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![17]), /* access_list.storage_keys
                                                                     * is none */
        (
            BeginVector,
            AccessListStorageKey,
            MAX_TAG_LENGTH_OF_LIST,
            vec![15, 16],
        ),
        (AccessListStorageKey, EndVector, N_BYTES_WORD, vec![17]), // finished parsing storage keys
        (
            AccessListStorageKey,
            AccessListStorageKey,
            N_BYTES_WORD,
            vec![15, 16],
        ), // keep parsing storage_keys
        (EndVector, EndList, 0, vec![18, 19]),
        (EndList, EndVector, 0, vec![20]), // finished parsing access_list
        (EndList, BeginList, 0, vec![11]), // parse another access_list entry
        (EndVector, EndList, 0, vec![21]),
        (EndList, EndList, 0, vec![22]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, TxSignEip2930, row.3).into())
        .collect()
}

pub fn eip2930_tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (TxType, BeginList, 1, vec![1]),
        (BeginList, ChainId, MAX_TAG_LENGTH_OF_LIST, vec![2]),
        (ChainId, Nonce, N_BYTES_U64, vec![3]),
        (Nonce, GasPrice, N_BYTES_U64, vec![4]),
        (GasPrice, Gas, N_BYTES_WORD, vec![5]),
        (Gas, To, N_BYTES_U64, vec![6]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![7]),
        (TxValue, Data, N_BYTES_WORD, vec![8]),
        (Data, BeginVector, N_BYTES_CALLDATA, vec![9, 10]),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![20]), // access_list is none
        (BeginVector, BeginList, MAX_TAG_LENGTH_OF_LIST, vec![11]),
        (
            BeginList,
            AccessListAddress,
            MAX_TAG_LENGTH_OF_LIST,
            vec![12],
        ),
        (
            AccessListAddress,
            BeginVector,
            N_BYTES_ACCOUNT_ADDRESS,
            vec![13, 14],
        ),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![17]), /* access_list.storage_keys
                                                                     * is none */
        (
            BeginVector,
            AccessListStorageKey,
            MAX_TAG_LENGTH_OF_LIST,
            vec![15, 16],
        ),
        (AccessListStorageKey, EndVector, N_BYTES_WORD, vec![17]), // finished parsing storage keys
        (
            AccessListStorageKey,
            AccessListStorageKey,
            N_BYTES_WORD,
            vec![15, 16],
        ), // keep parsing storage_keys
        (EndVector, EndList, 0, vec![18, 19]),
        (EndList, EndVector, 0, vec![20]), // finished parsing access_list
        (EndList, BeginList, 0, vec![11]), // parse another access_list entry
        (EndVector, SigV, 0, vec![21]),
        (SigV, SigR, N_BYTES_U64, vec![22]),
        (SigR, SigS, N_BYTES_WORD, vec![23]),
        (SigS, EndList, N_BYTES_WORD, vec![24]),
        (EndList, EndList, 0, vec![25]),
        // used to exit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, TxHashEip2930, row.3).into())
        .collect()
}

pub fn eip1559_tx_hash_rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (TxType, BeginList, 1, vec![1]),
        (BeginList, ChainId, MAX_TAG_LENGTH_OF_LIST, vec![2]),
        (ChainId, Nonce, N_BYTES_U64, vec![3]),
        (Nonce, MaxPriorityFeePerGas, N_BYTES_U64, vec![4]),
        (MaxPriorityFeePerGas, MaxFeePerGas, N_BYTES_WORD, vec![5]),
        (MaxFeePerGas, Gas, N_BYTES_WORD, vec![6]),
        (Gas, To, N_BYTES_U64, vec![7]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![8]),
        (TxValue, Data, N_BYTES_WORD, vec![9]),
        (Data, BeginVector, N_BYTES_CALLDATA, vec![10, 11]),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![21]), // access_list is none
        (BeginVector, BeginList, MAX_TAG_LENGTH_OF_LIST, vec![12]),
        (
            BeginList,
            AccessListAddress,
            MAX_TAG_LENGTH_OF_LIST,
            vec![13],
        ),
        (
            AccessListAddress,
            BeginVector,
            N_BYTES_ACCOUNT_ADDRESS,
            vec![14, 15],
        ),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![18]), /* access_list.storage_keys
                                                                     * is none */
        (
            BeginVector,
            AccessListStorageKey,
            MAX_TAG_LENGTH_OF_LIST,
            vec![16, 17],
        ),
        (AccessListStorageKey, EndVector, N_BYTES_WORD, vec![18]), // finished parsing storage keys
        (
            AccessListStorageKey,
            AccessListStorageKey,
            N_BYTES_WORD,
            vec![16, 17],
        ), // keep parsing storage_keys
        (EndVector, EndList, 0, vec![19, 20]),
        (EndList, EndVector, 0, vec![21]), // finished parsing access_list
        (EndList, BeginList, 0, vec![12]), // parse another access_list entry
        (EndVector, SigV, 0, vec![22]),
        (SigV, SigR, N_BYTES_U64, vec![23]),
        (SigR, SigS, N_BYTES_WORD, vec![24]),
        (SigS, EndList, N_BYTES_WORD, vec![25]),
        (EndList, EndList, 0, vec![26]),
        // used to exit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, TxHashEip1559, row.3).into())
        .collect()
}

pub fn eip1559_tx_sign_rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (TxType, BeginList, 1, vec![1]),
        (BeginList, ChainId, MAX_TAG_LENGTH_OF_LIST, vec![2]),
        (ChainId, Nonce, N_BYTES_U64, vec![3]),
        (Nonce, MaxPriorityFeePerGas, N_BYTES_U64, vec![4]),
        (MaxPriorityFeePerGas, MaxFeePerGas, N_BYTES_WORD, vec![5]),
        (MaxFeePerGas, Gas, N_BYTES_WORD, vec![6]),
        (Gas, To, N_BYTES_U64, vec![7]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![8]),
        (TxValue, Data, N_BYTES_WORD, vec![9]),
        (Data, BeginVector, N_BYTES_CALLDATA, vec![10, 11]),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![21]), // access_list is none
        (BeginVector, BeginList, MAX_TAG_LENGTH_OF_LIST, vec![12]),
        (
            BeginList,
            AccessListAddress,
            MAX_TAG_LENGTH_OF_LIST,
            vec![13],
        ),
        (
            AccessListAddress,
            BeginVector,
            N_BYTES_ACCOUNT_ADDRESS,
            vec![14, 15],
        ),
        (BeginVector, EndVector, MAX_TAG_LENGTH_OF_LIST, vec![18]), /* access_list.storage_keys
                                                                     * is none */
        (
            BeginVector,
            AccessListStorageKey,
            MAX_TAG_LENGTH_OF_LIST,
            vec![16, 17],
        ),
        (AccessListStorageKey, EndVector, N_BYTES_WORD, vec![18]), // finished parsing storage keys
        (
            AccessListStorageKey,
            AccessListStorageKey,
            N_BYTES_WORD,
            vec![16, 17],
        ), // keep parsing storage_keys
        (EndVector, EndList, 0, vec![19, 20]),
        (EndList, EndVector, 0, vec![21]), // finished parsing access_list
        (EndList, BeginList, 0, vec![12]), // parse another access_list entry
        (EndVector, EndList, 0, vec![22]),
        (EndList, EndList, 0, vec![23]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, TxSignEip1559, row.3).into())
        .collect()
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
#[derive(Clone, Copy, Default, Debug, EnumIter, PartialEq)]
pub enum Format {
    /// Sign for EIP155 tx
    #[default]
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
    /// Sign for EIP2930 tx
    TxSignEip2930,
    /// Hash for EIP2930 tx
    TxHashEip2930,
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
            TxSignEip1559 => eip1559_tx_sign_rom_table_rows(),
            TxHashEip1559 => eip1559_tx_hash_rom_table_rows(),
            TxSignEip2930 => eip2930_tx_sign_rom_table_rows(),
            TxHashEip2930 => eip2930_tx_hash_rom_table_rows(),
            Self::L1MsgHash => l1_msg::rom_table_rows(),
        }
    }
}

/// All possible states of RLP decoding state machine
#[derive(Clone, Copy, Debug, EnumIter, PartialEq, Eq)]
pub enum State {
    /// End
    End = 0,
    /// Start
    DecodeTagStart,
    /// Bytes
    Bytes,
    /// Long bytes
    LongBytes,
    /// Long list
    LongList,
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
    /// GasCost of raw RLP bytes up to `byte_idx`
    pub gas_cost_acc: Value<F>,
}

impl<F: FieldExt> DataTable<F> {
    /// values
    pub fn values(&self) -> Vec<Value<F>> {
        vec![
            Value::known(F::from(self.tx_id)),
            Value::known(F::from(usize::from(self.format) as u64)),
            Value::known(F::from(self.byte_idx as u64)),
            Value::known(F::from(self.byte_rev_idx as u64)),
            Value::known(F::from(self.byte_value as u64)),
            self.bytes_rlc,
            self.gas_cost_acc,
        ]
    }
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
    /// The tag's value
    pub tag_value: Value<F>,
    /// RLC of the tag's big-endian bytes
    pub tag_bytes_rlc: Value<F>,
    /// Length of the tag's big-endian bytes
    /// Note that we use (tag_bytes_rlc, tag_length) to identify
    /// the tag's dynamic-sized big-endian bytes
    pub tag_length: usize,
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
    /// Max length of bytes of current tag
    pub max_length: usize,
    /// The index of current byte we are reading
    pub byte_idx: usize,
    /// The reverse index of current byte we are reading
    pub byte_rev_idx: usize,
    /// The value of current byte we are reading
    pub byte_value: u8,
    /// The index of the actual bytes of tag
    pub tag_idx: usize,
    /// The accumulated value of bytes up to `tag_idx` of tag
    /// In most cases, RlpTable.tag_value == StateMachine.tag_value_acc.
    /// However, for RlpTag::Len, we have
    ///  tag_value == byte_idx + tag_value_acc
    pub tag_acc_value: Value<F>,
    /// The depth
    pub depth: usize,
    /// The RLC of bytes up to `byte_idx`
    pub bytes_rlc: Value<F>,
    /// The gas cost of bytes up to `byte_idx`
    pub gas_cost_acc: Value<F>,
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
    // From byte_idx we can get (byte_value, byte_rev_idx, bytes_rlc), and
    // byte_idx starts from 0.
    pub(crate) byte_idx: usize,
    pub(crate) depth: usize,
    pub(crate) tag_idx: usize,
    pub(crate) tag_length: usize,
    pub(crate) tag_value_acc: Value<F>,
    pub(crate) tag_bytes_rlc: Value<F>,
}
