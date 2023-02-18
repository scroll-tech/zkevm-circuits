//! Collection of structs and functions used to:
//! - Define the internals of a [`MemoryOp`], [`StackOp`] and [`StorageOp`].
//! - Define the actual operation types and a wrapper over them (the
//!   [`Operation`] enum).
//! - Define structures that interact with operations such as
//!   [`OperationContainer`].
pub(crate) mod container;

pub use container::OperationContainer;
pub use eth_types::evm_types::{MemoryAddress, StackAddress};

use core::cmp::Ordering;
use core::fmt;
use core::fmt::Debug;
use eth_types::{Address, Word};
use std::mem::swap;

/// Marker that defines whether an Operation performs a `READ` or a `WRITE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RW {
    /// Marks op as READ.
    READ,
    /// Marks op as WRITE.
    WRITE,
}

impl RW {
    /// Returns true if the RW corresponds internally to a [`READ`](RW::READ).
    pub const fn is_read(&self) -> bool {
        matches!(self, RW::READ)
    }

    /// Returns true if the RW corresponds internally to a [`WRITE`](RW::WRITE).
    pub const fn is_write(&self) -> bool {
        matches!(self, RW::WRITE)
    }
}

/// Wrapper type over `usize` which represents the global counter. The purpose
/// of the `RWCounter` is to enforce that each Opcode/Instruction and Operation
/// is unique and just executed once.
#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct RWCounter(pub usize);

impl fmt::Debug for RWCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl From<RWCounter> for usize {
    fn from(addr: RWCounter) -> usize {
        addr.0
    }
}

impl From<usize> for RWCounter {
    fn from(rwc: usize) -> Self {
        RWCounter(rwc)
    }
}

impl Default for RWCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl RWCounter {
    /// Create a new RWCounter with the initial default value
    pub fn new() -> Self {
        Self(1)
    }

    /// Increase Self by one
    pub fn inc(&mut self) {
        self.0 += 1;
    }

    /// Increase Self by one and return the value before the increase.
    pub fn inc_pre(&mut self) -> Self {
        let pre = *self;
        self.inc();
        pre
    }
}

/// Enum used to differenciate between EVM Stack, Memory and Storage operations.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum Target {
    /// Start is a padding operation.
    Start,
    /// Means the target of the operation is the Memory.
    Memory,
    /// Means the target of the operation is the Stack.
    Stack,
    /// Means the target of the operation is the Storage.
    Storage,
    /// Means the target of the operation is the TxAccessListAccount.
    TxAccessListAccount,
    /// Means the target of the operation is the TxAccessListAccountStorage.
    TxAccessListAccountStorage,
    /// Means the target of the operation is the TxRefund.
    TxRefund,
    /// Means the target of the operation is the Account.
    Account,
    /// Means the target of the operation is the CallContext.
    CallContext,
    /// Means the target of the operation is the TxReceipt.
    TxReceipt,
    /// Means the target of the operation is the TxLog.
    TxLog,
}

/// Trait used for Operation Kinds.

pub trait Op: Clone + Eq + Ord {
    /// Turn the Generic Op into an OpEnum so that we can match it into a
    /// particular Operation Kind.
    fn into_enum(self) -> OpEnum;
    /// Return a copy of the operation reversed.
    fn reverse(&self) -> Self;
}

/// Represents a [`READ`](RW::READ)/[`WRITE`](RW::WRITE) into the memory implied
/// by an specific [`OpcodeId`](eth_types::evm_types::opcode_ids::OpcodeId) of
/// the [`ExecStep`](crate::circuit_input_builder::ExecStep).
#[derive(Clone, PartialEq, Eq)]
pub struct MemoryOp {
    /// Call ID
    pub call_id: usize,
    /// Memory Address
    pub address: MemoryAddress,
    /// Value
    pub value: u8,
}

impl fmt::Debug for MemoryOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemoryOp { ")?;
        f.write_fmt(format_args!(
            "call_id: {:?}, addr: {:?}, value: 0x{:02x}",
            self.call_id, self.address, self.value
        ))?;
        f.write_str(" }")
    }
}

impl MemoryOp {
    /// Create a new instance of a `MemoryOp` from it's components.
    pub fn new(call_id: usize, address: MemoryAddress, value: u8) -> MemoryOp {
        MemoryOp {
            call_id,
            address,
            value,
        }
    }

    /// Returns the [`Target`] (operation type) of this operation.
    pub const fn target(&self) -> Target {
        Target::Memory
    }

    /// Returns the call id associated to this Operation.
    pub const fn call_id(&self) -> usize {
        self.call_id
    }

    /// Returns the [`MemoryAddress`] associated to this Operation.
    pub const fn address(&self) -> &MemoryAddress {
        &self.address
    }

    /// Returns the bytes read or written by this operation.
    pub fn value(&self) -> u8 {
        self.value
    }
}

impl Op for MemoryOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::Memory(self)
    }

    fn reverse(&self) -> Self {
        unreachable!("MemoryOp can't be reverted")
    }
}

impl PartialOrd for MemoryOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemoryOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.call_id, &self.address).cmp(&(&other.call_id, &other.address))
    }
}

/// Represents a [`READ`](RW::READ)/[`WRITE`](RW::WRITE) into the stack implied
/// by an specific [`OpcodeId`](eth_types::evm_types::opcode_ids::OpcodeId) of
/// the [`ExecStep`](crate::circuit_input_builder::ExecStep).
#[derive(Clone, PartialEq, Eq)]
pub struct StackOp {
    /// Call ID
    pub call_id: usize,
    /// Stack Address
    pub address: StackAddress,
    /// Value
    pub value: Word,
}

impl fmt::Debug for StackOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StackOp { ")?;
        f.write_fmt(format_args!(
            "call_id: {:?}, addr: {:?}, val: 0x{:x}",
            self.call_id, self.address, self.value
        ))?;
        f.write_str(" }")
    }
}

impl StackOp {
    /// Create a new instance of a `StackOp` from it's components.
    pub const fn new(call_id: usize, address: StackAddress, value: Word) -> StackOp {
        StackOp {
            call_id,
            address,
            value,
        }
    }

    /// Returns the [`Target`] (operation type) of this operation.
    pub const fn target(&self) -> Target {
        Target::Stack
    }

    /// Returns the call id associated to this Operation.
    pub const fn call_id(&self) -> usize {
        self.call_id
    }

    /// Returns the [`StackAddress`] associated to this Operation.
    pub const fn address(&self) -> &StackAddress {
        &self.address
    }

    /// Returns the [`Word`] read or written by this operation.
    pub const fn value(&self) -> &Word {
        &self.value
    }
}

impl Op for StackOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::Stack(self)
    }

    fn reverse(&self) -> Self {
        unreachable!("StackOp can't be reverted")
    }
}

impl PartialOrd for StackOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StackOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.call_id, &self.address).cmp(&(&other.call_id, &other.address))
    }
}

/// Represents a [`READ`](RW::READ)/[`WRITE`](RW::WRITE) into the storage
/// implied by an specific
/// [`OpcodeId`](eth_types::evm_types::opcode_ids::OpcodeId) of
/// the [`ExecStep`](crate::circuit_input_builder::ExecStep).
#[derive(Clone, PartialEq, Eq)]
pub struct StorageOp {
    /// Account Address
    pub address: Address,
    /// Storage Key
    pub key: Word,
    /// Storage Value after the operation
    pub value: Word,
    /// Storage Value before the operation
    pub value_prev: Word,
    /// Transaction ID: Transaction index in the block starting at 1.
    pub tx_id: usize,
    /// Storage Value before the transaction
    pub committed_value: Word,
}

impl fmt::Debug for StorageOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StorageOp { ")?;
        f.write_fmt(format_args!(
            "tx_id: {:?}, addr: {:?}, key: {:?}, committed_val: 0x{:x}, val_prev: 0x{:x}, val: 0x{:x}",
            self.tx_id, self.address, self.key, self.committed_value, self.value_prev, self.value
        ))?;
        f.write_str(" }")
    }
}

impl StorageOp {
    /// Create a new instance of a `StorageOp` from it's components.
    pub const fn new(
        address: Address,
        key: Word,
        value: Word,
        value_prev: Word,
        tx_id: usize,
        committed_value: Word,
    ) -> StorageOp {
        StorageOp {
            address,
            key,
            value,
            value_prev,
            tx_id,
            committed_value,
        }
    }

    /// Returns the [`Target`] (operation type) of this operation.
    pub const fn target(&self) -> Target {
        Target::Storage
    }

    /// Returns the [`Address`] corresponding to this storage operation.
    pub const fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the [`Word`] used as key for this operation.
    pub const fn key(&self) -> &Word {
        &self.key
    }

    /// Returns the [`Word`] read or written by this operation.
    pub const fn value(&self) -> &Word {
        &self.value
    }

    /// Returns the [`Word`] at key found previous to this operation.
    pub const fn value_prev(&self) -> &Word {
        &self.value_prev
    }
}

impl Op for StorageOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::Storage(self)
    }

    fn reverse(&self) -> Self {
        let mut rev = self.clone();
        swap(&mut rev.value, &mut rev.value_prev);
        rev
    }
}

impl PartialOrd for StorageOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StorageOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.address, &self.key).cmp(&(&other.address, &other.key))
    }
}

/// Represents a change in the Account AccessList implied by a `BeginTx`,
/// `EXTCODECOPY`, `EXTCODESIZE`, `EXTCODEHASH` `BALANCE`, `SELFDESTRUCT`,
/// `*CALL`* or `CREATE*` step.
#[derive(Clone, PartialEq, Eq)]
pub struct TxAccessListAccountOp {
    /// Transaction ID: Transaction index in the block starting at 1.
    pub tx_id: usize,
    /// Account Address
    pub address: Address,
    /// Represents whether we can classify the access to the value as `WARM`.
    pub is_warm: bool,
    /// Represents whether we can classify the access to the previous value as
    /// `WARM`.
    pub is_warm_prev: bool,
}

impl fmt::Debug for TxAccessListAccountOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TxAccessListAccountOp { ")?;
        f.write_fmt(format_args!(
            "tx_id: {:?}, addr: {:?}, is_warm_prev: {:?}, is_warm: {:?}",
            self.tx_id, self.address, self.is_warm_prev, self.is_warm
        ))?;
        f.write_str(" }")
    }
}

impl PartialOrd for TxAccessListAccountOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxAccessListAccountOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.tx_id, &self.address).cmp(&(&other.tx_id, &other.address))
    }
}

impl Op for TxAccessListAccountOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::TxAccessListAccount(self)
    }

    fn reverse(&self) -> Self {
        let mut rev = self.clone();
        swap(&mut rev.is_warm, &mut rev.is_warm_prev);
        rev
    }
}

/// Represents a change in the Storage AccessList implied by an `SSTORE` or
/// `SLOAD` step of the [`ExecStep`](crate::circuit_input_builder::ExecStep).
#[derive(Clone, PartialEq, Eq)]
pub struct TxAccessListAccountStorageOp {
    /// Transaction ID: Transaction index in the block starting at 1.
    pub tx_id: usize,
    /// Account Address
    pub address: Address,
    /// Storage Key
    pub key: Word,
    /// Whether the access was classified as `WARM` or not.
    pub is_warm: bool,
    /// Whether the prev_value access was classified as `WARM` or not.
    pub is_warm_prev: bool,
}

impl fmt::Debug for TxAccessListAccountStorageOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TxAccessListAccountStorageOp { ")?;
        f.write_fmt(format_args!(
            "tx_id: {:?}, addr: {:?}, key: 0x{:x}, is_warm_prev: {:?}, is_warm: {:?}",
            self.tx_id, self.address, self.key, self.is_warm_prev, self.is_warm
        ))?;
        f.write_str(" }")
    }
}

impl PartialOrd for TxAccessListAccountStorageOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxAccessListAccountStorageOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.tx_id, &self.address, &self.key).cmp(&(&other.tx_id, &other.address, &other.key))
    }
}

impl Op for TxAccessListAccountStorageOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::TxAccessListAccountStorage(self)
    }

    fn reverse(&self) -> Self {
        let mut rev = self.clone();
        swap(&mut rev.is_warm, &mut rev.is_warm_prev);
        rev
    }
}

/// Represents a change in the Transaction Refund AccessList implied by an
/// `SSTORE`, `STOP`, `RETURN` or `REVERT` step of the
/// [`ExecStep`](crate::circuit_input_builder::ExecStep).
#[derive(Clone, PartialEq, Eq)]
pub struct TxRefundOp {
    /// Transaction ID: Transaction index in the block starting at 1.
    pub tx_id: usize,
    /// Refund Value in units of gas after the operation.
    pub value: u64,
    /// Refund Value in units of gas after the operation.
    pub value_prev: u64,
}

impl fmt::Debug for TxRefundOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TxRefundOp { ")?;
        f.write_fmt(format_args!(
            "tx_id: {:?}, val_prev: 0x{:x}, val: 0x{:x}",
            self.tx_id, self.value_prev, self.value
        ))?;
        f.write_str(" }")
    }
}

impl PartialOrd for TxRefundOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxRefundOp {
    fn cmp(&self, other: &Self) -> Ordering {
        self.tx_id.cmp(&other.tx_id)
    }
}

impl Op for TxRefundOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::TxRefund(self)
    }

    fn reverse(&self) -> Self {
        let mut rev = self.clone();
        swap(&mut rev.value, &mut rev.value_prev);
        rev
    }
}

/// Represents a field parameter of the Account that can be accessed via EVM
/// execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccountField {
    /// Account Nonce
    Nonce,
    /// Account Balance
    Balance,
    /// Account Code Hash
    CodeHash,
}

/// Represents a change in the Account field implied by a `BeginTx`,
/// `EXTCODECOPY`, `EXTCODESIZE`, `BALANCE`, `SELFDESTRUCT`, `*CALL`*,
/// `CREATE*`, `STOP`, `RETURN` or `REVERT` step.
#[derive(Clone, PartialEq, Eq)]
pub struct AccountOp {
    /// Account Address
    pub address: Address,
    /// Field
    pub field: AccountField,
    /// Field Value after the operation
    pub value: Word,
    /// Field Value before the operation
    pub value_prev: Word,
}

impl AccountOp {
    /// Create a new instance of a `AccountOp` from it's components.
    pub const fn new(
        address: Address,
        field: AccountField,
        value: Word,
        value_prev: Word,
    ) -> AccountOp {
        AccountOp {
            address,
            field,
            value,
            value_prev,
        }
    }
}

impl fmt::Debug for AccountOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountOp { ")?;
        f.write_fmt(format_args!(
            "addr: {:?}, field: {:?}, val_prev: 0x{:x}, val: 0x{:x}",
            self.address, self.field, self.value_prev, self.value
        ))?;
        f.write_str(" }")
    }
}

impl PartialOrd for AccountOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AccountOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.address, &self.field).cmp(&(&other.address, &other.field))
    }
}

impl Op for AccountOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::Account(self)
    }

    fn reverse(&self) -> Self {
        let mut rev = self.clone();
        swap(&mut rev.value, &mut rev.value_prev);
        rev
    }
}

/// Represents a field parameter of the CallContext that can be accessed via EVM
/// execution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CallContextField {
    /// RwCounterEndOfReversion
    RwCounterEndOfReversion,
    /// CallerId
    CallerId,
    /// TxId
    TxId,
    /// Depth
    Depth,
    /// CallerAddress
    CallerAddress,
    /// CalleeAddress
    CalleeAddress,
    /// CallDataOffset
    CallDataOffset,
    /// CallDataLength
    CallDataLength,
    /// ReturnDataOffset
    ReturnDataOffset,
    /// ReturnDataLength
    ReturnDataLength,
    /// Value
    Value,
    /// IsSuccess
    IsSuccess,
    /// IsPersistent
    IsPersistent,
    /// IsStatic
    IsStatic,
    /// LastCalleeId
    LastCalleeId,
    /// LastCalleeReturnDataOffset
    LastCalleeReturnDataOffset,
    /// LastCalleeReturnDataLength
    LastCalleeReturnDataLength,
    /// IsRoot
    IsRoot,
    /// IsCreate
    IsCreate,
    /// CodeHash
    CodeHash,
    /// ProgramCounter
    ProgramCounter,
    /// StackPointer
    StackPointer,
    /// GasLeft
    GasLeft,
    /// MemorySize
    MemorySize,
    /// ReversibleWriteCounter
    ReversibleWriteCounter,
}

/// Represents an CallContext read/write operation.
#[derive(Clone, PartialEq, Eq)]
pub struct CallContextOp {
    /// call_id of CallContext
    pub call_id: usize,
    /// field of CallContext
    pub field: CallContextField,
    /// value of CallContext
    pub value: Word,
}

impl fmt::Debug for CallContextOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CallContextOp { ")?;
        f.write_fmt(format_args!(
            "call_id: {:?}, field: {:?}, value: {:?}",
            self.call_id, self.field, self.value,
        ))?;
        f.write_str(" }")
    }
}

impl PartialOrd for CallContextOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CallContextOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.call_id, &self.field).cmp(&(&other.call_id, &other.field))
    }
}

impl Op for CallContextOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::CallContext(self)
    }

    fn reverse(&self) -> Self {
        unreachable!("CallContextOp can't be reverted")
    }
}

impl CallContextOp {
    /// Create a new instance of a `CallContextOp` from it's components.
    pub const fn new(call_id: usize, field: CallContextField, value: Word) -> CallContextOp {
        CallContextOp {
            call_id,
            field,
            value,
        }
    }

    /// Returns the [`Target`] (operation type) of this operation.
    pub const fn target(&self) -> Target {
        Target::CallContext
    }

    /// Returns the call id associated to this Operation.
    pub const fn call_id(&self) -> usize {
        self.call_id
    }

    /// Returns the [`Word`] read or written by this operation.
    pub const fn value(&self) -> &Word {
        &self.value
    }
}

/// Represents a field parameter of the TxLog that can be accessed via EVM
/// execution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxLogField {
    /// contract address
    Address,
    /// topic of log entry
    Topic,
    /// data of log entry
    Data,
    /* TODO: Add `TopicLength` and `DataLength`, which will be used for the RLP encoding of the
     * Tx Receipt */
}

/// Represents TxLog read/write operation.
#[derive(Clone, PartialEq, Eq)]
pub struct TxLogOp {
    /// tx_id of TxLog, starts with 1 in rw table, and it's unique per Tx
    pub tx_id: usize,
    /// id of log entry, starts with 1 in rw table, it's unique within Tx,
    /// currently it is also field of execution step, As field of execution
    /// step, it resets to zero (in begin_tx), and increases with each Log* step
    /// the reason why rw table's `log_id` start with 1 instead of zero is that
    /// zero `log_id` represents no log steps(no any logs inserting) executed
    pub log_id: usize,
    /// field of TxLogField
    pub field: TxLogField,
    /// topic index if field is Topic
    /// byte index if field is Data
    /// it would be zero for other field tags
    pub index: usize,
    /// value
    pub value: Word,
}

impl TxLogOp {
    /// Create a new instance of a `TxLogOp` from it's components.
    pub fn new(
        tx_id: usize,
        log_id: usize,
        field: TxLogField,
        index: usize,
        value: Word,
    ) -> TxLogOp {
        TxLogOp {
            tx_id,
            log_id,
            field,
            index,
            value,
        }
    }
}

impl fmt::Debug for TxLogOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TxLogOp { ")?;
        f.write_fmt(format_args!(
            "tx_id: {:?}, log_id: {:?}, field: {:?}, index: {:?}, value: {:?}",
            self.tx_id, self.log_id, self.field, self.index, self.value,
        ))?;
        f.write_str(" }")
    }
}

impl PartialOrd for TxLogOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxLogOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.tx_id, &self.log_id, &self.field).cmp(&(&other.tx_id, &other.log_id, &other.field))
    }
}

impl Op for TxLogOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::TxLog(self)
    }

    fn reverse(&self) -> Self {
        unreachable!("TxLog can't be reverted")
    }
}

/// Represents a field parameter of the TxReceipt that can be accessed via EVM
/// execution.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxReceiptField {
    /// flag indicates whether a tx succeed or not
    PostStateOrStatus,
    /// the cumulative gas used in the block containing the transaction receipt
    /// as of immediately after the transaction has happened.
    CumulativeGasUsed,
    /// record how many log entries in the receipt/tx , 0 if tx fails
    LogLength,
}

/// Represent a Start padding operation
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StartOp {}

impl PartialOrd for StartOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StartOp {
    fn cmp(&self, _other: &Self) -> Ordering {
        Ordering::Equal
    }
}

impl Op for StartOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::Start(self)
    }

    fn reverse(&self) -> Self {
        unreachable!("StartOp can't be reverted")
    }
}

/// Represents TxReceipt read/write operation.
#[derive(Clone, PartialEq, Eq)]
pub struct TxReceiptOp {
    /// tx_id of TxReceipt
    pub tx_id: usize,
    /// field of TxReceipt
    pub field: TxReceiptField,
    /// value of TxReceipt
    pub value: u64,
}

impl fmt::Debug for TxReceiptOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TxReceiptOp { ")?;
        f.write_fmt(format_args!(
            "tx_id: {:?}, field: {:?}, value: {:?}",
            self.tx_id, self.field, self.value,
        ))?;
        f.write_str(" }")
    }
}

impl PartialOrd for TxReceiptOp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TxReceiptOp {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.tx_id, &self.field).cmp(&(&other.tx_id, &other.field))
    }
}

impl Op for TxReceiptOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::TxReceipt(self)
    }

    fn reverse(&self) -> Self {
        unreachable!("TxReceiptOp can't be reverted")
    }
}

/// Generic enum that wraps over all the operation types possible.
/// In particular [`StackOp`], [`MemoryOp`] and [`StorageOp`].
#[derive(Debug, Clone)]
pub enum OpEnum {
    /// Stack
    Stack(StackOp),
    /// Memory
    Memory(MemoryOp),
    /// Storage
    Storage(StorageOp),
    /// TxAccessListAccount
    TxAccessListAccount(TxAccessListAccountOp),
    /// TxAccessListAccountStorage
    TxAccessListAccountStorage(TxAccessListAccountStorageOp),
    /// TxRefund
    TxRefund(TxRefundOp),
    /// Account
    Account(AccountOp),
    /// CallContext
    CallContext(CallContextOp),
    /// TxReceipt
    TxReceipt(TxReceiptOp),
    /// TxLog
    TxLog(TxLogOp),
    /// Start
    Start(StartOp),
}

/// Operation is a Wrapper over a type that implements Op with a RWCounter.
#[derive(Debug, Clone)]
pub struct Operation<T: Op> {
    rwc: RWCounter,
    rw: RW,
    /// True when this Operation should be reverted or not when
    /// handle_reversion.
    reversible: bool,
    op: T,
}

impl<T: Op> PartialEq for Operation<T> {
    fn eq(&self, other: &Self) -> bool {
        self.op.eq(&other.op) && self.rwc == other.rwc
    }
}

impl<T: Op> Eq for Operation<T> {}

impl<T: Op> PartialOrd for Operation<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Op> Ord for Operation<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.op.cmp(&other.op) {
            Ordering::Equal => self.rwc.cmp(&other.rwc),
            ord => ord,
        }
    }
}

impl<T: Op> Operation<T> {
    /// Create a new Operation from an `op` with a `rwc`
    pub fn new(rwc: RWCounter, rw: RW, op: T) -> Self {
        Self {
            rwc,
            rw,
            reversible: false,
            op,
        }
    }

    /// Create a new reversible Operation from an `op` with a `rwc`
    pub fn new_reversible(rwc: RWCounter, rw: RW, op: T) -> Self {
        Self {
            rwc,
            rw,
            reversible: true,
            op,
        }
    }

    /// Return this `Operation` `rwc`
    pub fn rwc(&self) -> RWCounter {
        self.rwc
    }

    /// Return this `Operation` `rw`
    pub fn rw(&self) -> RW {
        self.rw
    }

    /// Return this `Operation` `reversible`
    pub fn reversible(&self) -> bool {
        self.reversible
    }

    /// Return this `Operation` `op`
    pub fn op(&self) -> &T {
        &self.op
    }

    /// Return this `Operation` `op` as mutable reference
    pub fn op_mut(&mut self) -> &mut T {
        &mut self.op
    }

    // /// Matches over an `Operation` returning the [`Target`] of the iternal
    // op /// it stores inside.
    // pub const fn target(&self) -> Target {
    //     self.op.target()
    // }
    //     match self {
    //         Operation::Memory(_) => Target::Memory,
    //         Operation::Stack(_) => Target::Stack,
    //         Operation::Storage(_) => Target::Storage,
    //     }
    // }

    // /// Returns true if the Operation hold internally is a [`StackOp`].
    // pub const fn is_stack(&self) -> bool {
    //     matches!(*self, Operation::Stack(_))
    // }

    // /// Returns true if the Operation hold internally is a [`MemoryOp`].
    // pub const fn is_memory(&self) -> bool {
    //     matches!(*self, Operation::Memory(_))
    // }

    // /// Returns true if the Operation hold internally is a [`StorageOp`].
    // pub const fn is_storage(&self) -> bool {
    //     matches!(*self, Operation::Storage(_))
    // }

    // /// Transmutes the internal (unlabeled) repr of the operation contained
    // /// inside of the enum into a [`StackOp`].
    // pub fn into_stack_unchecked(self) -> StackOp {
    //     match self {
    //         Operation::Stack(stack_op) => stack_op,
    //         _ => panic!("Broken Invariant"),
    //     }
    // }

    // /// Transmutes the internal (unlabeled) repr of the operation contained
    // /// inside of the enum into a [`MemoryOp`].
    // pub fn into_memory_unchecked(self) -> MemoryOp {
    //     match self {
    //         Operation::Memory(memory_op) => memory_op,
    //         _ => panic!("Broken Invariant"),
    //     }
    // }

    // /// Transmutes the internal (unlabeled) repr of the operation contained
    // /// inside of the enum into a [`StorageOp`].
    // pub fn into_storage_unchecked(self) -> StorageOp {
    //     match self {
    //         Operation::Storage(storage_op) => storage_op,
    //         _ => panic!("Broken Invariant"),
    //     }
    // }
}

#[cfg(test)]
mod operation_tests {
    use super::*;

    #[test]
    fn unchecked_op_transmutations_are_safe() {
        let stack_op = StackOp::new(1, StackAddress::from(1024), Word::from(0x40));

        let stack_op_as_operation = Operation::new(RWCounter(1), RW::WRITE, stack_op.clone());

        let memory_op = MemoryOp::new(1, MemoryAddress(0x40), 0x40);

        let memory_op_as_operation = Operation::new(RWCounter(1), RW::WRITE, memory_op.clone());

        assert_eq!(stack_op, stack_op_as_operation.op);
        assert_eq!(memory_op, memory_op_as_operation.op)
    }
}
