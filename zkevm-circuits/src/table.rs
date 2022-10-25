//! Table definitions used cross-circuits

use crate::copy_circuit::number_or_hash_to_field;
use crate::evm_circuit::util::{rlc, RandomLinearCombination};
use crate::impl_expr;
use crate::util::build_tx_log_address;
use crate::util::Challenges;
use crate::witness::{
    Block, BlockContexts, Bytecode, MptUpdateRow, MptUpdates, Rw, RwMap, RwRow, Transaction,
};
use bus_mapping::circuit_input_builder::{CopyDataType, CopyEvent, CopyStep};
use core::iter::once;
use eth_types::{Field, ToLittleEndian, ToScalar, Word};
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use halo2_proofs::{circuit::Layouter, plonk::*, poly::Rotation};
use itertools::Itertools;
use keccak256::plain::Keccak;
use std::array;
use strum_macros::{EnumCount, EnumIter};

/// Trait used for dynamic tables.  Used to get an automatic implementation of
/// the LookupTable trait where each `table_expr` is a query to each column at
/// `Rotation::cur`.
pub trait DynamicTableColumns {
    /// Returns the list of advice columns following the table order.
    fn columns(&self) -> Vec<Column<Advice>>;
}

/// Trait used to define lookup tables
pub trait LookupTable<F: Field> {
    /// Return the list of expressions used to define the lookup table.
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>>;
}

impl<F: Field, T: DynamicTableColumns> LookupTable<F> for T {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.columns()
            .iter()
            .map(|column| meta.query_advice(*column, Rotation::cur()))
            .collect()
    }
}

impl<F: Field, C: Into<Column<Any>> + Clone, const W: usize> LookupTable<F> for [C; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.iter()
            .map(|column| meta.query_any(column.clone(), Rotation::cur()))
            .collect()
    }
}

/// Tag used to identify each field in the transaction in a row of the
/// transaction table.
#[derive(Clone, Copy, Debug)]
pub enum TxFieldTag {
    /// Unused tag
    Null = 0,
    /// Nonce
    Nonce,
    /// Gas
    Gas,
    /// GasPrice
    GasPrice,
    /// CallerAddress
    CallerAddress,
    /// CalleeAddress
    CalleeAddress,
    /// IsCreate
    IsCreate,
    /// Value
    Value,
    /// CallDataLength
    CallDataLength,
    /// Gas cost for transaction call data (4 for byte == 0, 16 otherwise)
    CallDataGasCost,
    /// TxSignHash: Hash of the transaction without the signature, used for
    /// signing.
    TxSignHash,
    /// CallData
    CallData,
    /// The block number in which this tx is included.
    BlockNumber,
}
impl_expr!(TxFieldTag);

/// Alias for TxFieldTag used by EVM Circuit
pub type TxContextFieldTag = TxFieldTag;

/// Table that contains the fields of all Transactions in a block
#[derive(Clone, Debug)]
pub struct TxTable {
    /// Tx ID
    pub tx_id: Column<Advice>,
    /// Tag (TxContextFieldTag)
    pub tag: Column<Advice>,
    /// Index for Tag = CallData
    pub index: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
}

impl TxTable {
    /// Construct a new TxTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tx_id: meta.advice_column(),
            tag: meta.advice_column(),
            index: meta.advice_column(),
            value: meta.advice_column(),
        }
    }

    /// Assign the `TxTable` from a list of block `Transaction`s, followig the
    /// same layout that the Tx Circuit uses.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        txs: &[Transaction],
        randomness: F,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "tx table",
            |mut region| {
                let mut offset = 0;
                for column in self.columns() {
                    region.assign_advice(
                        || "tx table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let tx_table_columns = self.columns();
                for tx in txs.iter() {
                    for row in tx.table_assignments(randomness) {
                        for (column, value) in tx_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("tx table row {}", offset),
                                *column,
                                offset,
                                || Value::known(value),
                            )?;
                        }
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }
}

impl DynamicTableColumns for TxTable {
    fn columns(&self) -> Vec<Column<Advice>> {
        vec![self.tx_id, self.tag, self.index, self.value]
    }
}

/// Tag to identify the operation type in a RwTable row
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, EnumIter)]
pub enum RwTableTag {
    /// Start (used for padding)
    Start = 1,
    /// Stack operation
    Stack,
    /// Memory operation
    Memory,
    /// Account Storage operation
    AccountStorage,
    /// Tx Access List Account operation
    TxAccessListAccount,
    /// Tx Access List Account Storage operation
    TxAccessListAccountStorage,
    /// Tx Refund operation
    TxRefund,
    /// Account operation
    Account,
    /// Account Destructed operation
    AccountDestructed,
    /// Call Context operation
    CallContext,
    /// Tx Log operation
    TxLog,
    /// Tx Receipt operation
    TxReceipt,
}
impl_expr!(RwTableTag);

impl RwTableTag {
    /// Returns true if the RwTable operation is reversible
    pub fn is_reversible(self) -> bool {
        matches!(
            self,
            RwTableTag::TxAccessListAccount
                | RwTableTag::TxAccessListAccountStorage
                | RwTableTag::TxRefund
                | RwTableTag::Account
                | RwTableTag::AccountStorage
                | RwTableTag::AccountDestructed
        )
    }
}

impl From<RwTableTag> for usize {
    fn from(t: RwTableTag) -> Self {
        t as usize
    }
}

/// Tag for an AccountField in RwTable
#[derive(Clone, Copy, Debug, EnumIter, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccountFieldTag {
    /// Nonce field
    Nonce = 1,
    /// Balance field
    Balance,
    /// CodeHash field
    CodeHash,
}
impl_expr!(AccountFieldTag);

/// Tag for a TxLogField in RwTable
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
pub enum TxLogFieldTag {
    /// Address field
    Address = 1,
    /// Topic field
    Topic,
    /// Data field
    Data,
}
impl_expr!(TxLogFieldTag);

/// Tag for a TxReceiptField in RwTable
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter, EnumCount)]
pub enum TxReceiptFieldTag {
    /// Tx result
    PostStateOrStatus = 1,
    /// CumulativeGasUsed in the tx
    CumulativeGasUsed,
    /// Number of logs in the tx
    LogLength,
}
impl_expr!(TxReceiptFieldTag);

/// Tag for a CallContextField in RwTable
#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
pub enum CallContextFieldTag {
    /// RwCounterEndOfReversion
    RwCounterEndOfReversion = 1,
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
impl_expr!(CallContextFieldTag);

/// The RwTable shared between EVM Circuit and State Circuit, which contains
/// traces of the EVM state operations.
#[derive(Clone, Copy, Debug)]
pub struct RwTable {
    /// Read Write Counter
    pub rw_counter: Column<Advice>,
    /// Is Write
    pub is_write: Column<Advice>,
    /// Tag
    pub tag: Column<Advice>,
    /// Key1 (Id)
    pub id: Column<Advice>,
    /// Key2 (Address)
    pub address: Column<Advice>,
    /// Key3 (FieldTag)
    pub field_tag: Column<Advice>,
    /// Key3 (StorageKey)
    pub storage_key: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
    /// Value Previous
    pub value_prev: Column<Advice>,
    /// Aux1
    pub aux1: Column<Advice>,
    /// Aux2 (Committed Value)
    pub aux2: Column<Advice>,
}

impl DynamicTableColumns for RwTable {
    fn columns(&self) -> Vec<Column<Advice>> {
        vec![
            self.rw_counter,
            self.is_write,
            self.tag,
            self.id,
            self.address,
            self.field_tag,
            self.storage_key,
            self.value,
            self.value_prev,
            self.aux1,
            self.aux2,
        ]
    }
}
impl RwTable {
    /// Construct a new RwTable
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            tag: meta.advice_column(),
            id: meta.advice_column(),
            address: meta.advice_column(),
            field_tag: meta.advice_column(),
            storage_key: meta.advice_column(),
            value: meta.advice_column(),
            value_prev: meta.advice_column(),
            aux1: meta.advice_column(),
            aux2: meta.advice_column(),
        }
    }
    /// Assign a `RwRow` at offset into the `RwTable`
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &RwRow<F>,
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.rw_counter, row.rw_counter),
            (self.is_write, row.is_write),
            (self.tag, row.tag),
            (self.id, row.id),
            (self.address, row.address),
            (self.field_tag, row.field_tag),
            (self.storage_key, row.storage_key),
            (self.value, row.value),
            (self.value_prev, row.value_prev),
            (self.aux1, row.aux1),
            (self.aux2, row.aux2),
        ] {
            region.assign_advice(
                || "assign rw row on rw table",
                column,
                offset,
                || Value::known(value),
            )?;
        }
        Ok(())
    }

    /// Assign the `RwTable` from a `RwMap`, following the same
    /// table layout that the State Circuit uses.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        rws: &[Rw],
        n_rows: usize,
        randomness: F,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "rw table",
            |mut region| self.load_with_region(&mut region, rws, n_rows, randomness),
        )
    }

    pub(crate) fn load_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        rws: &[Rw],
        n_rows: usize,
        randomness: F,
    ) -> Result<(), Error> {
        let (rows, _) = RwMap::table_assignments_prepad(rws, n_rows);
        for (offset, row) in rows.iter().enumerate() {
            self.assign(region, offset, &row.table_assignment(randomness))?;
        }
        Ok(())
    }
}

/// The types of proofs in the MPT table
pub enum ProofType {
    /// Nonce updated
    NonceChanged = AccountFieldTag::Nonce as isize,
    /// Balance updated
    BalanceChanged = AccountFieldTag::Balance as isize,
    /// Code hash exists
    CodeHashExists = AccountFieldTag::CodeHash as isize,
    /// Account destroyed
    AccountDestructed,
    /// Account does not exist
    AccountDoesNotExist,
    /// Storage updated
    StorageChanged,
}
impl_expr!(ProofType);

impl From<AccountFieldTag> for ProofType {
    fn from(tag: AccountFieldTag) -> Self {
        match tag {
            AccountFieldTag::Nonce => Self::NonceChanged,
            AccountFieldTag::Balance => Self::BalanceChanged,
            AccountFieldTag::CodeHash => Self::CodeHashExists,
        }
    }
}

/// The MptTable shared between MPT Circuit and State Circuit
#[derive(Clone, Copy, Debug)]
pub struct MptTable([Column<Advice>; 7]);

impl DynamicTableColumns for MptTable {
    fn columns(&self) -> Vec<Column<Advice>> {
        self.0.to_vec()
    }
}

impl MptTable {
    /// Construct a new MptTable
    pub(crate) fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self([0; 7].map(|_| meta.advice_column()))
    }

    pub(crate) fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &MptUpdateRow<F>,
    ) -> Result<(), Error> {
        for (column, value) in self.0.iter().zip_eq(row.values()) {
            region.assign_advice(
                || "assign mpt table row value",
                *column,
                offset,
                || Value::known(*value),
            )?;
        }
        Ok(())
    }

    pub(crate) fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        updates: &MptUpdates,
        randomness: F,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "mpt table",
            |mut region| self.load_with_region(&mut region, updates, randomness),
        )
    }

    pub(crate) fn load_with_region<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        updates: &MptUpdates,
        randomness: F,
    ) -> Result<(), Error> {
        for (offset, row) in updates.table_assignments(randomness).iter().enumerate() {
            self.assign(region, offset, row)?;
        }
        Ok(())
    }
}

/// Tag to identify the field in a Bytecode Table row
#[derive(Clone, Copy, Debug)]
pub enum BytecodeFieldTag {
    /// Length field
    Length,
    /// Byte field
    Byte,
    /// Padding field
    Padding,
}
impl_expr!(BytecodeFieldTag);

/// Table with Bytecode indexed by its Code Hash
#[derive(Clone, Debug)]
pub struct BytecodeTable {
    /// Code Hash
    pub code_hash: Column<Advice>,
    /// Tag
    pub tag: Column<Advice>,
    /// Index
    pub index: Column<Advice>,
    /// Is Code is true when the byte is not an argument to a PUSH* instruction.
    pub is_code: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
}

impl BytecodeTable {
    /// Construct a new BytecodeTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let [tag, index, is_code, value] = array::from_fn(|_| meta.advice_column());
        let code_hash = meta.advice_column();
        Self {
            code_hash,
            tag,
            index,
            is_code,
            value,
        }
    }

    /// Assign the `BytecodeTable` from a list of bytecodes, followig the same
    /// table layout that the Bytecode Circuit uses.
    pub fn load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        bytecodes: impl IntoIterator<Item = &'a Bytecode> + Clone,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "bytecode table",
            |mut region| {
                let mut offset = 0;
                for column in self.columns() {
                    region.assign_advice(
                        || "bytecode table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let bytecode_table_columns = self.columns();
                for bytecode in bytecodes.clone() {
                    for row in bytecode.table_assignments(challenges) {
                        for (column, value) in bytecode_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("bytecode table row {}", offset),
                                *column,
                                offset,
                                || value,
                            )?;
                        }
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }
}

impl DynamicTableColumns for BytecodeTable {
    fn columns(&self) -> Vec<Column<Advice>> {
        vec![
            self.code_hash,
            self.tag,
            self.index,
            self.is_code,
            self.value,
        ]
    }
}

/// Tag to identify the field in a Block Table row
// Keep the sequence consistent with OpcodeId for scalar
#[derive(Clone, Copy, Debug)]
pub enum BlockContextFieldTag {
    /// Coinbase field
    Coinbase = 1,
    /// Timestamp field
    Timestamp,
    /// Number field
    Number,
    /// Difficulty field
    Difficulty,
    /// Gas Limit field
    GasLimit,
    /// Base Fee field
    BaseFee = 8,
    /// Block Hash field
    BlockHash,
    /// Chain ID field.  Although this is not a field in the block header, we
    /// add it here for convenience.
    ChainId,
    /// In a multi-block setup, this variant represents the total number of txs
    /// included in this block.
    NumTxs,
    /// In a multi-block setup, this variant represents the cumulative number of
    /// txs included up to this block, including the txs in this block.
    CumNumTxs,
}
impl_expr!(BlockContextFieldTag);

/// Table with Block header fields
#[derive(Clone, Debug)]
pub struct BlockTable {
    /// Tag
    pub tag: Column<Advice>,
    /// Index
    pub index: Column<Advice>,
    /// Value
    pub value: Column<Advice>,
}

impl BlockTable {
    /// Construct a new BlockTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.advice_column(),
            index: meta.advice_column(),
            value: meta.advice_column(),
        }
    }

    /// Assign the `BlockTable` from a `BlockContext`.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        block_ctxs: &BlockContexts,
        txs: &[Transaction],
        randomness: F,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "block table",
            |mut region| {
                let mut offset = 0;
                let block_table_columns = self.columns();
                for column in block_table_columns.iter() {
                    region.assign_advice(
                        || "block table all-zero row",
                        *column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let mut cum_num_txs = 0usize;
                for block_ctx in block_ctxs.ctxs.values() {
                    let num_txs = txs
                        .iter()
                        .filter(|tx| tx.block_number == block_ctx.number.as_u64())
                        .count();
                    cum_num_txs += num_txs;
                    for row in block_ctx.table_assignments(num_txs, cum_num_txs, randomness) {
                        for (column, value) in block_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("block table row {}", offset),
                                *column,
                                offset,
                                || Value::known(value),
                            )?;
                        }
                        offset += 1;
                    }
                }

                Ok(())
            },
        )
    }
}

impl DynamicTableColumns for BlockTable {
    fn columns(&self) -> Vec<Column<Advice>> {
        vec![self.tag, self.index, self.value]
    }
}

/// Keccak Table, used to verify keccak hashing from RLC'ed input.
#[derive(Clone, Debug)]
pub struct KeccakTable {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// Byte array input as `RLC(reversed(input))`
    pub input_rlc: Column<Advice>, // RLC of input bytes
    /// Byte array input length
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub output_rlc: Column<Advice>, // RLC of hash of input bytes
}

impl KeccakTable {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_enabled: meta.advice_column(),
            input_rlc: meta.advice_column(),
            input_len: meta.advice_column(),
            output_rlc: meta.advice_column(),
        }
    }

    /// Generate the keccak table assignments from a byte array input.
    pub fn assignments<F: Field>(
        input: &[u8],
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        let input_rlc = challenges
            .keccak_input()
            .map(|challenge| rlc::value(input.iter().rev(), challenge));
        let input_len = F::from(input.len() as u64);
        let mut keccak = Keccak::default();
        keccak.update(input);
        let output = keccak.digest();
        let output_rlc = challenges.evm_word().map(|challenge| {
            RandomLinearCombination::<F, 32>::random_linear_combine(
                Word::from_big_endian(output.as_slice()).to_le_bytes(),
                challenge,
            )
        });

        vec![[
            Value::known(F::one()),
            input_rlc,
            Value::known(input_len),
            output_rlc,
        ]]
    }

    /// Assign a table row for keccak table
    pub fn assign_row<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        values: [F; 4],
    ) -> Result<(), Error> {
        for (column, value) in self.columns().iter().zip(values.iter()) {
            region.assign_advice(
                || format!("assign {}", offset),
                *column,
                offset,
                || Value::known(*value),
            )?;
        }
        Ok(())
    }

    /// Provide this function for the case that we want to consume a keccak
    /// table but without running the full keccak circuit
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: impl IntoIterator<Item = &'a Vec<u8>> + Clone,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "keccak table",
            |mut region| {
                let mut offset = 0;
                for column in self.columns() {
                    region.assign_advice(
                        || "keccak table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let keccak_table_columns = self.columns();
                for input in inputs.clone() {
                    for row in Self::assignments(input, challenges) {
                        // let mut column_index = 0;
                        for (column, value) in keccak_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("keccak table row {}", offset),
                                *column,
                                offset,
                                || value,
                            )?;
                        }
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }
}

impl DynamicTableColumns for KeccakTable {
    fn columns(&self) -> Vec<Column<Advice>> {
        vec![
            self.is_enabled,
            self.input_rlc,
            self.input_len,
            self.output_rlc,
        ]
    }
}

/// Copy Table, used to verify copies of byte chunks between Memory, Bytecode,
/// TxLogs and TxCallData.
#[derive(Clone, Copy, Debug)]
pub struct CopyTable {
    /// Whether the row is the first read-write pair for a copy event.
    pub is_first: Column<Advice>,
    /// The relevant ID for the read-write row, represented as a random linear
    /// combination. The ID may be one of the below:
    /// 1. Call ID/Caller ID for CopyDataType::Memory
    /// 2. RLC encoding of bytecode hash for CopyDataType::Bytecode
    /// 3. Transaction ID for CopyDataType::TxCalldata, CopyDataType::TxLog
    pub id: Column<Advice>,
    /// The source/destination address for this copy step.  Can be memory
    /// address, byte index in the bytecode, tx call data, and tx log data.
    pub addr: Column<Advice>,
    /// The end of the source buffer for the copy event.  Any data read from an
    /// address greater than or equal to this value will be 0.
    pub src_addr_end: Column<Advice>,
    /// The number of bytes left to be copied.
    pub bytes_left: Column<Advice>,
    /// An accumulator value in the RLC representation. This is used for
    /// specific purposes, for instance, when `tag == CopyDataType::RlcAcc`.
    /// Having an additional column for the `rlc_acc` simplifies the lookup
    /// to copy table.
    pub rlc_acc: Column<Advice>,
    /// The associated read-write counter for this row.
    pub rw_counter: Column<Advice>,
    /// Decrementing counter denoting reverse read-write counter.
    pub rwc_inc_left: Column<Advice>,
    /// Binary chip to constrain the copy table conditionally depending on the
    /// current row's tag, whether it is Bytecode, Memory, TxCalldata or
    /// TxLog.
    pub tag: BinaryNumberConfig<CopyDataType, 3>,
}

type CopyTableRow<F> = [(F, &'static str); 8];
type CopyCircuitRow<F> = [(F, &'static str); 4];

impl CopyTable {
    /// Construct a new CopyTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>, q_enable: Column<Fixed>) -> Self {
        Self {
            is_first: meta.advice_column(),
            id: meta.advice_column(),
            tag: BinaryNumberChip::configure(meta, q_enable, None),
            addr: meta.advice_column(),
            src_addr_end: meta.advice_column(),
            bytes_left: meta.advice_column(),
            rlc_acc: meta.advice_column(),
            rw_counter: meta.advice_column(),
            rwc_inc_left: meta.advice_column(),
        }
    }

    /// Generate the copy table and copy circuit assignments from a copy event.
    pub fn assignments<F: Field>(
        copy_event: &CopyEvent,
        randomness: F,
    ) -> Vec<(CopyDataType, CopyTableRow<F>, CopyCircuitRow<F>)> {
        let mut assignments = Vec::new();
        // rlc_acc
        let rlc_acc = if copy_event.dst_type == CopyDataType::RlcAcc {
            let values = copy_event
                .bytes
                .iter()
                .map(|(value, _)| *value)
                .collect::<Vec<u8>>();
            rlc::value(values.iter().rev(), randomness)
        } else {
            F::zero()
        };
        let mut value_acc = F::zero();
        for (step_idx, (is_read_step, copy_step)) in copy_event
            .bytes
            .iter()
            .flat_map(|(value, is_code)| {
                let read_step = CopyStep {
                    value: *value,
                    is_code: if copy_event.src_type == CopyDataType::Bytecode {
                        Some(*is_code)
                    } else {
                        None
                    },
                };
                let write_step = CopyStep {
                    value: *value,
                    is_code: if copy_event.dst_type == CopyDataType::Bytecode {
                        Some(*is_code)
                    } else {
                        None
                    },
                };
                once((true, read_step)).chain(once((false, write_step)))
            })
            .enumerate()
        {
            // is_first
            let is_first = if step_idx == 0 { F::one() } else { F::zero() };
            // is last
            let is_last = if step_idx == copy_event.bytes.len() * 2 - 1 {
                F::one()
            } else {
                F::zero()
            };

            // id
            let id = if is_read_step {
                number_or_hash_to_field(&copy_event.src_id, randomness)
            } else {
                number_or_hash_to_field(&copy_event.dst_id, randomness)
            };

            // tag binary bumber chip
            let tag = if is_read_step {
                copy_event.src_type
            } else {
                copy_event.dst_type
            };

            // addr
            let copy_step_addr: u64 =
                if is_read_step {
                    copy_event.src_addr
                } else {
                    copy_event.dst_addr
                } + (u64::try_from(step_idx).unwrap() - if is_read_step { 0 } else { 1 }) / 2u64;

            let addr = if tag == CopyDataType::TxLog {
                build_tx_log_address(
                    copy_step_addr,
                    TxLogFieldTag::Data,
                    copy_event.log_id.unwrap(),
                )
                .to_scalar()
                .unwrap()
            } else {
                F::from(copy_step_addr)
            };

            // bytes_left
            let bytes_left = u64::try_from(copy_event.bytes.len() * 2 - step_idx).unwrap() / 2;
            // value
            let value = if copy_event.dst_type == CopyDataType::RlcAcc {
                if is_read_step {
                    F::from(copy_step.value as u64)
                } else {
                    value_acc = value_acc * randomness + F::from(copy_step.value as u64);
                    value_acc
                }
            } else {
                F::from(copy_step.value as u64)
            };
            // is_pad
            let is_pad = F::from(is_read_step && copy_step_addr >= copy_event.src_addr_end);

            // is_code
            let is_code = copy_step.is_code.map_or(F::zero(), |v| F::from(v));

            assignments.push((
                tag,
                [
                    (is_first, "is_first"),
                    (id, "id"),
                    (addr, "addr"),
                    (F::from(copy_event.src_addr_end), "src_addr_end"),
                    (F::from(bytes_left), "bytes_left"),
                    (rlc_acc, "rlc_acc"),
                    (F::from(copy_event.rw_counter(step_idx)), "rw_counter"),
                    (
                        F::from(copy_event.rw_counter_increase_left(step_idx)),
                        "rwc_inc_left",
                    ),
                ],
                [
                    (is_last, "is_last"),
                    (value, "value"),
                    (is_pad, "is_pad"),
                    (is_code, "is_code"),
                ],
            ));
        }
        assignments
    }

    /// Assign the `CopyTable` from a `Block`.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
        randomness: F,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "copy table",
            |mut region| {
                let mut offset = 0;
                for column in self.columns() {
                    region.assign_advice(
                        || "copy table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let tag_chip = BinaryNumberChip::construct(self.tag);
                let copy_table_columns = self.columns();
                for copy_event in block.copy_events.iter() {
                    for (tag, row, _) in Self::assignments(copy_event, randomness) {
                        for (column, (value, label)) in copy_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("{} at row: {}", label, offset),
                                *column,
                                offset,
                                || Value::known(value),
                            )?;
                        }
                        tag_chip.assign(&mut region, offset, &tag)?;
                        offset += 1;
                    }
                }

                Ok(())
            },
        )
    }
}

impl CopyTable {
    pub(crate) fn columns(&self) -> Vec<Column<Advice>> {
        vec![
            self.is_first,
            self.id,
            self.addr,
            self.src_addr_end,
            self.bytes_left,
            self.rlc_acc,
            self.rw_counter,
            self.rwc_inc_left,
        ]
    }
}

impl<F: Field> LookupTable<F> for CopyTable {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.is_first, Rotation::cur()),
            meta.query_advice(self.id, Rotation::cur()), // src_id
            self.tag.value(Rotation::cur())(meta),       // src_tag
            meta.query_advice(self.id, Rotation::next()), // dst_id
            self.tag.value(Rotation::next())(meta),      // dst_tag
            meta.query_advice(self.addr, Rotation::cur()), // src_addr
            meta.query_advice(self.src_addr_end, Rotation::cur()), // src_addr_end
            meta.query_advice(self.addr, Rotation::next()), // dst_addr
            meta.query_advice(self.bytes_left, Rotation::cur()), // length
            meta.query_advice(self.rlc_acc, Rotation::cur()), // rlc_acc
            meta.query_advice(self.rw_counter, Rotation::cur()), // rw_counter
            meta.query_advice(self.rwc_inc_left, Rotation::cur()), // rwc_inc_left
        ]
    }
}
