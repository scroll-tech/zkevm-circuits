//! Table definitions used cross-circuits

use crate::copy_circuit::number_or_hash_to_field;
use crate::evm_circuit::witness::{Rw, RwRow};
use crate::evm_circuit::{
    util::{rlc, RandomLinearCombination},
    witness::{Block, BlockContext, Bytecode, RwMap, Transaction},
};
use crate::impl_expr;
use bus_mapping::circuit_input_builder::{CopyDataType, CopyEvent};
use eth_types::{Field, ToAddress, ToLittleEndian, ToScalar, Word, U256};
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use halo2_proofs::{circuit::Layouter, plonk::*, poly::Rotation};
use itertools::Itertools;
use keccak256::plain::Keccak;
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
                        || Ok(F::zero()),
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
                                || Ok(value),
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
#[derive(Clone, Copy, Debug, EnumIter)]
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
            region.assign_advice(|| "assign rw row on rw table", column, offset, || Ok(value))?;
        }
        Ok(())
    }

    /// Assign the `RwTable` from a `RwMap`, followig the same
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
        Self {
            code_hash: meta.advice_column(),
            tag: meta.advice_column(),
            index: meta.advice_column(),
            is_code: meta.advice_column(),
            value: meta.advice_column(),
        }
    }

    /// Assign the `BytecodeTable` from a list of bytecodes, followig the same
    /// table layout that the Bytecode Circuit uses.
    pub fn load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        bytecodes: impl IntoIterator<Item = &'a Bytecode> + Clone,
        randomness: F,
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
                        || Ok(F::zero()),
                    )?;
                }
                offset += 1;

                let bytecode_table_columns = self.columns();
                for bytecode in bytecodes.clone() {
                    for row in bytecode.table_assignments(randomness) {
                        for (column, value) in bytecode_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("bytecode table row {}", offset),
                                *column,
                                offset,
                                || Ok(value),
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
        block: &BlockContext,
        randomness: F,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "block table",
            |mut region| {
                let mut offset = 0;
                for column in self.columns() {
                    region.assign_advice(
                        || "block table all-zero row",
                        column,
                        offset,
                        || Ok(F::zero()),
                    )?;
                }
                offset += 1;

                let block_table_columns = self.columns();
                for row in block.table_assignments(randomness) {
                    for (column, value) in block_table_columns.iter().zip_eq(row) {
                        region.assign_advice(
                            || format!("block table row {}", offset),
                            *column,
                            offset,
                            || Ok(value),
                        )?;
                    }
                    offset += 1;
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
    pub fn assignments<F: Field>(input: &[u8], randomness: F) -> Vec<[F; 4]> {
        let input_rlc: F = rlc::value(input.iter().rev(), randomness);
        let input_len = F::from(input.len() as u64);
        let mut keccak = Keccak::default();
        keccak.update(input);
        let output = keccak.digest();
        let output_rlc = RandomLinearCombination::<F, 32>::random_linear_combine(
            Word::from_big_endian(output.as_slice()).to_le_bytes(),
            randomness,
        );

        vec![[F::one(), input_rlc, input_len, output_rlc]]
    }

    // NOTE: For now, the input_rlc of the keccak is defined as
    // `RLC(reversed(input))` for convenience of the circuits that do the lookups.
    // This allows calculating the `input_rlc` after all the inputs bytes have been
    // layed out via the pattern `acc[i] = acc[i-1] * r + value[i]`.
    /// Assign the `KeccakTable` from a list hashing inputs, followig the same
    /// table layout that the Keccak Circuit uses.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: impl IntoIterator<Item = Vec<u8>> + Clone,
        randomness: F,
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
                        || Ok(F::zero()),
                    )?;
                }
                offset += 1;

                let keccak_table_columns = self.columns();
                for input in inputs.clone() {
                    for row in Self::assignments(&input, randomness) {
                        // let mut column_index = 0;
                        for (column, value) in keccak_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("keccak table row {}", offset),
                                *column,
                                offset,
                                || Ok(value),
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

    /// Generate the copy table assignments from a copy event.
    pub fn assignments<F: Field>(
        copy_event: &CopyEvent,
        randomness: F,
    ) -> Vec<(CopyDataType, [F; 8])> {
        let mut assignments = Vec::new();
        let rlc_acc = if copy_event.dst_type == CopyDataType::RlcAcc {
            let values = copy_event
                .steps
                .iter()
                .filter(|s| s.rw.is_write())
                .map(|s| s.value)
                .collect::<Vec<u8>>();
            rlc::value(values.iter().rev(), randomness)
        } else {
            F::zero()
        };
        for (step_idx, copy_step) in copy_event.steps.iter().enumerate() {
            // is_first
            let is_first = if step_idx == 0 { F::one() } else { F::zero() };
            // id
            let id = {
                let id = if copy_step.rw.is_read() {
                    &copy_event.src_id
                } else {
                    &copy_event.dst_id
                };
                number_or_hash_to_field(id, randomness)
            };
            // addr
            let addr = match copy_step.tag {
                CopyDataType::TxLog => {
                    let addr = (U256::from(copy_step.addr)
                        + (U256::from(TxLogFieldTag::Data as u64) << 32)
                        + (U256::from(copy_event.log_id.unwrap()) << 48))
                        .to_address();
                    addr.to_scalar().unwrap()
                }
                _ => F::from(copy_step.addr),
            };
            assignments.push((
                copy_step.tag,
                [
                    is_first,
                    id,
                    addr,
                    F::from(copy_event.src_addr_end), // src_addr_end
                    F::from(copy_event.length - step_idx as u64 / 2), // bytes_left
                    rlc_acc,                          // rlc_acc
                    F::from(copy_step.rwc.0 as u64),  // rw_counter
                    F::from(copy_step.rwc_inc_left),  // rw_inc_left
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
                        || Ok(F::zero()),
                    )?;
                }
                offset += 1;

                let tag_chip = BinaryNumberChip::construct(self.tag);
                let copy_table_columns = self.columns();
                for copy_event in block.copy_events.iter() {
                    for (tag, row) in Self::assignments(copy_event, randomness) {
                        for (column, value) in copy_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("copy table row {}", offset),
                                *column,
                                offset,
                                || Ok(value),
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
    fn columns(&self) -> Vec<Column<Advice>> {
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

/// Lookup table within the Exponentiation circuit.
#[derive(Clone, Debug)]
pub struct ExpTable {
    /// Whether this row is the first row in the circuit.
    pub is_first: Column<Advice>,
    /// The integer base of the exponentiation.
    pub base_limb: Column<Advice>,
    /// The integer exponent of the exponentiation.
    pub intermediate_exponent: Column<Advice>,
    /// The intermediate result of exponentiation by squaring.
    pub intermediate_exp_lo_hi: Column<Advice>,
}

impl ExpTable {
    /// Construct the Exponentiation table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_first: meta.advice_column(),
            base_limb: meta.advice_column(),
            intermediate_exponent: meta.advice_column(),
            intermediate_exp_lo_hi: meta.advice_column(),
        }
    }
}

impl<F: Field> LookupTable<F> for ExpTable {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.is_first, Rotation::cur()),
            meta.query_advice(self.base_limb, Rotation::cur()),
            meta.query_advice(self.base_limb, Rotation::next()),
            meta.query_advice(self.base_limb, Rotation(2)),
            meta.query_advice(self.base_limb, Rotation(3)),
            meta.query_advice(self.intermediate_exponent, Rotation::cur()),
            meta.query_advice(self.intermediate_exp_lo_hi, Rotation::cur()),
            meta.query_advice(self.intermediate_exp_lo_hi, Rotation::next()),
        ]
    }
}
