//! Execution step related module.

use std::{
    marker::PhantomData,
    ops::{Add, Mul},
};

use crate::{
    circuit_input_builder::CallContext,
    error::ExecError,
    exec_trace::OperationRef,
    operation::RWCounter,
    precompile::{PrecompileAuxData, PrecompileCalls},
};
use eth_types::{
    evm_types::{memory::MemoryWordRange, Gas, GasCost, MemoryAddress, OpcodeId, ProgramCounter},
    sign_types::SignData,
    GethExecStep, Word, H256,
};
use ethers_core::k256::elliptic_curve::subtle::CtOption;
use gadgets::impl_expr;
use halo2_proofs::{
    arithmetic::{CurveAffine, Field},
    halo2curves::{
        bn256::{Fq, Fr, G1Affine, G2Affine},
        group::cofactor::CofactorCurveAffine,
    },
    plonk::Expression,
};

/// An execution step of the EVM.
#[derive(Clone, Debug)]
pub struct ExecStep {
    /// Execution state
    pub exec_state: ExecState,
    /// Program Counter
    pub pc: ProgramCounter,
    /// Stack size
    pub stack_size: usize,
    /// Memory size
    pub memory_size: usize,
    /// Gas left
    pub gas_left: Gas,
    /// Gas cost of the step.  If the error is OutOfGas caused by a "gas uint64
    /// overflow", this value will **not** be the actual Gas cost of the
    /// step.
    pub gas_cost: GasCost,
    /// Accumulated gas refund
    pub gas_refund: Gas,
    /// Call index within the Transaction.
    pub call_index: usize,
    /// The global counter when this step was executed.
    pub rwc: RWCounter,
    /// Reversible Write Counter.  Counter of write operations in the call that
    /// will need to be undone in case of a revert.  Value at the beginning of
    /// the step.
    pub reversible_write_counter: usize,
    /// Number of reversible write operations done by this step.
    pub reversible_write_counter_delta: usize,
    /// Log index when this step was executed.
    pub log_id: usize,
    /// The list of references to Operations in the container
    pub bus_mapping_instance: Vec<OperationRef>,
    /// Number of rw operations performed via a copy event in this step.
    pub copy_rw_counter_delta: u64,
    /// Error generated by this step
    pub error: Option<ExecError>,
    /// Optional auxiliary data that is attached to precompile call internal states.
    pub aux_data: Option<PrecompileAuxData>,
}

impl ExecStep {
    /// Create a new Self from a `GethExecStep`.
    pub fn new(
        step: &GethExecStep,
        call_ctx: &CallContext,
        rwc: RWCounter,
        reversible_write_counter: usize,
        log_id: usize,
    ) -> Self {
        ExecStep {
            exec_state: ExecState::Op(step.op),
            pc: step.pc,
            stack_size: step.stack.0.len(),
            memory_size: call_ctx.memory.len(),
            gas_left: step.gas,
            gas_cost: step.gas_cost,
            gas_refund: step.refund,
            call_index: call_ctx.index,
            rwc,
            reversible_write_counter,
            reversible_write_counter_delta: 0,
            log_id,
            bus_mapping_instance: Vec::new(),
            copy_rw_counter_delta: 0,
            error: None,
            aux_data: None,
        }
    }

    /// Returns `true` if `error` is oog and stack related..
    pub fn oog_or_stack_error(&self) -> bool {
        matches!(
            self.error,
            Some(ExecError::OutOfGas(_) | ExecError::StackOverflow | ExecError::StackUnderflow)
        )
    }

    /// Returns `true` if this is an execution step of Precompile.
    pub fn is_precompiled(&self) -> bool {
        matches!(self.exec_state, ExecState::Precompile(_))
    }
}

impl Default for ExecStep {
    fn default() -> Self {
        Self {
            exec_state: ExecState::Op(OpcodeId::INVALID(0)),
            pc: ProgramCounter(0),
            stack_size: 0,
            memory_size: 0,
            gas_left: Gas(0),
            gas_cost: GasCost(0),
            gas_refund: Gas(0),
            call_index: 0,
            rwc: RWCounter(0),
            reversible_write_counter: 0,
            reversible_write_counter_delta: 0,
            log_id: 0,
            bus_mapping_instance: Vec::new(),
            copy_rw_counter_delta: 0,
            error: None,
            aux_data: None,
        }
    }
}

/// Execution state
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecState {
    /// EVM Opcode ID
    Op(OpcodeId),
    /// Precompile call
    Precompile(PrecompileCalls),
    /// Virtual step Begin Tx
    BeginTx,
    /// Virtual step End Tx
    EndTx,
    /// Virtual step End Block
    EndBlock,
}

impl ExecState {
    /// Returns `true` if `ExecState` is an opcode and the opcode is a `PUSHn`.
    pub fn is_push(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_push()
        } else {
            false
        }
    }

    /// Returns `true` if `ExecState` is an opcode and the opcode is a `DUPn`.
    pub fn is_dup(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_dup()
        } else {
            false
        }
    }

    /// Returns `true` if `ExecState` is an opcode and the opcode is a `SWAPn`.
    pub fn is_swap(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_swap()
        } else {
            false
        }
    }

    /// Returns `true` if `ExecState` is an opcode and the opcode is a `Logn`.
    pub fn is_log(&self) -> bool {
        if let ExecState::Op(op) = self {
            op.is_log()
        } else {
            false
        }
    }
}

/// Defines the various source/destination types for a copy event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyDataType {
    /// When we need to pad the Copy rows of the circuit up to a certain maximum
    /// with rows that are not "useful".
    Padding,
    /// When the source for the copy event is the bytecode table.
    Bytecode,
    /// When the source/destination for the copy event is memory.
    Memory,
    /// When the source for the copy event is tx's calldata.
    TxCalldata,
    /// When the destination for the copy event is tx's log.
    TxLog,
    /// When the destination rows are not directly for copying but for a special
    /// scenario where we wish to accumulate the value (RLC) over all rows.
    /// This is used for Copy Lookup from SHA3 opcode verification.
    RlcAcc,
}
impl CopyDataType {
    /// How many bits are necessary to represent a copy data type.
    pub const N_BITS: usize = 3usize;
}
const NUM_COPY_DATA_TYPES: usize = 6usize;
pub struct CopyDataTypeIter {
    idx: usize,
    back_idx: usize,
    marker: PhantomData<()>,
}
impl CopyDataTypeIter {
    fn get(&self, idx: usize) -> Option<CopyDataType> {
        match idx {
            0usize => Some(CopyDataType::Padding),
            1usize => Some(CopyDataType::Bytecode),
            2usize => Some(CopyDataType::Memory),
            3usize => Some(CopyDataType::TxCalldata),
            4usize => Some(CopyDataType::TxLog),
            5usize => Some(CopyDataType::RlcAcc),
            _ => None,
        }
    }
}
impl strum::IntoEnumIterator for CopyDataType {
    type Iterator = CopyDataTypeIter;
    fn iter() -> CopyDataTypeIter {
        CopyDataTypeIter {
            idx: 0,
            back_idx: 0,
            marker: PhantomData,
        }
    }
}
impl Iterator for CopyDataTypeIter {
    type Item = CopyDataType;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        #[allow(clippy::iter_nth_zero)]
        self.nth(0)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let t = if self.idx + self.back_idx >= NUM_COPY_DATA_TYPES {
            0
        } else {
            NUM_COPY_DATA_TYPES - self.idx - self.back_idx
        };
        (t, Some(t))
    }
    fn nth(&mut self, n: usize) -> Option<<Self as Iterator>::Item> {
        let idx = self.idx + n + 1;
        if idx + self.back_idx > NUM_COPY_DATA_TYPES {
            self.idx = NUM_COPY_DATA_TYPES;
            None
        } else {
            self.idx = idx;
            self.get(idx - 1)
        }
    }
}
impl ExactSizeIterator for CopyDataTypeIter {
    fn len(&self) -> usize {
        self.size_hint().0
    }
}
impl DoubleEndedIterator for CopyDataTypeIter {
    fn next_back(&mut self) -> Option<<Self as Iterator>::Item> {
        let back_idx = self.back_idx + 1;
        if self.idx + back_idx > NUM_COPY_DATA_TYPES {
            self.back_idx = NUM_COPY_DATA_TYPES;
            None
        } else {
            self.back_idx = back_idx;
            self.get(NUM_COPY_DATA_TYPES - self.back_idx)
        }
    }
}

impl From<CopyDataType> for usize {
    fn from(t: CopyDataType) -> Self {
        match t {
            CopyDataType::Padding => 0,
            CopyDataType::Bytecode => 1,
            CopyDataType::Memory => 2,
            CopyDataType::TxCalldata => 3,
            CopyDataType::TxLog => 4,
            CopyDataType::RlcAcc => 5,
        }
    }
}

impl From<&CopyDataType> for u64 {
    fn from(t: &CopyDataType) -> Self {
        match t {
            CopyDataType::Padding => 0,
            CopyDataType::Bytecode => 1,
            CopyDataType::Memory => 2,
            CopyDataType::TxCalldata => 3,
            CopyDataType::TxLog => 4,
            CopyDataType::RlcAcc => 5,
        }
    }
}

impl Default for CopyDataType {
    fn default() -> Self {
        Self::Memory
    }
}

impl_expr!(CopyDataType, u64::from);

/// Defines a single copy step in a copy event. This type is unified over the
/// source/destination row in the copy table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyStep {
    /// Byte value copied in this step.
    pub value: u8,
    /// Byte value before this step.
    pub prev_value: u8,
    /// mask indicates this byte won't be copied.
    pub mask: bool,
    /// Optional field which is enabled only for the source being `bytecode`,
    /// and represents whether or not the byte is an opcode.
    pub is_code: Option<bool>,
}

/// Defines an enum type that can hold either a number or a hash value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NumberOrHash {
    /// Variant to indicate a number value.
    Number(usize),
    /// Variant to indicate a 256-bits hash value.
    Hash(H256),
}

/// Represents all bytes related in one copy event.
///
/// - When the source is memory, `bytes` is the memory content, including masked areas. The
///   destination data is the non-masked bytes.
/// - When only the destination is memory or log, `bytes` is the memory content to write, including
///   masked areas. The source data is the non-masked bytes.
/// - When both source and destination are memory or log, it is `aux_bytes` that holds the
///   destination memory.
///
/// Additionally, when the destination is memory, `bytes_write_prev` holds the memory content
/// *before* the write.
#[derive(Clone, Debug)]
pub struct CopyBytes {
    /// Represents the list of (bytes, is_code, mask) copied during this copy event
    pub bytes: Vec<(u8, bool, bool)>,
    /// Represents the list of (bytes, is_code, mask) read to copy during this copy event, used for
    /// memory to memory write case
    pub aux_bytes: Option<Vec<(u8, bool, bool)>>,
    /// Represents the list of bytes before this copy event, it is required for memory write copy
    /// event
    pub bytes_write_prev: Option<Vec<u8>>,
}

impl CopyBytes {
    /// construct CopyBytes instance
    pub fn new(
        bytes: Vec<(u8, bool, bool)>,
        aux_bytes: Option<Vec<(u8, bool, bool)>>,
        bytes_write_prev: Option<Vec<u8>>,
    ) -> Self {
        Self {
            bytes,
            aux_bytes,
            bytes_write_prev,
        }
    }
}

/// Defines a copy event associated with EVM opcodes such as CALLDATACOPY,
/// CODECOPY, CREATE, etc. More information:
/// <https://github.com/privacy-scaling-explorations/zkevm-specs/blob/master/specs/copy-proof.md>.
#[derive(Clone, Debug)]
pub struct CopyEvent {
    /// Represents the start address at the source of the copy event.
    pub src_addr: u64,
    /// Represents the end address at the source of the copy event.
    /// It must be `src_addr_end >= src_addr`.
    pub src_addr_end: u64,
    /// Represents the source type.
    pub src_type: CopyDataType,
    /// Represents the relevant ID for source.
    pub src_id: NumberOrHash,
    /// Represents the start address at the destination of the copy event.
    pub dst_addr: u64,
    /// Represents the destination type.
    pub dst_type: CopyDataType,
    /// Represents the relevant ID for destination.
    pub dst_id: NumberOrHash,
    /// An optional field to hold the log ID in case of the destination being
    /// TxLog.
    pub log_id: Option<u64>,
    /// Value of rw counter at start of this copy event
    pub rw_counter_start: RWCounter,
    /// Represents the list of bytes related during this copy event
    pub copy_bytes: CopyBytes,
}

pub type CopyEventSteps = Vec<(u8, bool, bool)>;
pub type CopyEventPrevBytes = Vec<u8>;

impl CopyEvent {
    /// The full length of the event, including masked segments.
    pub fn full_length(&self) -> u64 {
        self.copy_bytes.bytes.len() as u64
    }

    /// The length of the copied data, excluding masked segments.
    pub fn copy_length(&self) -> u64 {
        self.copy_bytes.bytes.iter().filter(|&step| !step.2).count() as u64
    }

    /// Whether the source performs RW lookups in the state circuit.
    pub fn is_source_rw(&self) -> bool {
        self.src_type == CopyDataType::Memory
    }

    /// Whether the destination performs RW lookups in the state circuit.
    pub fn is_destination_rw(&self) -> bool {
        self.dst_type == CopyDataType::Memory || self.dst_type == CopyDataType::TxLog
    }

    /// Whether the RLC of data must be computed.
    pub fn has_rlc(&self) -> bool {
        matches!(
            (self.src_type, self.dst_type),
            (CopyDataType::RlcAcc, _) | (_, CopyDataType::RlcAcc) | (_, CopyDataType::Bytecode)
        )
    }

    /// The RW counter of the first RW lookup performed by this copy event.
    pub fn rw_counter_start(&self) -> u64 {
        usize::from(self.rw_counter_start) as u64
    }

    /// The number of RW lookups performed by this copy event.
    pub fn rw_counter_delta(&self) -> u64 {
        (self.is_source_rw() as u64 + self.is_destination_rw() as u64) * (self.full_length() / 32)
    }
}

/// Defines a builder to construct a copy event.
///
/// ```markdown
///     │◄──read_offset──►│
///     ├─────────────────┼───────────────┬──────┐
///     │                 │ Source  Bytes │      │
///     └─────────────────┼───────┬───────┼──────┘
///      get_padding      │     mapper    │
/// ┌─────────▼───────────┼───────▼───────┼─────────┐
/// │      Padding        │ Copied  Bytes │ Padding │
/// ├─────────────────────┼───────────────┼─────────┤
/// │◄────write_offset───►│◄───length────►│         │
/// │◄─────────────── step_length ─────────────────►│
/// ```
pub struct CopyEventStepsBuilder<
    Source,
    ReadOffset,
    WriteOffset,
    StepLength,
    Length,
    Padding,
    Mapper,
> {
    source: Source,
    read_offset: ReadOffset,
    write_offset: WriteOffset,
    step_length: StepLength,
    length: Length,
    padding_byte_getter: Padding,
    mapper: Mapper,
}

impl Default for CopyEventStepsBuilder<(), (), (), (), (), (), ()> {
    fn default() -> Self {
        Self::new()
    }
}

impl CopyEventStepsBuilder<(), (), (), (), (), (), ()> {
    /// Create a new copy steps builder.
    pub fn new() -> Self {
        CopyEventStepsBuilder {
            source: (),
            read_offset: (),
            write_offset: (),
            step_length: (),
            length: (),
            padding_byte_getter: (),
            mapper: (),
        }
    }

    /// Create a memory copy steps builder.
    #[allow(clippy::type_complexity)]
    pub fn memory() -> CopyEventStepsBuilder<
        (),
        (),
        (),
        (),
        (),
        Box<dyn Fn(&[u8], usize) -> u8>,
        Box<dyn Fn(&u8) -> (u8, bool)>,
    > {
        Self::new()
            .padding_byte_getter(
                Box::new(|s: &[u8], idx: usize| s.get(idx).copied().unwrap_or(0))
                    as Box<dyn Fn(&[u8], usize) -> u8>,
            )
            .mapper(Box::new(|v: &u8| (*v, false)) as Box<dyn Fn(&u8) -> (u8, bool)>)
    }

    /// Create a memory copy steps builder from rage.
    #[allow(clippy::type_complexity)]
    pub fn memory_range(
        range: MemoryWordRange,
    ) -> CopyEventStepsBuilder<
        (),
        MemoryAddress,
        MemoryAddress,
        MemoryAddress,
        MemoryAddress,
        Box<dyn Fn(&[u8], usize) -> u8>,
        Box<dyn Fn(&u8) -> (u8, bool)>,
    > {
        Self::memory()
            .read_offset(range.shift())
            .write_offset(range.shift())
            .step_length(range.full_length())
            .length(range.original_length())
    }
}

impl<Source, ReadOffset, WriteOffset, StepLength, Length, Padding, Mapper>
    CopyEventStepsBuilder<Source, ReadOffset, WriteOffset, StepLength, Length, Padding, Mapper>
{
    /// Set source
    pub fn source<New>(
        self,
        source: New,
    ) -> CopyEventStepsBuilder<New, ReadOffset, WriteOffset, StepLength, Length, Padding, Mapper>
    {
        let CopyEventStepsBuilder {
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
            ..
        } = self;
        CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
        }
    }

    /// Set read offset
    pub fn read_offset<New>(
        self,
        read_offset: New,
    ) -> CopyEventStepsBuilder<Source, New, WriteOffset, StepLength, Length, Padding, Mapper> {
        let CopyEventStepsBuilder {
            source,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
            ..
        } = self;
        CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
        }
    }

    /// Set write offset
    pub fn write_offset<New>(
        self,
        write_offset: New,
    ) -> CopyEventStepsBuilder<Source, ReadOffset, New, StepLength, Length, Padding, Mapper> {
        let CopyEventStepsBuilder {
            source,
            read_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
            ..
        } = self;
        CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
        }
    }

    /// Set step length
    pub fn step_length<New>(
        self,
        step_length: New,
    ) -> CopyEventStepsBuilder<Source, ReadOffset, WriteOffset, New, Length, Padding, Mapper> {
        let CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            length,
            padding_byte_getter,
            mapper,
            ..
        } = self;
        CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
        }
    }

    /// Set length
    pub fn length<New>(
        self,
        length: New,
    ) -> CopyEventStepsBuilder<Source, ReadOffset, WriteOffset, StepLength, New, Padding, Mapper>
    {
        let CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            padding_byte_getter,
            mapper,
            ..
        } = self;
        CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
        }
    }

    /// Set padding byte getter
    pub fn padding_byte_getter<New>(
        self,
        padding_byte_getter: New,
    ) -> CopyEventStepsBuilder<Source, ReadOffset, WriteOffset, StepLength, Length, New, Mapper>
    {
        let CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            mapper,
            ..
        } = self;
        CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
        }
    }

    /// Set mapper
    pub fn mapper<New>(
        self,
        mapper: New,
    ) -> CopyEventStepsBuilder<Source, ReadOffset, WriteOffset, StepLength, Length, Padding, New>
    {
        let CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            ..
        } = self;
        CopyEventStepsBuilder {
            source,
            read_offset,
            write_offset,
            step_length,
            length,
            padding_byte_getter,
            mapper,
        }
    }
}

impl<'a, T: 'a, ReadOffset, WriteOffset, StepLength, Length, Padding, Mapper>
    CopyEventStepsBuilder<&'a [T], ReadOffset, WriteOffset, StepLength, Length, Padding, Mapper>
where
    ReadOffset: Into<MemoryAddress>,
    WriteOffset: Into<MemoryAddress>,
    StepLength: Into<MemoryAddress>,
    Length: Into<MemoryAddress>,
    Padding: Fn(&[T], usize) -> u8,
    Mapper: Fn(&T) -> (u8, bool),
{
    /// Build the copy event steps.
    pub fn build(self) -> CopyEventSteps {
        let read_offset = self.read_offset.into().0;
        let write_offset = self.write_offset.into().0;
        let step_length = self.step_length.into().0;
        let length = self.length.into().0;
        let read_end = read_offset
            .checked_add(length)
            .expect("unexpected overflow");

        let mut steps = Vec::with_capacity(step_length);
        for idx in 0..step_length {
            if (idx < write_offset) || (idx >= write_offset + length) {
                // padding bytes
                let value = (self.padding_byte_getter)(self.source, idx);
                steps.push((value, false, true));
            } else {
                let addr = read_offset
                    .checked_add(idx - write_offset)
                    .unwrap_or(read_end);
                if addr < self.source.len() {
                    let (value, is_code) = (self.mapper)(&self.source[addr]);
                    steps.push((value, is_code, false));
                } else {
                    // out range bytes
                    steps.push((0, false, false));
                }
            }
        }
        steps
    }
}

/// Intermediary multiplication step, representing `a * b == d (mod 2^256)`
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpStep {
    /// First multiplicand.
    pub a: Word,
    /// Second multiplicand.
    pub b: Word,
    /// Multiplication result.
    pub d: Word,
}

impl From<(Word, Word, Word)> for ExpStep {
    fn from(values: (Word, Word, Word)) -> Self {
        Self {
            a: values.0,
            b: values.1,
            d: values.2,
        }
    }
}

/// Event representating an exponentiation `a ^ b == d (mod 2^256)`.
#[derive(Clone, Debug)]
pub struct ExpEvent {
    /// Identifier for the exponentiation trace.
    pub identifier: usize,
    /// Base `a` for the exponentiation.
    pub base: Word,
    /// Exponent `b` for the exponentiation.
    pub exponent: Word,
    /// Exponentiation result.
    pub exponentiation: Word,
    /// Intermediate multiplication results.
    pub steps: Vec<ExpStep>,
}

impl Default for ExpEvent {
    fn default() -> Self {
        Self {
            identifier: 0,
            base: 2.into(),
            exponent: 2.into(),
            exponentiation: 4.into(),
            steps: vec![ExpStep {
                a: 2.into(),
                b: 2.into(),
                d: 4.into(),
            }],
        }
    }
}

/// I/Os from all precompiled contract calls in a block.
#[derive(Clone, Debug, Default)]
pub struct PrecompileEvents {
    /// All events.
    pub events: Vec<PrecompileEvent>,
}

impl PrecompileEvents {
    /// Get all ecrecover events.
    pub fn get_ecrecover_events(&self) -> Vec<SignData> {
        self.events
            .iter()
            .filter_map(|e| {
                if let PrecompileEvent::Ecrecover(sign_data) = e {
                    Some(sign_data)
                } else {
                    None
                }
            })
            .cloned()
            .collect()
    }
    /// Get all EcAdd events.
    pub fn get_ec_add_events(&self) -> Vec<EcAddOp> {
        self.events
            .iter()
            .filter_map(|e| {
                if let PrecompileEvent::EcAdd(op) = e {
                    Some(op)
                } else {
                    None
                }
            })
            .cloned()
            .collect()
    }
    /// Get all EcMul events.
    pub fn get_ec_mul_events(&self) -> Vec<EcMulOp> {
        self.events
            .iter()
            .filter_map(|e| {
                if let PrecompileEvent::EcMul(op) = e {
                    Some(op)
                } else {
                    None
                }
            })
            .cloned()
            .collect()
    }
    /// Get all EcPairing events.
    pub fn get_ec_pairing_events(&self) -> Vec<EcPairingOp> {
        self.events
            .iter()
            .cloned()
            .filter_map(|e| {
                if let PrecompileEvent::EcPairing(op) = e {
                    Some(*op)
                } else {
                    None
                }
            })
            .collect()
    }
    /// Get all Big Modexp events.
    pub fn get_modexp_events(&self) -> Vec<BigModExp> {
        self.events
            .iter()
            .filter_map(|e| {
                if let PrecompileEvent::ModExp(op) = e {
                    Some(op)
                } else {
                    None
                }
            })
            .cloned()
            .collect()
    }
}

/// I/O from a precompiled contract call.
#[derive(Clone, Debug)]
pub enum PrecompileEvent {
    /// Represents the I/O from Ecrecover call.
    Ecrecover(SignData),
    /// Represents the I/O from EcAdd call.
    EcAdd(EcAddOp),
    /// Represents the I/O from EcMul call.
    EcMul(EcMulOp),
    /// Represents the I/O from EcPairing call.
    EcPairing(Box<EcPairingOp>),
    /// Represents the I/O from Modexp call.
    ModExp(BigModExp),
}

impl Default for PrecompileEvent {
    fn default() -> Self {
        Self::Ecrecover(SignData::default())
    }
}

/// EcAdd operation: P + Q = R
#[derive(Clone, Debug)]
pub struct EcAddOp {
    /// First EC point.
    pub p: G1Affine,
    /// Second EC point.
    pub q: G1Affine,
    /// Addition of the first and second EC points.
    pub r: G1Affine,
}

impl Default for EcAddOp {
    fn default() -> Self {
        let p = G1Affine::generator();
        let q = G1Affine::generator();
        let r = p.add(q).into();
        Self { p, q, r }
    }
}

impl EcAddOp {
    /// Creates a new EcAdd op given the inputs and output.
    pub fn new(p: G1Affine, q: G1Affine, r: G1Affine) -> Self {
        assert_eq!(p.add(q), r.into());
        Self { p, q, r }
    }

    /// Creates a new EcAdd op given input and output bytes from a precompile call.
    ///
    /// Note: At the moment we are handling invalid/erroneous cases for precompiled contract calls
    /// via a dummy gadget ErrorPrecompileFailure. So we expect the input bytes to be valid, i.e.
    /// points P and Q are valid points on the curve. In the near future, we should ideally handle
    /// invalid inputs within the respective precompile call's gadget. And then this function will
    /// be fallible, since we would handle invalid inputs as well.
    pub fn new_from_bytes(input: &[u8], output: &[u8]) -> Self {
        let fq_from_slice = |buf: &mut [u8; 32], bytes: &[u8]| -> CtOption<Fq> {
            buf.copy_from_slice(bytes);
            buf.reverse();
            Fq::from_bytes(buf)
        };

        let g1_from_slice = |buf: &mut [u8; 32], bytes: &[u8]| -> CtOption<G1Affine> {
            fq_from_slice(buf, &bytes[0x00..0x20]).and_then(|x| {
                fq_from_slice(buf, &bytes[0x20..0x40]).and_then(|y| G1Affine::from_xy(x, y))
            })
        };

        assert_eq!(input.len(), 128);
        assert_eq!(output.len(), 64);

        let mut buf = [0u8; 32];
        let point_p = g1_from_slice(&mut buf, &input[0x00..0x40]).unwrap();
        let point_q = g1_from_slice(&mut buf, &input[0x40..0x80]).unwrap();
        let point_r_got = g1_from_slice(&mut buf, &output[0x00..0x40]).unwrap();
        assert_eq!(G1Affine::from(point_p.add(&point_q)), point_r_got);
        Self {
            p: point_p,
            q: point_q,
            r: point_r_got,
        }
    }

    /// A check on the op to tell the ECC Circuit whether or not to skip the op.
    pub fn skip_by_ecc_circuit(&self) -> bool {
        false
    }
}

/// EcMul operation: s.P = R
#[derive(Clone, Debug)]
pub struct EcMulOp {
    /// EC point.
    pub p: G1Affine,
    /// Scalar.
    pub s: Fr,
    /// Result for s.P = R.
    pub r: G1Affine,
}

impl Default for EcMulOp {
    fn default() -> Self {
        let p = G1Affine::generator();
        let s = Fr::one();
        let r = p.mul(s).into();
        Self { p, s, r }
    }
}

impl EcMulOp {
    /// Creates a new EcMul op given the inputs and output.
    pub fn new(p: G1Affine, s: Fr, r: G1Affine) -> Self {
        assert_eq!(p.mul(s), r.into());
        Self { p, s, r }
    }

    /// Creates a new EcMul op given input and output bytes from a precompile call.    
    pub fn new_from_bytes(input: &[u8], output: &[u8]) -> Self {
        let copy_bytes = |buf: &mut [u8; 32], bytes: &[u8]| {
            buf.copy_from_slice(bytes);
            buf.reverse();
        };

        assert_eq!(input.len(), 96);
        assert_eq!(output.len(), 64);

        let mut buf = [0u8; 32];

        let p: G1Affine = {
            copy_bytes(&mut buf, &input[0x00..0x20]);
            Fq::from_bytes(&buf).and_then(|x| {
                copy_bytes(&mut buf, &input[0x20..0x40]);
                Fq::from_bytes(&buf).and_then(|y| G1Affine::from_xy(x, y))
            })
        }
        .unwrap();

        let s = Fr::from_raw(Word::from_big_endian(&input[0x40..0x60]).0);

        let r_specified: G1Affine = {
            copy_bytes(&mut buf, &output[0x00..0x20]);
            Fq::from_bytes(&buf).and_then(|x| {
                copy_bytes(&mut buf, &output[0x20..0x40]);
                Fq::from_bytes(&buf).and_then(|y| G1Affine::from_xy(x, y))
            })
        }
        .unwrap();

        assert_eq!(G1Affine::from(p.mul(s)), r_specified);

        Self {
            p,
            s,
            r: r_specified,
        }
    }

    /// A check on the op to tell the ECC Circuit whether or not to skip the op.
    pub fn skip_by_ecc_circuit(&self) -> bool {
        self.p.is_identity().into() || self.s.is_zero().into()
    }
}

/// The number of pairing inputs per pairing operation. If the inputs provided to the precompile
/// call are < 4, we append (G1::infinity, G2::generator) until we have the required no. of inputs.
pub const N_PAIRING_PER_OP: usize = 4;

/// The number of bytes taken to represent a pair (G1, G2).
pub const N_BYTES_PER_PAIR: usize = 192;

/// Pair of (G1, G2).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EcPairingPair {
    /// G1 point.
    pub g1_point: G1Affine,
    /// G2 point.
    pub g2_point: G2Affine,
}

impl EcPairingPair {
    /// Returns the big-endian representation of the G1 point in the pair.
    pub fn g1_bytes_be(&self) -> Vec<u8> {
        std::iter::empty()
            .chain(self.g1_point.x.to_bytes().iter().rev())
            .chain(self.g1_point.y.to_bytes().iter().rev())
            .cloned()
            .collect()
    }

    /// Returns the big-endian representation of the G2 point in the pair.
    pub fn g2_bytes_be(&self) -> Vec<u8> {
        std::iter::empty()
            .chain(self.g2_point.x.c1.to_bytes().iter().rev())
            .chain(self.g2_point.x.c0.to_bytes().iter().rev())
            .chain(self.g2_point.y.c1.to_bytes().iter().rev())
            .chain(self.g2_point.y.c0.to_bytes().iter().rev())
            .cloned()
            .collect()
    }

    /// Returns the uncompressed big-endian byte representation of the (G1, G2) pair.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        std::iter::empty()
            .chain(self.g1_point.x.to_bytes().iter().rev())
            .chain(self.g1_point.y.to_bytes().iter().rev())
            .chain(self.g2_point.x.c1.to_bytes().iter().rev())
            .chain(self.g2_point.x.c0.to_bytes().iter().rev())
            .chain(self.g2_point.y.c1.to_bytes().iter().rev())
            .chain(self.g2_point.y.c0.to_bytes().iter().rev())
            .cloned()
            .collect()
    }

    /// Create a new pair.
    pub fn new(g1_point: G1Affine, g2_point: G2Affine) -> Self {
        Self { g1_point, g2_point }
    }

    /// Padding pair for ECC circuit. The pairing check is done with a constant number
    /// `N_PAIRING_PER_OP` of (G1, G2) pairs. The ECC circuit under the hood uses halo2-lib to
    /// compute the multi-miller loop, which allows `(G1::Infinity, G2::Generator)` pair to skip
    /// the loop for that pair. So in case the EVM inputs are less than `N_PAIRING_PER_OP` we pad
    /// the ECC Circuit inputs by this pair. Any EVM input of `(G1::Infinity, G2)` or
    /// `(G1, G2::Infinity)` is also transformed into `(G1::Infinity, G2::Generator)`.
    pub fn ecc_padding() -> Self {
        Self {
            g1_point: G1Affine::identity(),
            g2_point: G2Affine::generator(),
        }
    }

    /// Padding pair for EVM circuit. The pairing check is done with a constant number
    /// `N_PAIRING_PER_OP` of (G1, G2) pairs. In case EVM inputs are less in number, we pad them
    /// with `(G1::Infinity, G2::Infinity)` for simplicity.
    pub fn evm_padding() -> Self {
        Self {
            g1_point: G1Affine::identity(),
            g2_point: G2Affine::identity(),
        }
    }
}

/// EcPairing operation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcPairingOp {
    /// tuples of G1 and G2 points supplied to the ECC circuit.
    pub pairs: [EcPairingPair; N_PAIRING_PER_OP],
    /// Result from the pairing check.
    pub output: Word,
}

impl Default for EcPairingOp {
    fn default() -> Self {
        let g1_point = G1Affine::generator();
        let g2_point = G2Affine::generator();
        Self {
            pairs: [
                EcPairingPair { g1_point, g2_point },
                EcPairingPair { g1_point, g2_point },
                EcPairingPair { g1_point, g2_point },
                EcPairingPair { g1_point, g2_point },
            ],
            output: Word::zero(),
        }
    }
}

impl EcPairingOp {
    /// Returns the uncompressed big-endian byte representation of inputs to the EcPairingOp.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.pairs
            .iter()
            .flat_map(|pair| pair.to_bytes_be())
            .collect::<Vec<u8>>()
    }

    /// A check on the op to tell the ECC Circuit whether or not to skip the op.
    pub fn skip_by_ecc_circuit(&self) -> bool {
        false
    }
}

/// Event representating an exponentiation `a ^ b == d (mod m)` in precompile modexp.
#[derive(Clone, Debug)]
pub struct BigModExp {
    /// Base `a` for the exponentiation.
    pub base: Word,
    /// Exponent `b` for the exponentiation.
    pub exponent: Word,
    /// Modulus `m`
    pub modulus: Word,
    /// Mod exponentiation result.
    pub result: Word,
}

impl Default for BigModExp {
    fn default() -> Self {
        Self {
            modulus: 1.into(),
            base: Default::default(),
            exponent: Default::default(),
            result: Default::default(),
        }
    }
}
