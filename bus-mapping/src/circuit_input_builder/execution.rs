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
    evm_types::{Gas, GasCost, OpcodeId, ProgramCounter},
    sign_types::SignData,
    word, GethExecStep, ToLittleEndian, Word, H256,
};
use ethers_core::k256::elliptic_curve::subtle::{Choice, CtOption};
use gadgets::impl_expr;
use halo2_proofs::{
    arithmetic::CurveAffine,
    halo2curves::{
        bn256::{Fq, Fq2, Fr, G1Affine, G2Affine},
        group::cofactor::CofactorCurveAffine,
    },
    plonk::Expression,
};
use strum::IntoEnumIterator;

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
    /// When the source of the copy is a call to a precompiled contract.
    Precompile(PrecompileCalls),
}
impl CopyDataType {
    /// Get variants that represent a precompile call.
    pub fn precompile_types() -> Vec<Self> {
        PrecompileCalls::iter().map(Self::Precompile).collect()
    }
}
const NUM_COPY_DATA_TYPES: usize = 15usize;
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
            6usize => Some(CopyDataType::Precompile(PrecompileCalls::Ecrecover)),
            7usize => Some(CopyDataType::Precompile(PrecompileCalls::Sha256)),
            8usize => Some(CopyDataType::Precompile(PrecompileCalls::Ripemd160)),
            9usize => Some(CopyDataType::Precompile(PrecompileCalls::Identity)),
            10usize => Some(CopyDataType::Precompile(PrecompileCalls::Modexp)),
            11usize => Some(CopyDataType::Precompile(PrecompileCalls::Bn128Add)),
            12usize => Some(CopyDataType::Precompile(PrecompileCalls::Bn128Mul)),
            13usize => Some(CopyDataType::Precompile(PrecompileCalls::Bn128Pairing)),
            14usize => Some(CopyDataType::Precompile(PrecompileCalls::Blake2F)),
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
            CopyDataType::Precompile(prec_call) => 5 + usize::from(prec_call),
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
            CopyDataType::Precompile(prec_call) => 5 + u64::from(*prec_call),
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

/// Defines a copy event associated with EVM opcodes such as CALLDATACOPY,
/// CODECOPY, CREATE, etc. More information:
/// <https://github.com/privacy-scaling-explorations/zkevm-specs/blob/master/specs/copy-proof.md>.
#[derive(Clone, Debug)]
pub struct CopyEvent {
    /// Represents the start address at the source of the copy event.
    pub src_addr: u64,
    /// Represents the end address at the source of the copy event.
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
    /// Represents the list of (bytes, is_code) copied during this copy event
    pub bytes: Vec<(u8, bool)>,
}

impl CopyEvent {
    /// rw counter at step index
    pub fn rw_counter(&self, step_index: usize) -> u64 {
        u64::try_from(self.rw_counter_start.0).unwrap() + self.rw_counter_increase(step_index)
    }

    /// rw counter increase left at step index
    pub fn rw_counter_increase_left(&self, step_index: usize) -> u64 {
        self.rw_counter(self.bytes.len() * 2) - self.rw_counter(step_index)
    }

    /// Number of rw operations performed by this copy event
    pub fn rw_counter_delta(&self) -> u64 {
        self.rw_counter_increase(self.bytes.len() * 2)
    }

    // increase in rw counter from the start of the copy event to step index
    fn rw_counter_increase(&self, step_index: usize) -> u64 {
        let source_rw_increase = match self.src_type {
            CopyDataType::Bytecode | CopyDataType::TxCalldata | CopyDataType::Precompile(_) => 0,
            CopyDataType::Memory => std::cmp::min(
                u64::try_from(step_index + 1).unwrap() / 2,
                self.src_addr_end
                    .checked_sub(self.src_addr)
                    .unwrap_or_default(),
            ),
            CopyDataType::RlcAcc | CopyDataType::TxLog | CopyDataType::Padding => unreachable!(),
        };
        let destination_rw_increase = match self.dst_type {
            CopyDataType::RlcAcc | CopyDataType::Bytecode | CopyDataType::Precompile(_) => 0,
            CopyDataType::TxLog | CopyDataType::Memory => u64::try_from(step_index).unwrap() / 2,
            CopyDataType::TxCalldata | CopyDataType::Padding => {
                unreachable!()
            }
        };
        source_rw_increase + destination_rw_increase
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
    pub fn new_from_bytes(input: &[u8], output: &[u8]) -> CtOption<Self> {
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

        let mut buf = [0u8; 32];
        g1_from_slice(&mut buf, &input[0x00..0x40]).and_then(|point_p| {
            g1_from_slice(&mut buf, &input[0x40..0x80]).and_then(|point_q| {
                // valid input implies valid output. If the result matches, the computation was
                // successful.
                let point_r_got = g1_from_slice(&mut buf, output).unwrap();
                let point_r: G1Affine = point_p.add(&point_q).into();
                if point_r.eq(&point_r_got) {
                    CtOption::new(
                        Self {
                            p: point_p,
                            q: point_q,
                            r: point_r,
                        },
                        Choice::from(1u8),
                    )
                } else {
                    CtOption::new(Self::default(), Choice::from(0u8))
                }
            })
        })
    }

    /// Returns true if the input points P and Q are the same.
    pub fn inputs_equal(&self) -> bool {
        self.p.eq(&self.q)
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
        let s = Fr::from_raw([2, 0, 0, 0]);
        let r = p.mul(s).into();
        Self { p, s, r }
    }
}

/// The number of pairing inputs per pairing operation. If the inputs provided to the precompile
/// call are < 4, we append (G1::infinity, G2::Infinity) until we have the required number of
/// inputs.
pub const N_PAIRING_PER_OP: usize = 4;

/// EcPairing operation
#[derive(Clone, Debug)]
pub struct EcPairingOp {
    /// tuples of G1 and G2 points.
    pub inputs: [(G1Affine, G2Affine); N_PAIRING_PER_OP],
    /// Result from the pairing check.
    pub output: Word,
}

impl Default for EcPairingOp {
    fn default() -> Self {
        // example from https://evm.codes/precompiled
        const G1_X_1: &str = "0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da";
        const G1_Y_1: &str = "0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6";
        const G2_X_11: &str = "0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc";
        const G2_X_12: &str = "0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9";
        const G2_Y_11: &str = "0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90";
        const G2_Y_12: &str = "0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e";
        const G1_X_2: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";
        const G1_Y_2: &str = "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45";
        const G2_X_21: &str = "0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4";
        const G2_X_22: &str = "0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7";
        const G2_Y_21: &str = "0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2";
        const G2_Y_22: &str = "0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc";
        Self {
            inputs: [
                (
                    G1Affine {
                        x: Fq::from_bytes(&word!(G1_X_1).to_le_bytes()).unwrap(),
                        y: Fq::from_bytes(&word!(G1_Y_1).to_le_bytes()).unwrap(),
                    },
                    G2Affine {
                        x: Fq2 {
                            c1: Fq::from_bytes(&word!(G2_X_11).to_le_bytes()).unwrap(),
                            c0: Fq::from_bytes(&word!(G2_X_12).to_le_bytes()).unwrap(),
                        },
                        y: Fq2 {
                            c1: Fq::from_bytes(&word!(G2_Y_11).to_le_bytes()).unwrap(),
                            c0: Fq::from_bytes(&word!(G2_Y_12).to_le_bytes()).unwrap(),
                        },
                    },
                ),
                (
                    G1Affine {
                        x: Fq::from_bytes(&word!(G1_X_2).to_le_bytes()).unwrap(),
                        y: Fq::from_bytes(&word!(G1_Y_2).to_le_bytes()).unwrap(),
                    },
                    G2Affine {
                        x: Fq2 {
                            c1: Fq::from_bytes(&word!(G2_X_21).to_le_bytes()).unwrap(),
                            c0: Fq::from_bytes(&word!(G2_X_22).to_le_bytes()).unwrap(),
                        },
                        y: Fq2 {
                            c1: Fq::from_bytes(&word!(G2_Y_21).to_le_bytes()).unwrap(),
                            c0: Fq::from_bytes(&word!(G2_Y_22).to_le_bytes()).unwrap(),
                        },
                    },
                ),
                (G1Affine::identity(), G2Affine::identity()),
                (G1Affine::identity(), G2Affine::identity()),
            ],
            output: Word::one(),
        }
    }
}

impl EcPairingOp {
    /// Returns the uncompressed byte representation of inputs to the EcPairingOp.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inputs
            .iter()
            .flat_map(|i| {
                std::iter::empty()
                    .chain(i.0.x.to_bytes().iter().rev())
                    .chain(i.0.y.to_bytes().iter().rev())
                    .chain(i.1.x.c0.to_bytes().iter().rev())
                    .chain(i.1.x.c1.to_bytes().iter().rev())
                    .chain(i.1.y.c0.to_bytes().iter().rev())
                    .chain(i.1.y.c1.to_bytes().iter().rev())
                    .cloned()
                    .collect::<Vec<u8>>()
            })
            .collect::<Vec<u8>>()
    }
}
