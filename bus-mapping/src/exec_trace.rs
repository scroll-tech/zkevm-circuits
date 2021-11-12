//! This module contains the logic for parsing and interacting with EVM
//! execution traces.
pub(crate) mod exec_step;
pub(crate) mod parsing;
use crate::evm::EvmWord;
use crate::operation::{
    container::OperationContainer, GlobalCounter, Op, Operation,
};
use crate::operation::{EthAddress, MemoryOp, StackOp, StorageOp, Target};
use crate::util::serialize_field_ext;
use crate::Error;
use core::ops::{Index, IndexMut};
pub use exec_step::ExecutionStep;
pub(crate) use parsing::ParsedExecutionStep;
use pasta_curves::arithmetic::FieldExt;
use serde::Serialize;
use std::convert::TryFrom;
use std::str::FromStr;

/// Definition of all of the constants related to an Ethereum block and
/// therefore, related with an [`ExecutionTrace`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BlockConstants<F: FieldExt> {
    hash: EvmWord, // Until we know how to deal with it
    coinbase: EthAddress,
    #[serde(serialize_with = "serialize_field_ext")]
    timestamp: F,
    #[serde(serialize_with = "serialize_field_ext")]
    number: F,
    #[serde(serialize_with = "serialize_field_ext")]
    difficulty: F,
    #[serde(serialize_with = "serialize_field_ext")]
    gas_limit: F,
    #[serde(serialize_with = "serialize_field_ext")]
    chain_id: F,
    #[serde(serialize_with = "serialize_field_ext")]
    base_fee: F,
}

impl<F: FieldExt> Default for BlockConstants<F> {
    fn default() -> Self {
        BlockConstants {
            hash: EvmWord([0u8; 32]),
            coinbase: EthAddress::from_str(
                "0x00000000000000000000000000000000c014ba5e",
            )
            .unwrap(),
            timestamp: F::from_u64(1633398551u64),
            number: F::from_u64(123456u64),
            difficulty: F::from_u64(0x200000u64),
            gas_limit: F::from_u64(15_000_000u64),
            chain_id: F::one(),
            base_fee: F::from_u64(97u64),
        }
    }
}

impl<F: FieldExt> BlockConstants<F> {
    #[allow(clippy::too_many_arguments)]
    /// Generates a new `BlockConstants` instance from it's fields.
    pub fn new(
        hash: EvmWord,
        coinbase: EthAddress,
        timestamp: F,
        number: F,
        difficulty: F,
        gas_limit: F,
        chain_id: F,
        base_fee: F,
    ) -> BlockConstants<F> {
        BlockConstants {
            hash,
            coinbase,
            timestamp,
            number,
            difficulty,
            gas_limit,
            chain_id,
            base_fee,
        }
    }
    #[inline]
    /// Return the hash of a block.
    pub fn hash(&self) -> &EvmWord {
        &self.hash
    }

    #[inline]
    /// Return the coinbase of a block.
    pub fn coinbase(&self) -> &EthAddress {
        &self.coinbase
    }

    #[inline]
    /// Return the timestamp of a block.
    pub fn timestamp(&self) -> &F {
        &self.timestamp
    }

    #[inline]
    /// Return the block number.
    pub fn number(&self) -> &F {
        &self.number
    }

    #[inline]
    /// Return the difficulty of a block.
    pub fn difficulty(&self) -> &F {
        &self.difficulty
    }

    #[inline]
    /// Return the gas_limit of a block.
    pub fn gas_limit(&self) -> &F {
        &self.gas_limit
    }

    #[inline]
    /// Return the chain ID associated to a block.
    pub fn chain_id(&self) -> &F {
        &self.chain_id
    }

    #[inline]
    /// Return the base fee of a block.
    pub fn base_fee(&self) -> &F {
        &self.base_fee
    }
}

/// Context of a trace, which mutates at every ExecutionStep and provides both a context of
/// execution and an accumulation of operations we need to generate the witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    /// The next gc to be used
    pub gc: GlobalCounter,
    /// Container of Operations
    pub container: OperationContainer,
    // TODO: Add CallContext here
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceContext {
    /// Create a new empty TraceContext
    pub fn new() -> Self {
        Self {
            gc: GlobalCounter::new(),
            container: OperationContainer::new(),
        }
    }

    /// Push an [`Operation`] into the [`OperationContainer`] with the next [`GlobalCounter`] and
    /// then adds a reference to the stored operation ([`OperationRef`]) inside the bus-mapping
    /// instance of the given [`ExecutionStep`].  Then increase the internal [`GlobalCounter`] by
    /// one.
    pub fn push_op<T: Op>(&mut self, exec_step: &mut ExecutionStep, op: T) {
        exec_step
            .bus_mapping_instance_mut()
            .push(self.container.insert(Operation::new(self.gc.inc_pre(), op)));
    }
}

/// Result of the parsing of an EVM execution trace.
/// This structure is the centre of the crate and is intended to be the only
/// entry point to it. The `ExecutionTrace` provides three main actions:
///
/// 1. Generate an `ExecutionTrace` instance by parsing an EVM trace (JSON
/// format for now).
///
/// 2. Generate and provide an iterator over all of the
/// [`ExecutionStep`]s giving an easy way to witness all of the data of each
/// step when building the Circuits for the EVM Proof.
///
/// 3. Generate and provide an ordered list of all of the
/// [`StackOp`]s,
/// [`MemoryOp`]s and
/// [`StorageOp`](crate::operation::StorageOp)s that each
/// [`OpcodeId`](crate::evm::OpcodeId)s used in each `ExecutionTrace` step so that
/// the State Proof witnesses are already generated on a structured manner and
/// ready to be added into the State circuit.
#[derive(Debug, Clone)]
pub struct ExecutionTrace<F: FieldExt> {
    pub(crate) steps: Vec<ExecutionStep>,
    pub(crate) block_ctants: BlockConstants<F>,
    pub(crate) ctx: TraceContext,
}

impl<F: FieldExt> Index<usize> for ExecutionTrace<F> {
    type Output = ExecutionStep;
    fn index(&self, index: usize) -> &Self::Output {
        &self.steps[index]
    }
}

impl<F: FieldExt> IndexMut<usize> for ExecutionTrace<F> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.steps[index]
    }
}

impl<F: FieldExt> ExecutionTrace<F> {
    /// Given an EVM trace in JSON format according to the specs and format
    /// shown in [zkevm-test-vectors crate](https://github.com/appliedzkp/zkevm-testing-vectors),
    /// generate the execution steps.
    pub fn load_trace<T: AsRef<[u8]>>(
        bytes: T,
    ) -> Result<Vec<ExecutionStep>, Error> {
        serde_json::from_slice::<Vec<ParsedExecutionStep>>(bytes.as_ref())
            .map_err(Error::SerdeError)?
            .iter()
            .map(ExecutionStep::try_from)
            .collect::<Result<Vec<ExecutionStep>, Error>>()
    }

    /// Given an EVM trace in JSON format according to the specs and format
    /// shown in [zkevm-test-vectors crate](https://github.com/appliedzkp/zkevm-testing-vectors), generate an `ExecutionTrace`
    /// and generate all of the [`Operation`]s associated to each one of it's
    /// [`ExecutionStep`]s filling them bus-mapping instances.
    pub fn from_trace_bytes<T: AsRef<[u8]>>(
        bytes: T,
        block_ctants: BlockConstants<F>,
    ) -> Result<ExecutionTrace<F>, Error> {
        let trace_loaded = Self::load_trace(bytes)?;
        ExecutionTrace::<F>::new(trace_loaded, block_ctants)
    }

    /// Given a vector of [`ExecutionStep`]s and a [`BlockConstants`] instance,
    /// generate an [`ExecutionTrace`] by:
    ///
    /// 1) Setting the correct [`GlobalCounter`](crate::evm::GlobalCounter) to
    /// each [`ExecutionStep`].
    /// 2) Generating the corresponding [`Operation`]s, registering them in the
    /// container and storing the [`OperationRef`]s to each one of the
    /// generated ops into the bus-mapping instances of each [`ExecutionStep`].
    pub(crate) fn new(
        steps: Vec<ExecutionStep>,
        block_ctants: BlockConstants<F>,
    ) -> Result<Self, Error> {
        ExecutionTrace {
            steps,
            block_ctants,
            /// Dummy empty TraceContext to enable build.
            ctx: TraceContext::new(),
        }
        .build()
    }

    /// Returns an ordered `Vec` containing all the [`StackOp`]s of the actual
    /// `ExecutionTrace` so that they can be directly included in the State
    /// proof.
    pub fn sorted_stack_ops(&self) -> Vec<Operation<StackOp>> {
        self.ctx.container.sorted_stack()
    }

    /// Returns an ordered `Vec` containing all the [`MemoryOp`]s of the actual
    /// `ExecutionTrace` so that they can be directly included in the State
    /// proof.
    pub fn sorted_memory_ops(&self) -> Vec<Operation<MemoryOp>> {
        self.ctx.container.sorted_memory()
    }

    /// Returns an ordered `Vec` containing all the [`StorageOp`]s of the actual
    /// `ExecutionTrace` so that they can be directly included in the State
    /// proof.
    pub fn sorted_storage_ops(&self) -> Vec<Operation<StorageOp>> {
        self.ctx.container.sorted_storage()
    }

    /// Traverses the trace step by step, and for each [`ExecutionStep`]:
    /// 1.  Sets the correct [`GlobalCounter`](crate::evm::GlobalCounter).
    /// 2.  Generates the corresponding [`Operation`]s  associated to the
    /// [`OpcodeId`](crate::evm::OpcodeId) executed in the step and stores them inside the
    /// [`OperationContainer`] instance stored inside of the trace.
    /// It also adds the [`OperationRef`]s obtained from the container
    /// addition into each [`ExecutionStep`] bus-mapping instances.
    fn build(mut self) -> Result<Self, Error> {
        let mut ctx = TraceContext::new();
        // XXX: We need a better achitecture to work on that without cloning..
        let cloned_steps = self.steps().clone();

        // Generate operations and update the GlobalCounter of each step.
        self.steps_mut()
            .iter_mut()
            .enumerate()
            .try_for_each::<_, Result<_, Error>>(|(idx, exec_step)| {
                // Set the exec_step global counter
                exec_step.set_gc(ctx.gc);
                // Add the `OpcodeId` associated ops and increment the gc counting
                // all of them.
                exec_step
                    .gen_associated_ops(&mut ctx, &cloned_steps[idx + 1..])?;
                Ok(())
            })?;
        // Replace the empty original container with the new one we just filled.
        self.ctx = ctx;
        Ok(self)
    }

    /// Returns a reference to the [`ExecutionStep`] vector instance
    /// that the `ExecutionTrace` holds.
    pub fn steps(&self) -> &Vec<ExecutionStep> {
        &self.steps
    }

    /// Returns a mutable reference to the [`ExecutionStep`] vector instance
    /// that the `ExecutionTrace` holds.
    fn steps_mut(&mut self) -> &mut Vec<ExecutionStep> {
        &mut self.steps
    }

    /// Returns a mutable reference to the [`OperationContainer`] instance that
    /// the `ExecutionTrace` holds.
    fn container_mut(&mut self) -> &mut OperationContainer {
        &mut self.ctx.container
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The target and index of an `Operation` in the context of an
/// `ExecutionTrace`.
pub struct OperationRef(Target, usize);

impl From<(Target, usize)> for OperationRef {
    fn from(op_ref_data: (Target, usize)) -> Self {
        match op_ref_data.0 {
            Target::Memory => Self(Target::Memory, op_ref_data.1),
            Target::Stack => Self(Target::Stack, op_ref_data.1),
            Target::Storage => Self(Target::Storage, op_ref_data.1),
            Target::Byte_code => Self(Target::Byte_code, op_ref_data.1),
            // _ => unreachable!(),
        }
    }
}

impl OperationRef {
    /// Return the `OperationRef` as a `usize`.
    pub const fn as_usize(&self) -> usize {
        self.1
    }

    /// Return the [`Target`] op type of the `OperationRef`.
    pub const fn target(&self) -> Target {
        self.0
    }
}
