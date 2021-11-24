//! Collection of structs and functions used to:
//! - Define the internals of a [`MemoryOp`], [`StackOp`] and [`StorageOp`].
//! - Define the actual operation types and a wrapper over them (the
//!   [`Operation`] enum).
//! - Define structures that interact with operations such as
//!   [`OperationContainer`].
pub(crate) mod container;

pub use super::evm::{
    EthAddress, EvmWord, GlobalCounter, MemoryAddress, StackAddress,
};
pub use container::OperationContainer;
use core::cmp::Ordering;
use core::fmt::Debug;

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
        match self {
            RW::READ => true,
            RW::WRITE => false,
        }
    }

    /// Returns true if the RW corresponds internally to a [`WRITE`](RW::WRITE).
    pub const fn is_write(&self) -> bool {
        !self.is_read()
    }
}

/// Enum used to differenciate between EVM Stack, Memory and Storage operations.
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum Target {
    /// Means the target of the operation is the Memory.
    Memory,
    /// Means the target of the operation is the Stack.
    Stack,
    /// Means the target of the operation is the Storage.
    Storage,
}

/// Trait used for Operation Kinds.
pub trait Op: Eq + Ord {
    /// Turn the Generic Op into an OpEnum so that we can match it into a particular Operation
    /// Kind.
    fn into_enum(self) -> OpEnum;
}

/// Represents a [`READ`](RW::READ)/[`WRITE`](RW::WRITE) into the memory implied
/// by an specific [`OpcodeId`](crate::evm::opcodes::ids::OpcodeId) of the
/// [`ExecutionTrace`](crate::exec_trace::ExecutionTrace).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryOp {
    rw: RW,
    addr: MemoryAddress,
    value: u8,
}

impl MemoryOp {
    /// Create a new instance of a `MemoryOp` from it's components.
    pub fn new(rw: RW, addr: MemoryAddress, value: u8) -> MemoryOp {
        MemoryOp { rw, addr, value }
    }

    /// Returns the internal [`RW`] which says whether the operation corresponds
    /// to a Read or a Write into memory.
    pub const fn rw(&self) -> RW {
        self.rw
    }

    /// Returns the [`Target`] (operation type) of this operation.
    pub const fn target(&self) -> Target {
        Target::Memory
    }

    /// Returns the [`MemoryAddress`] associated to this Operation.
    pub const fn address(&self) -> &MemoryAddress {
        &self.addr
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
}

impl PartialOrd for MemoryOp {
    fn partial_cmp(&self, other: &MemoryOp) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemoryOp {
    fn cmp(&self, other: &MemoryOp) -> Ordering {
        self.address().cmp(other.address())
    }
}

/// Represents a [`READ`](RW::READ)/[`WRITE`](RW::WRITE) into the stack implied
/// by an specific [`OpcodeId`](crate::evm::opcodes::ids::OpcodeId) of the
/// [`ExecutionTrace`](crate::exec_trace::ExecutionTrace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackOp {
    rw: RW,
    addr: StackAddress,
    value: EvmWord,
}

impl StackOp {
    /// Create a new instance of a `MemoryOp` from it's components.
    pub const fn new(rw: RW, addr: StackAddress, value: EvmWord) -> StackOp {
        StackOp { rw, addr, value }
    }

    /// Returns the internal [`RW`] which says whether the operation corresponds
    /// to a Read or a Write into memory.
    pub const fn rw(&self) -> RW {
        self.rw
    }

    /// Returns the [`Target`] (operation type) of this operation.
    pub const fn target(&self) -> Target {
        Target::Stack
    }

    /// Returns the [`StackAddress`] associated to this Operation.
    pub const fn address(&self) -> &StackAddress {
        &self.addr
    }

    /// Returns the [`EvmWord`] read or written by this operation.
    pub const fn value(&self) -> &EvmWord {
        &self.value
    }
}

impl Op for StackOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::Stack(self)
    }
}

impl PartialOrd for StackOp {
    fn partial_cmp(&self, other: &StackOp) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StackOp {
    fn cmp(&self, other: &StackOp) -> Ordering {
        self.address().cmp(other.address())
    }
}

/// Represents a [`READ`](RW::READ)/[`WRITE`](RW::WRITE) into the storage
/// implied by an specific [`OpcodeId`](crate::evm::opcodes::ids::OpcodeId) of
/// the [`ExecutionTrace`](crate::exec_trace::ExecutionTrace).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageOp {
    rw: RW,
    address: EthAddress,
    key: EvmWord,
    value: EvmWord,
    value_prev: EvmWord,
}

impl StorageOp {
    /// Create a new instance of a `StorageOp` from it's components.
    pub const fn new(
        rw: RW,
        address: EthAddress,
        key: EvmWord,
        value: EvmWord,
        value_prev: EvmWord,
    ) -> StorageOp {
        StorageOp {
            rw,
            address,
            key,
            value,
            value_prev,
        }
    }

    /// Returns the internal [`RW`] which says whether the operation corresponds
    /// to a Read or a Write into storage.
    pub const fn rw(&self) -> RW {
        self.rw
    }

    /// Returns the [`Target`] (operation type) of this operation.
    pub const fn target(&self) -> Target {
        Target::Storage
    }

    /// Returns the [`EthAddress`] corresponding to this storage operation.
    pub const fn address(&self) -> &EthAddress {
        &self.address
    }

    /// Returns the [`EvmWord`] used as key for this operation.
    pub const fn key(&self) -> &EvmWord {
        &self.key
    }

    /// Returns the [`EvmWord`] read or written by this operation.
    pub const fn value(&self) -> &EvmWord {
        &self.value
    }

    /// Returns the [`EvmWord`] at key found previous to this operation.
    pub const fn value_prev(&self) -> &EvmWord {
        &self.value_prev
    }
}

impl Op for StorageOp {
    fn into_enum(self) -> OpEnum {
        OpEnum::Storage(self)
    }
}

impl PartialOrd for StorageOp {
    fn partial_cmp(&self, other: &StorageOp) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StorageOp {
    fn cmp(&self, other: &StorageOp) -> Ordering {
        match self.address().cmp(other.address()) {
            Ordering::Equal => self.key().cmp(other.key()),
            ord => ord,
        }
    }
}

/// Generic enum that wraps over all the operation types possible.
/// In particular [`StackOp`], [`MemoryOp`] and [`StorageOp`].
#[derive(Debug, Clone)]
pub enum OpEnum {
    /// Doc
    Stack(StackOp),
    /// Doc
    Memory(MemoryOp),
    /// Doc
    Storage(StorageOp),
}

/// Operation is a Wrapper over a type that implements Op with a GlobalCounter.
#[derive(Debug, Clone)]
pub struct Operation<T: Op> {
    gc: GlobalCounter,
    op: T,
}

impl<T: Op> PartialEq for Operation<T> {
    fn eq(&self, other: &Operation<T>) -> bool {
        self.op.eq(&other.op) && self.gc == other.gc
    }
}

impl<T: Op> Eq for Operation<T> {}

impl<T: Op> PartialOrd for Operation<T> {
    fn partial_cmp(&self, other: &Operation<T>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Op> Ord for Operation<T> {
    fn cmp(&self, other: &Operation<T>) -> Ordering {
        match self.op.cmp(&other.op) {
            Ordering::Equal => self.gc.cmp(&other.gc),
            ord => ord,
        }
    }
}

impl<T: Op> Operation<T> {
    /// Create a new Operation from an `op` with a `gc`
    pub fn new(gc: GlobalCounter, op: T) -> Self {
        Self { gc, op }
    }

    /// Return this `Operation` `gc`
    pub fn gc(&self) -> GlobalCounter {
        self.gc
    }

    /// Return this `Operation` `op`
    pub fn op(&self) -> &T {
        &self.op
    }

    // /// Matches over an `Operation` returning the [`Target`] of the iternal op
    // /// it stores inside.
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
        let stack_op = StackOp::new(
            RW::WRITE,
            StackAddress::from(1024),
            EvmWord::from(0x40u8),
        );

        let stack_op_as_operation =
            Operation::new(GlobalCounter(1usize), stack_op.clone());

        let memory_op = MemoryOp::new(
            RW::WRITE,
            MemoryAddress(usize::from(0x40u8)),
            0x40u8,
        );

        let memory_op_as_operation =
            Operation::new(GlobalCounter(1usize), memory_op.clone());

        assert_eq!(stack_op, stack_op_as_operation.op);
        assert_eq!(memory_op, memory_op_as_operation.op)
    }
}
