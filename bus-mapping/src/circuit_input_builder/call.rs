use super::CodeSource;
use crate::{exec_trace::OperationRef, Error};
use eth_types::evm_types::Memory;
use eth_types::{evm_types::OpcodeId, Address, Hash, Word};

/// Type of a *CALL*/CREATE* Function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallKind {
    /// CALL
    Call,
    /// CALLCODE
    CallCode,
    /// DELEGATECALL
    DelegateCall,
    /// STATICCALL
    StaticCall,
    /// CREATE
    Create,
    /// CREATE2
    Create2,
}

impl CallKind {
    fn is_create(&self) -> bool {
        matches!(self, Self::Create | Self::Create2)
    }
}

impl Default for CallKind {
    fn default() -> Self {
        Self::Call
    }
}

impl TryFrom<OpcodeId> for CallKind {
    type Error = Error;

    fn try_from(op: OpcodeId) -> Result<Self, Self::Error> {
        Ok(match op {
            OpcodeId::CALL => CallKind::Call,
            OpcodeId::CALLCODE => CallKind::CallCode,
            OpcodeId::DELEGATECALL => CallKind::DelegateCall,
            OpcodeId::STATICCALL => CallKind::StaticCall,
            OpcodeId::CREATE => CallKind::Create,
            OpcodeId::CREATE2 => CallKind::Create2,
            _ => return Err(Error::OpcodeIdNotCallType),
        })
    }
}

/// Circuit Input related to an Ethereum Call
#[derive(Clone, Debug, Default)]
pub struct Call {
    /// Unique call identifier within the Block.
    pub call_id: usize,
    /// Caller's id.
    pub caller_id: usize,
    /// Last Callee's id.
    pub last_callee_id: usize,
    /// Type of call
    pub kind: CallKind,
    /// This call is being executed without write access (STATIC)
    pub is_static: bool,
    /// This call generated implicity by a Transaction.
    pub is_root: bool,
    /// This call is persistent or call stack reverts at some point
    pub is_persistent: bool,
    /// This call ends successfully or not
    pub is_success: bool,
    /// This rw_counter at the end of reversion
    pub rw_counter_end_of_reversion: usize,
    /// Address of caller
    pub caller_address: Address,
    /// Address where this call is being executed
    pub address: Address,
    /// Code Source
    pub code_source: CodeSource,
    /// Code Hash
    pub code_hash: Hash,
    /// Depth
    pub depth: usize,
    /// Value
    pub value: Word,
    /// Call data offset
    pub call_data_offset: u64,
    /// Call data length
    pub call_data_length: u64,
    /// Return data offset
    pub return_data_offset: u64,
    /// Return data length
    pub return_data_length: u64,
    /// last callee's return data offset
    pub last_callee_return_data_offset: u64,
    /// last callee's return data length
    pub last_callee_return_data_length: u64,
}

impl Call {
    /// This call is root call with tx.to == null, or op == CREATE or op ==
    /// CREATE2
    pub fn is_create(&self) -> bool {
        self.kind.is_create()
    }

    /// ..
    pub fn is_success(&self) -> bool {
        self.is_success
    }

    /// This call is call with op DELEGATECALL
    pub fn is_delegatecall(&self) -> bool {
        matches!(self.kind, CallKind::DelegateCall)
    }
    /// Get the code address if possible
    pub fn code_address(&self) -> Option<Address> {
        match self.kind {
            CallKind::Call | CallKind::StaticCall => Some(self.address),
            CallKind::CallCode | CallKind::DelegateCall => match self.code_source {
                CodeSource::Address(address) => Some(address),
                _ => None,
            },
            CallKind::Create | CallKind::Create2 => None,
        }
    }
}

/// Context of a [`Call`].
#[derive(Debug, Default)]
pub struct CallContext {
    /// Index of call
    pub index: usize,
    /// Reversible Write Counter tracks the number of write operations in the
    /// call. It is incremented when a subcall in this call succeeds by the
    /// number of successful writes in the subcall.
    pub reversible_write_counter: usize,
    /// Call data (copy of tx input or caller's
    /// memory[call_data_offset..call_data_offset + call_data_length])
    pub call_data: Vec<u8>,
    /// memory context of current call
    pub memory: Memory,
    /// return data buffer
    pub return_data: Vec<u8>,
}

impl CallContext {
    /// Memory size in words, rounded up
    pub fn memory_word_size(&self) -> u64 {
        u64::try_from(self.memory.len()).expect("failed to convert usize to u64") / 32
    }
}

/// A reversion group is the collection of calls and the operations which are
/// [`Operation::reversible`](crate::operation::Operation::reversible) that
/// happened in them, that will be reverted at once when the call that initiated
/// this reversion group eventually ends with failure (and thus reverts).
#[derive(Debug, Default)]
pub struct ReversionGroup {
    /// List of `index` and `reversible_write_counter_offset` of calls belong to
    /// this group. `reversible_write_counter_offset` is the number of
    /// reversible operations that have happened before the call within the
    /// same reversion group.
    pub(crate) calls: Vec<(usize, usize)>,
    /// List of `step_index` and [`OperationRef`] that have been done in this
    /// group.
    pub(crate) op_refs: Vec<(usize, OperationRef)>,
}

impl ReversionGroup {
    /// Creates a new `ReversionGroup` instance from the calls and operation
    /// references lists.
    pub fn new(calls: Vec<(usize, usize)>, op_refs: Vec<(usize, OperationRef)>) -> Self {
        Self { calls, op_refs }
    }
}
