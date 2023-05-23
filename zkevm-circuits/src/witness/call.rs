use eth_types::{Address, Word};

/// Call in transactions.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Call {
    /// The unique identifier of call in the whole proof, using the
    /// `rw_counter` at the call step.
    pub id: usize,
    /// Indicate if the call is the root call
    pub is_root: bool,
    /// Indicate if the call is a create call
    pub is_create: bool,
    /// The identifier of current executed bytecode
    pub code_hash: Word,
    /// The `rw_counter` at the end of reversion of a call if it has
    /// `is_persistent == false`
    pub rw_counter_end_of_reversion: usize,
    /// The call index of caller
    pub caller_id: usize,
    /// The depth in the call stack
    pub depth: usize,
    /// The caller address
    pub caller_address: Address,
    /// The callee address
    pub callee_address: Address,
    /// The code address. This comes handy to differentiate between different kinds of call, for
    /// instance CALL, DELEGATECALL and so on.
    pub code_address: Option<Address>,
    /// The call data offset in the memory
    pub call_data_offset: u64,
    /// The length of call data
    pub call_data_length: u64,
    /// The return data offset in the memory
    pub return_data_offset: u64,
    /// The length of return data
    pub return_data_length: u64,
    /// The ether amount of the transaction
    pub value: Word,
    /// Indicate if this call halts successfully.
    pub is_success: bool,
    /// Indicate if this call and all its caller have `is_success == true`
    pub is_persistent: bool,
    /// Indicate if it's a static call
    pub is_static: bool,
}
