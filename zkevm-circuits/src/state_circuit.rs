//! The state circuit implementation.

// TODO: clean up module structure.
pub(super) mod cells;

pub(super) mod constraint_builder;
pub(super) mod fixed_table;
pub(super) mod param;

// mod account;
// mod account_destructed;
// mod account_storage;
// mod call_context;
// mod memory;
// mod tx_access_list_account;
// mod tx_access_list_storage;
// mod tx_refund;
// mod stack;

pub(crate) mod state;
pub use state::StateCircuit;
