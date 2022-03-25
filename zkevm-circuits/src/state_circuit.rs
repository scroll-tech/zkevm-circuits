//! The state circuit implementation.

// TODO: clean up module structure.
pub(super) mod constraint_builder;
pub(super) mod fixed_table;
pub(super) mod param;

pub(crate) mod state;
pub use state::StateCircuit;
