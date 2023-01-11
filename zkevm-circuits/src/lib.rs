//! # zk_evm

// We should try not to use incomplete_features unless it is really really needed and cannot be
// avoided like `adt_const_params` used by DummyGadget
#![allow(incomplete_features)]
// Needed by DummyGadget in evm circuit
#![feature(adt_const_params)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
// We want to have UPPERCASE idents sometimes.
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::result_large_err)] // it's large, but what can we do?
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::debug_assert_with_mut_call)]

pub mod bytecode_circuit;
pub mod copy_circuit;
pub mod evm_circuit;
pub mod exp_circuit;
pub mod keccak_circuit;
pub mod pi_circuit;
pub mod rlp_circuit;
pub mod state_circuit;
pub mod super_circuit;
pub mod table;

#[cfg(any(feature = "test", test))]
pub mod test_util;

pub mod tx_circuit;
pub mod util;
pub mod witness;

pub use gadgets::impl_expr;
