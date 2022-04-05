//! # zk_evm

#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
// We want to have UPPERCASE idents sometimes.
#![allow(clippy::upper_case_acronyms)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::debug_assert_with_mut_call)]

pub mod bytecode_circuit;
pub mod evm_circuit;
pub mod gadget;
pub mod rw_table;
pub mod state_circuit;
#[cfg(test)]
pub mod test_util;
pub mod util;
