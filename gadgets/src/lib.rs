//! # ZKEVM-Gadgets
//!
//! A collection of reusable gadgets for the zk_evm circuits.

#![cfg_attr(docsrs, feature(doc_cfg))]
// We want to have UPPERCASE idents sometimes.
#![allow(clippy::upper_case_acronyms)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::debug_assert_with_mut_call)]

pub mod evm_word;
pub mod is_zero;
pub mod monotone;

use halo2_proofs::circuit::AssignedCell;
use pairing::arithmetic::FieldExt;

#[allow(dead_code)]
/// An assigned cell in the circuit.
#[derive(Clone, Debug)]
pub struct Variable<T, F: FieldExt> {
    assig_cell: AssignedCell<F, F>,
    value: Option<T>,
}

impl<T, F: FieldExt> Variable<T, F> {
    pub(crate) fn new(assig_cell: AssignedCell<F, F>, value: Option<T>) -> Self {
        Self { assig_cell, value }
    }
}
