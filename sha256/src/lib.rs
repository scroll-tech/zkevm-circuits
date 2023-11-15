//! sha256 adapt table16 in halo2_gadgets

#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

// The size of a SHA-256 digest, in 32-bit words.
const DIGEST_SIZE: usize = 8;
pub use halo2_gadgets::sha256::{Sha256, Sha256Instructions, Sha256Digest, BLOCK_SIZE};
use halo2_proofs::arithmetic::FieldExt as Field;

/// ...
pub mod table16;
/// sha256 circuit can be integrated into zkevm
pub mod circuit;