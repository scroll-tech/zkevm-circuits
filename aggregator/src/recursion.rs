//! A recursion circuit generates a new proof for multiple 
//! target circuit (now it is compression circuit) in a recursive fashion
//! It use the begin and final inputs (block hashes) of the aggregated snarks
//! The designation base on https://github.com/axiom-crypto/snark-verifier/blob/main/snark-verifier/examples/recursion.rs

/// Circuit implementation of recursion circuit.
mod circuit;
/// Config for recursion circuit
mod config;