//! A recursion circuit generates a new proof for multiple
//! target circuit (now it is compression circuit) in a recursive fashion
//! It use the begin and final inputs (block hashes) of the aggregated snarks
//! The designation base on https://github.com/axiom-crypto/snark-verifier/blob/main/snark-verifier/examples/recursion.rs

/// Circuit implementation of recursion circuit.
mod circuit;

/// Common functionality utilised by the recursion circuit.
mod common;

/// Config for recursion circuit
mod config;

/// Some utility functions.
mod util;

pub use circuit::RecursionCircuit;
pub(crate) use common::dynamic_verify;
pub use util::{gen_recursion_pk, initial_recursion_snark};

use halo2_proofs::{
    halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine},
        group::ff::Field,
    },
    plonk::{Circuit, ConstraintSystem, Error, ProvingKey, Selector, VerifyingKey},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::{
        halo2::halo2_ecc::halo2_base as sv_halo2_base, native::NativeLoader, Loader, ScalarLoader,
    },
    system::halo2::{compile, Config},
    verifier::{PlonkProof, PlonkVerifier},
};
use snark_verifier_sdk::{
    types::{PoseidonTranscript, POSEIDON_SPEC},
    CircuitExt, Snark,
};
use sv_halo2_base::halo2_proofs;

use crate::constants::{BITS, LIMBS};

/// Any data that can be recursively bundled must implement the described state transition
/// trait.
pub trait StateTransition: Sized {
    type Input: Clone;
    type Circuit: CircuitExt<Fr>;

    /// Initialise a new type that implements the state transition behaviour.
    fn new(state: Self::Input) -> Self;

    /// Transition to the next state.
    fn state_transition(&self, round: usize) -> Self::Input;

    /// Returns the number of fields used to represent state. The public input consists of twice
    /// this number as both the previous and current states are included in the public input.
    fn num_transition_instance() -> usize;

    /// Returns the number of fields required by the circuit in addition to the fields to represent
    /// its state.
    fn num_additional_instance() -> usize {
        0
    }

    /// The number of instance cells for the circuit.
    fn num_instance() -> usize {
        Self::num_accumulator_instance()
            + Self::num_transition_instance() * 2
            + Self::num_additional_instance()
    }

    /// Returns the number of instance cells used to hold the accumulator.
    fn num_accumulator_instance() -> usize {
        Self::Circuit::accumulator_indices()
            .map(|v| v.len())
            .unwrap_or_default()
    }

    /// Following is the indices of the layout of instance
    /// for StateTransition circuit, the default suppose
    /// single col of instance, and the layout is:
    /// accumulator | prev_state | state | additional
    ///
    /// Notice we do not verify the layout of accumulator
    /// simply suppose they are put in the beginning
    fn accumulator_indices() -> Vec<usize> {
        let start = 0;
        let end = Self::num_accumulator_instance();
        (start..end).collect()
    }

    /// The accumulator is followed by the instance cells representing the previous state.
    fn state_prev_indices() -> Vec<usize> {
        let start = Self::num_accumulator_instance();
        let end = start + Self::num_transition_instance();
        (start..end).collect()
    }

    /// The previous state is followed by the instance cells representing the current state.
    fn state_indices() -> Vec<usize> {
        let start = Self::num_accumulator_instance() + Self::num_transition_instance();
        let end = start + Self::num_transition_instance();
        (start..end).collect()
    }

    /// The indices of any other instances cells in addition to the accumulator and state
    /// transition cells.
    fn additional_indices() -> Vec<usize> {
        let start = Self::num_accumulator_instance() + 2 * Self::num_transition_instance();
        let end = Self::num_instance();
        (start..end).collect()
    }
}
