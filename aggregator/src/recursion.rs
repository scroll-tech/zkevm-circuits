//! A recursion circuit generates a new proof for multiple
//! target circuit (now it is compression circuit) in a recursive fashion
//! It use the begin and final inputs (block hashes) of the aggregated snarks
//! The designation base on https://github.com/axiom-crypto/snark-verifier/blob/main/snark-verifier/examples/recursion.rs

/// Circuit implementation of recursion circuit.
mod circuit;
mod common;
/// Config for recursion circuit
mod config;
mod util;

pub(crate) use common::dynamic_verify;
pub use util::{gen_recursion_pk, initial_recursion_snark};

// define the halo2base importing from snark_verifier;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base as sv_halo2_base;
use sv_halo2_base::halo2_proofs;
// fix the circuit on Bn256
use halo2_proofs::{
    halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine},
        group::ff::Field,
    },
    plonk::{Circuit, ConstraintSystem, Error, ProvingKey, Selector, VerifyingKey},
};
// exports Snark and specs for F-S scheme
use snark_verifier_sdk::{
    types::{PoseidonTranscript, POSEIDON_SPEC},
    CircuitExt, Snark,
};

use crate::{
    constants::{BITS, LIMBS},
    param::ConfigParams as AggregationConfigParams,
};

use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::{native::NativeLoader, Loader, ScalarLoader},
    system::halo2::{compile, Config},
    verifier::{PlonkProof, PlonkVerifier},
};

pub trait StateTransition: Sized {
    type Input: Clone;
    type Circuit: CircuitExt<Fr>;

    fn new(state: Self::Input) -> Self;

    fn state_transition(&self, round: usize) -> Self::Input;

    // the number of fields should be used for state transition
    // notice the pi take 2 times of the returned number (before -> after)
    fn num_transition_instance() -> usize;

    // in case the circuit still require more PI followed by
    // state transition
    fn num_additional_instance() -> usize {
        0
    }

    fn num_instance() -> usize {
        Self::num_transition_instance() * 2 + Self::num_additional_instance()
    }
}

pub use circuit::RecursionCircuit;
