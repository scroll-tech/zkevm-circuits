//! A recursion circuit generates a new proof for multiple 
//! target circuit (now it is compression circuit) in a recursive fashion
//! It use the begin and final inputs (block hashes) of the aggregated snarks
//! The designation base on https://github.com/axiom-crypto/snark-verifier/blob/main/snark-verifier/examples/recursion.rs

mod common;
/// Circuit implementation of recursion circuit.
mod circuit;
/// Config for recursion circuit
mod config;

use ark_std::{end_timer, start_timer};
use halo2_base::halo2_proofs;
use halo2_proofs::{
    halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine},
        group::ff::Field,
    },
    circuit::{Layouter, Value},
    plonk::{Selector, Circuit, Error, ConstraintSystem, ProvingKey, VerifyingKey},
};
use snark_verifier::{
    loader::{
        native::NativeLoader,
        Loader, ScalarLoader, {self},
    },
    system::halo2::{
        compile, Config, {self},
    },
    verifier::{
        PlonkProof, PlonkVerifier, {self},
    },    
    Protocol,
};
use rand::Rng;
use itertools::Itertools;
use crate::param::ConfigParams as AggregationConfigParams;
use common::*;

pub trait CircuitExt<F: Field>: Circuit<F> {
    fn num_instance() -> Vec<usize>;

    fn instances(&self) -> Vec<Vec<F>>;

    fn accumulator_indices() -> Option<Vec<(usize, usize)>> {
        None
    }

    /// Output the simple selector columns (before selector compression) of the circuit
    fn selectors(_: &Self::Config) -> Vec<Selector> {
        vec![]
    }
}

pub trait StateTransition {
    type Input;

    fn new(state: Fr) -> Self;

    fn state_transition(&self, input: Self::Input) -> Fr;
}
