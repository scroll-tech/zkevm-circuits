use halo2_proofs::halo2curves::bn256::Fr;

use aggregator::{BatchCircuit, StateTransition};
use snark_verifier_sdk::Snark;

/// 4 fields for 2 hashes (Hi, Lo)
const ST_INSTANCE: usize = 4;

/// Additional public inputs, specifically:
/// - withdraw root (hi, lo)
/// - chain ID
const ADD_INSTANCE: usize = 3;

/// Number of public inputs to describe the state.
const NUM_INSTANCES: usize = ST_INSTANCE + ADD_INSTANCE;

/// Number of public inputs to describe the initial state.
const NUM_INIT_INSTANCES: usize = ST_INSTANCE;

#[derive(Clone, Debug)]
pub struct RecursionTask<'a, const N_SNARK: usize> {
    /// The [`snarks`][snark] from the [`BatchCircuit`][batch_circuit].
    ///
    /// [snark]: snark_verifier_sdk::Snark
    /// [batch_circuit]: aggregator::BatchCircuit
    snarks: &'a [Snark],
}

impl<const N_SNARK: usize> RecursionTask<'_, N_SNARK> {
    pub fn init_instances(&self) -> [Fr; NUM_INIT_INSTANCES] {
        self.snarks.first().unwrap().instances[0][..ST_INSTANCE]
            .try_into()
            .unwrap()
    }

    pub fn state_instances(&self) -> [Fr; NUM_INSTANCES] {
        self.snarks.first().unwrap().instances[0][ST_INSTANCE..]
            .try_into()
            .unwrap()
    }

    pub fn iter_snark(&self) -> Snark {
        self.snarks.first().unwrap().clone()
    }

    pub fn completed(&self) -> bool {
        self.snarks.is_empty()
    }
}

impl<'a, const N_SNARK: usize> StateTransition for RecursionTask<'a, N_SNARK> {
    type Input = &'a [Snark];
    type Circuit = BatchCircuit<N_SNARK>;

    fn new(state: Self::Input) -> Self {
        Self { snarks: state }
    }

    fn state_transition(&self, _round: usize) -> Self::Input {
        &self.snarks[1..]
    }

    fn num_transition_instance() -> usize {
        ST_INSTANCE
    }

    fn num_additional_instance() -> usize {
        ADD_INSTANCE
    }
}
