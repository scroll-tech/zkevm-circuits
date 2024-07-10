use halo2_proofs::halo2curves::bn256::Fr;

use aggregator::{BatchCircuit, StateTransition};
use snark_verifier_sdk::Snark;

#[derive(Clone, Debug)]
pub struct AggregatedBatchProvingTask<'a, const N_SNARK: usize> {
    agg_snarks: &'a [Snark],
}

// 4 fields for 2 hashes (Hi, Lo)
const ST_INSTANCE: usize = 4;
// and then 3 fields for 1 hash (withdraw root) and chainID
const ADD_INSTANCE: usize = 3;
const NUM_INSTANCES: usize = ST_INSTANCE + ADD_INSTANCE;
const NUM_INIT_INSTANCES: usize = ST_INSTANCE;

impl<const N_SNARK: usize> AggregatedBatchProvingTask<'_, N_SNARK> {
    pub fn init_instances(&self) -> [Fr; NUM_INIT_INSTANCES] {
        self.agg_snarks.first().unwrap().instances[0][..ST_INSTANCE]
            .try_into()
            .unwrap()
    }

    pub fn state_instances(&self) -> [Fr; NUM_INSTANCES] {
        self.agg_snarks.first().unwrap().instances[0][ST_INSTANCE..]
            .try_into()
            .unwrap()
    }

    pub fn iter_snark(&self) -> Snark {
        self.agg_snarks.first().unwrap().clone()
    }

    pub fn completed(&self) -> bool {
        self.agg_snarks.is_empty()
    }
}

impl<'a, const N_SNARK: usize> StateTransition for AggregatedBatchProvingTask<'a, N_SNARK> {
    type Input = &'a [Snark];
    type Circuit = BatchCircuit<N_SNARK>;

    fn new(state: Self::Input) -> Self {
        Self { agg_snarks: state }
    }

    fn state_transition(&self, _round: usize) -> Self::Input {
        &self.agg_snarks[1..]
    }

    fn num_transition_instance() -> usize {
        ST_INSTANCE
    }
    fn num_additional_instance() -> usize {
        ADD_INSTANCE
    }
}
