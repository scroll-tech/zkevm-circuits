use super::Prover;
use crate::{
    config::layer_config_path,
    io::{load_snark, write_snark},
    utils::gen_rng,
};
use aggregator::{initial_recursion_snark, RecursionCircuit, StateTransition, MAX_AGG_SNARKS};
use anyhow::Result;
use rand::Rng;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};
use std::env;
// TODO: move the type to `types`
use crate::recursion::AggregatedBatchProvingTask;

impl Prover {
    pub fn gen_recursion_snark(
        &mut self,
        id: &str,
        degree: u32,
        mut rng: impl Rng + Send,
        batch_snarks: &[Snark],
    ) -> Result<Snark> {
        assert!(!batch_snarks.is_empty());
        // recursion is a special kind of aggregation so we use aggregation's config
        env::set_var("AGGREGATION_CONFIG", layer_config_path(id));

        let params = self.params(degree);

        let init_snark = initial_recursion_snark::<AggregatedBatchProvingTask<MAX_AGG_SNARKS>>(
            params, None, &mut rng,
        );
        let init_state = batch_snarks;
        let task = AggregatedBatchProvingTask::<MAX_AGG_SNARKS>::new(init_state);
        let init_instance = task.init_instances();

        let circuit = RecursionCircuit::<AggregatedBatchProvingTask<MAX_AGG_SNARKS>>::new(
            self.params(degree),
            batch_snarks[0].clone(),
            init_snark,
            &mut rng,
            &init_instance,
            &task.state_instances(),
            0,
        );

        let (params, pk) = self.params_and_pk(id, degree, &circuit)?;

        // prepare the initial snark
        let mut previous_snark = gen_snark_shplonk(params, pk, circuit, &mut rng, None::<String>)?;
        log::debug!("construct recursion snark for first round ...done");
        let mut n_rounds = 1;
        let mut cur_state = task.state_transition(n_rounds);

        while !cur_state.is_empty() {
            log::debug!("construct recursion circuit for round {}", n_rounds);
            let task = AggregatedBatchProvingTask::<MAX_AGG_SNARKS>::new(cur_state);
            let circuit = RecursionCircuit::<AggregatedBatchProvingTask<MAX_AGG_SNARKS>>::new(
                params,
                batch_snarks[0].clone(),
                previous_snark,
                &mut rng,
                &init_instance,
                &task.state_instances(),
                n_rounds,
            );
            previous_snark = gen_snark_shplonk(params, pk, circuit, &mut rng, None::<String>)?;
            log::debug!("construct recursion snark for round {} ...done", n_rounds);
            n_rounds += 1;
            cur_state = task.state_transition(n_rounds);
        }

        Ok(previous_snark)
    }

    pub fn load_or_gen_recursion_snark(
        &mut self,
        name: &str,
        id: &str,
        degree: u32,
        batch_snarks: &[Snark],
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        let file_path = format!(
            "{}/recursion_snark_{}_{}.json",
            output_dir.unwrap_or_default(),
            id,
            name
        );

        match output_dir.and_then(|_| load_snark(&file_path).ok().flatten()) {
            Some(snark) => Ok(snark),
            None => {
                let rng = gen_rng();
                let result = self.gen_recursion_snark(id, degree, rng, batch_snarks);
                if let (Some(_), Ok(snark)) = (output_dir, &result) {
                    write_snark(&file_path, snark);
                }

                result
            }
        }
    }
}
