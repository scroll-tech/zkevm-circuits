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
        env::set_var("BUNDLE_CONFIG", layer_config_path(id));

        let params = self.params(degree);

        let init_snark = initial_recursion_snark::<AggregatedBatchProvingTask<MAX_AGG_SNARKS>>(
            params, None, &mut rng,
        );

        // notice this circuit must not be used to genreate the real snark
        // since it has a "fake" circuit in its `init_snark` (the preprocess digest is not identify)
        let circuit_for_pk = RecursionCircuit::<AggregatedBatchProvingTask<MAX_AGG_SNARKS>>::new(
            params,
            batch_snarks[0].clone(),
            init_snark,
            &mut rng,
            0,
        );

        let (params, pk) = self.params_and_pk(id, degree, &circuit_for_pk)?;

        // with the pk we can construct the correct init_snark
        let init_snark = initial_recursion_snark::<AggregatedBatchProvingTask<MAX_AGG_SNARKS>>(
            params, Some(pk.get_vk()), &mut rng,
        );        
        let init_state = batch_snarks;
        let mut task = AggregatedBatchProvingTask::<MAX_AGG_SNARKS>::new(init_state);

        let circuit = RecursionCircuit::<AggregatedBatchProvingTask<MAX_AGG_SNARKS>>::new(
            params,
            task.iter_snark(),
            init_snark,
            &mut rng,
            0,
        );

        // prepare the initial snark
        let mut cur_snark = gen_snark_shplonk(params, pk, circuit, &mut rng, None::<String>)?;
        log::info!("construct recursion snark for first round ...done");
        let mut n_rounds = 1;
        let mut cur_state = task.state_transition(n_rounds);

        while !task.completed() {
            log::debug!("construct recursion circuit for round {}", n_rounds);
            task = AggregatedBatchProvingTask::<MAX_AGG_SNARKS>::new(cur_state);
            let circuit = RecursionCircuit::<AggregatedBatchProvingTask<MAX_AGG_SNARKS>>::new(
                params,
                task.iter_snark(),
                cur_snark,
                &mut rng,
                n_rounds,
            );
            cur_snark = gen_snark_shplonk(params, pk, circuit, &mut rng, None::<String>)?;
            log::info!("construct recursion snark for round {} ...done", n_rounds);
            n_rounds += 1;
            cur_state = task.state_transition(n_rounds);
        }

        Ok(cur_snark)
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
