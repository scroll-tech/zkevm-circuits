use std::{env, path::Path};

use aggregator::{initial_recursion_snark, RecursionCircuit, StateTransition, MAX_AGG_SNARKS};
use anyhow::Result;
use rand::Rng;
use snark_verifier_sdk::{gen_snark_shplonk, Snark};

use crate::{
    aggregator::RecursionTask,
    config::layer_config_path,
    utils::{gen_rng, read_json_deep, write_json},
};

impl<'params> super::Prover<'params> {
    pub fn load_or_gen_recursion_snark(
        &mut self,
        name: &str,
        id: &str,
        degree: u32,
        batch_snarks: &[Snark],
        output_dir: Option<&str>,
    ) -> Result<Snark> {
        // If an output directory is provided and we are successfully able to locate a SNARK with
        // the same identifier on disk, return early.
        if let Some(dir) = output_dir {
            let path = Path::new(dir).join(format!("recursion_snark_{}_{}.json", id, name));
            if let Ok(snark) = read_json_deep(&path) {
                return Ok(snark);
            }
        }

        // Generate the layer-5 recursion SNARK.
        let rng = gen_rng();
        let snark = self.gen_recursion_snark(id, degree, rng, batch_snarks)?;

        // Write to disk if an output directory is provided.
        if let Some(dir) = output_dir {
            let path = Path::new(dir).join(format!("recursion_snark_{}_{}.json", id, name));
            write_json(&path, &snark)?;
        }

        Ok(snark)
    }

    fn gen_recursion_snark(
        &mut self,
        id: &str,
        degree: u32,
        mut rng: impl Rng + Send,
        batch_snarks: &[Snark],
    ) -> Result<Snark> {
        // We should at least have a single snark.
        assert!(!batch_snarks.is_empty());

        env::set_var("BUNDLE_CONFIG", layer_config_path(id));
        let params = self.params(degree);

        // Generate an initial snark, that represents the start of the recursion process.
        let init_snark =
            initial_recursion_snark::<RecursionTask<MAX_AGG_SNARKS>>(params, None, &mut rng);

        // The recursion circuit's instance based on this initial snark state should not be used as
        // the "real" snark output. It doesn't take into account the preprocessed state. The
        // recursion circuit needs a verification key, which itself needs the recursion circuit. To
        // break this dependency cycle.
        let circuit_for_pk = RecursionCircuit::<RecursionTask<MAX_AGG_SNARKS>>::new(
            params,
            batch_snarks[0].clone(),
            init_snark,
            &mut rng,
            0,
        );
        let (params, pk) = self.params_and_pk(id, degree, &circuit_for_pk)?;

        // Using the above generated PK, we can now construct the legitimate starting state.
        let mut cur_snark = initial_recursion_snark::<RecursionTask<MAX_AGG_SNARKS>>(
            params,
            Some(pk.get_vk()),
            &mut rng,
        );

        // The recursion task is initialised with all the snarks, and the we are at the 0th round
        // of recursion at the start.
        let mut task = RecursionTask::<MAX_AGG_SNARKS>::new(batch_snarks);
        let mut n_rounds = 0;

        while !task.completed() {
            log::debug!("construct recursion circuit for round {}", n_rounds);

            let circuit = RecursionCircuit::<RecursionTask<MAX_AGG_SNARKS>>::new(
                params,
                task.iter_snark(),
                cur_snark,
                &mut rng,
                n_rounds,
            );
            cur_snark = gen_snark_shplonk(params, pk, circuit, &mut rng, None::<String>)?;

            log::info!("construct recursion snark for round {} ...done", n_rounds);

            // Increment the round of recursion and transition to the next state.
            n_rounds += 1;
            task = RecursionTask::<MAX_AGG_SNARKS>::new(task.state_transition(n_rounds));
        }

        Ok(cur_snark)
    }
}
