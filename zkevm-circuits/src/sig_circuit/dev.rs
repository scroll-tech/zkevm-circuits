use super::*;

use crate::util::Challenges;

use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};

/// SigCircuitTesterConfig
#[derive(Clone, Debug)]
pub struct SigCircuitTesterConfig<F: Field> {
    sign_verify: SigCircuitConfig<F>,
    challenges: crate::util::Challenges,
}

impl<F: Field> SigCircuitTesterConfig<F> {
    pub(crate) fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let keccak_table = KeccakTable::construct(meta);
        let sig_table = SigTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenges_expr = challenges.exprs(meta);
        let sign_verify = SigCircuitConfig::new(
            meta,
            SigCircuitConfigArgs {
                keccak_table,
                challenges: challenges_expr,
                sig_table,
            },
        );

        SigCircuitTesterConfig {
            sign_verify,
            challenges,
        }
    }
}

impl<F: Field> Circuit<F> for SigCircuit<F> {
    type Config = SigCircuitTesterConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        SigCircuitTesterConfig::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = config.challenges.values(&layouter);
        self.synthesize_sub(&config.sign_verify, &challenges, &mut layouter)?;
        config.sign_verify.keccak_table.dev_load(
            &mut layouter,
            &keccak_inputs_sign_verify(&self.signatures),
            &challenges,
        )?;
        Ok(())
    }
}
