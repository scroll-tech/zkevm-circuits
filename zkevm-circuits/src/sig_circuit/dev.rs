use super::*;

//#[cfg(not(feature = "onephase"))]
use crate::util::Challenges;
//#[cfg(feature = "onephase")]
//use crate::util::MockChallenges as Challenges;

use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
use eth_types::sign_types::sign;
use halo2_proofs::{
    arithmetic::Field as HaloField,
    circuit::SimpleFloorPlanner,
    dev::MockProver,
    halo2curves::{bn256::Fr, group::Curve, secp256k1},
    plonk::Circuit,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use sha3::{Digest, Keccak256};

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
        config.sign_verify.load_range(&mut layouter)?;
        let _assigned_sig_verifs = self.assign(
            &config.sign_verify,
            &mut layouter,
            &self.signatures,
            &challenges,
        )?;
        config.sign_verify.keccak_table.dev_load(
            &mut layouter,
            &keccak_inputs_sign_verify(&self.signatures),
            &challenges,
        )?;
        /*
        self.assert_sig_is_valid(
            &config.sign_verify,
            &mut layouter,
            assigned_sig_verifs.as_slice(),
        )?;
        */
        Ok(())
    }
}
