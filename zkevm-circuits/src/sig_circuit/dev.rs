use super::*;

//#[cfg(not(feature = "onephase"))]
use crate::{util::Challenges, witness::keccak::keccak_inputs_sign_verify};
//#[cfg(feature = "onephase")]
//use crate::util::MockChallenges as Challenges;

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
        let mut sig_k1_with_dummy = self.signatures_k1.clone();
        sig_k1_with_dummy.push(SignData::<Fq_K1, Secp256k1Affine>::default());

        let mut keccak_inputs_sign = keccak_inputs_sign_verify(&sig_k1_with_dummy);

        let mut sig_r1_with_dummy = self.signatures_r1.clone();
        sig_r1_with_dummy.push(SignData::<Fq_R1, Secp256r1Affine>::default());

        let keccak_inputs_r1 = keccak_inputs_sign_verify(&sig_r1_with_dummy);

        keccak_inputs_sign.extend(keccak_inputs_r1);

        config.sign_verify.keccak_table.dev_load(
            &mut layouter,
            &keccak_inputs_sign,
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
