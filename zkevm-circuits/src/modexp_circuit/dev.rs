use super::*;
use crate::util::MockChallenges;
use halo2_proofs::{
    circuit::SimpleFloorPlanner,
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem},
};

impl Circuit<Fr> for ModExpCircuit<Fr> {
    type Config = (ModExpCircuitConfig, MockChallenges);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let modexp_table = ModExpTable::construct(meta);
        let challenge = MockChallenges::construct(meta);
        (
            <ModExpCircuitConfig as SubCircuitConfig<Fr>>::new(meta, modexp_table),
            challenge,
        )
    }

    fn synthesize(
        &self,
        (config, challenge): Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let challenges = challenge.values(&layouter);
        <Self as SubCircuit<Fr>>::synthesize_sub(self, &config, &challenges, &mut layouter)
    }
}
