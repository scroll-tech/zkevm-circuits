pub use super::ExpCircuit;

use crate::{
    exp_circuit::ExpCircuitConfig,
    table::ExpTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

impl<F: Field> Circuit<F> for ExpCircuit<F> {
    type Config = (ExpCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let exp_table = ExpTable::construct(meta);
        let challenges = Challenges::construct(meta);
        (ExpCircuitConfig::new(meta, exp_table), challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
