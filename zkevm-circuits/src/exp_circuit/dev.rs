pub use super::ExpCircuit;

use crate::{
    exp_circuit::{ExpCircuitArgs, ExpCircuitConfig},
    table::{ExpTable, U16Table, U8Table},
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
        let u8_table = U8Table::construct(meta);
        let u16_table = U16Table::construct(meta);
        (
            ExpCircuitConfig::new(
                meta,
                ExpCircuitArgs {
                    exp_table,
                    u8_table,
                    u16_table,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        config.u8_table.load(&mut layouter)?;
        config.u16_table.load(&mut layouter)?;
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
