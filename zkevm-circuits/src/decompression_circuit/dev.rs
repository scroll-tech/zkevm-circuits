use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::{
    decompression_circuit::{
        DecompressionCircuit, DecompressionCircuitConfig, DecompressionCircuitConfigArgs,
    },
    table::{KeccakTable, U8Table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
};

impl<F: Field> Circuit<F> for DecompressionCircuit<F> {
    type Config = (DecompressionCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        let u8_table = U8Table::construct(meta);
        let keccak_table = KeccakTable::construct(meta);

        let config = DecompressionCircuitConfig::new(
            meta,
            DecompressionCircuitConfigArgs {
                challenges: challenge_exprs,
                u8_table,
                keccak_table,
            },
        );
        log::debug!("meta.degree() = {}", meta.degree());

        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = &config.1.values(&layouter);
        config.0.u8_table.load(&mut layouter)?;
        self.synthesize_sub(&config.0, challenges, &mut layouter)
    }
}
