use crate::{
    rlp_circuit_fsm::{RlpCircuit, RlpCircuitConfig, RlpCircuitConfigArgs},
    table::{RlpFsmRlpTable, U8Table},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::Transaction,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

impl<F: Field> Circuit<F> for RlpCircuit<F, Transaction> {
    type Config = (RlpCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let rlp_table = RlpFsmRlpTable::construct(meta);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        let u8_table = U8Table::construct(meta);

        let config = RlpCircuitConfig::new(
            meta,
            RlpCircuitConfigArgs {
                rlp_table,
                u8_table,
                challenges: challenge_exprs,
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
