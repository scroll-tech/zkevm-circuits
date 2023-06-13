pub use super::TxCircuit;
//use super::sign_verify::SigTable;

use crate::{
    table::{BlockTable, KeccakTable, RlpFsmRlpTable as RlpTable, TxTable, SigTable},
    tx_circuit::{TxCircuitConfig, TxCircuitConfigArgs},
    sig_circuit::SigCircuit,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::Transaction, sig_circuit::{SigCircuitConfig, SigCircuitConfigArgs},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};


/// TxCircuitTesterConfig
#[derive(Clone, Debug)]
pub struct TxCircuitTesterConfig<F: Field> {
    // SigTable is assigned inside SigCircuit
    sig_table: SigTable,
    keccak_table: KeccakTable,
    tx_config: TxCircuitConfig<F>,
    sig_config: SigCircuitConfig<F>,
}

/// The difference of this tester circuit and TxCircuit is that sig_circuit is included here.
#[derive(Clone, Debug, Default)]
pub struct TxCircuitTester<F: Field> {
    pub(super) sig_circuit: SigCircuit<F>,
    //keccak_table: KeccakTable,
    pub(super) tx_circuit: TxCircuit<F>,
    //sig_config: SigCircuitConfig<F>,
}



// SigCircuit is embedded inside TxCircuit to make testing easier
impl<F: Field> Circuit<F> for TxCircuitTester<F> {
    type Config = (TxCircuitTesterConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta);
        let tx_table = TxTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let rlp_table = RlpTable::construct(meta);
        let sig_table = SigTable::construct(meta);
        let challenges = Challenges::construct(meta);


        // TODO: check this 
        //#[cfg(feature = "enable-sign-verify")]
        //self.sign_verify.load_range(layouter)?;

        let config = {
            let challenges = challenges.exprs(meta);
            let sig_config = SigCircuitConfig::new(
                meta,
                SigCircuitConfigArgs {
                    sig_table: sig_table.clone(),
                    challenges: challenges.clone(),
                    keccak_table: keccak_table.clone(),
                }
            );
            let tx_config = TxCircuitConfig::new(
                meta,
                TxCircuitConfigArgs {
                    sig_table: sig_table.clone(),
                    block_table,
                    tx_table,
                    keccak_table: keccak_table.clone(),
                    rlp_table,
                    challenges,
                },
            );
            TxCircuitTesterConfig {
                sig_table,
                keccak_table,
                tx_config,
                sig_config,
            }
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        config.tx_config
            .keccak_table
            .dev_load(&mut layouter, &self.tx_circuit.keccak_inputs()?, &challenges)?;
        self.tx_circuit.synthesize_sub(&config.tx_config, &challenges, &mut layouter)?;
        self.sig_circuit.synthesize_sub(&config.sig_config, &challenges, &mut layouter)?;
        self.tx_circuit.assign_dev_block_table(config.tx_config, &mut layouter)?;
        Ok(())
    }
}
