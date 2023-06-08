pub use super::TxCircuit;

use crate::{
    table::{BlockTable, KeccakTable, RlpTable, TxTable},
    tx_circuit::{TxCircuitConfig, TxCircuitConfigArgs},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::Transaction,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
impl<F: Field> Circuit<F> for TxCircuit<F> {
    type Config = (TxCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let block_table = BlockTable::construct(meta); println!("block_table.num_advice_columns: {}", meta.num_advice_columns);
        let tx_table = TxTable::construct(meta); println!("tx_table.num_advice_columns: {}", meta.num_advice_columns);
        let keccak_table = KeccakTable::construct(meta); println!("keccak_table.num_advice_columns: {}", meta.num_advice_columns);
        let rlp_table = RlpTable::construct(meta); println!("rlp_table.num_advice_columns: {}", meta.num_advice_columns);
        let challenges = Challenges::construct(meta); println!("challenges.num_advice_columns: {}", meta.num_advice_columns);

        let config = {
            let challenges = challenges.exprs(meta);
            TxCircuitConfig::new(
                meta,
                TxCircuitConfigArgs {
                    block_table,
                    tx_table,
                    keccak_table,
                    rlp_table,
                    challenges,
                },
            )
        };
        println!("TxCircuitConfig.num_advice_columns: {}", meta.num_advice_columns);

        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        println!("tx circuit dev synthesize");

        let padding_txs = (self.txs.len()..self.max_txs)
            .into_iter()
            .map(|i| {
                let mut tx = Transaction::dummy(self.chain_id);
                tx.id = i + 1;
                tx
            })
            .collect::<Vec<Transaction>>();

        config
            .keccak_table
            .dev_load(&mut layouter, &self.keccak_inputs()?, &challenges)?;
        config.tx_table.load(
            &mut layouter,
            &self.txs,
            self.max_txs,
            self.max_calldata,
            self.chain_id,
            &challenges,
        )?;
        config.rlp_table.dev_load(
            &mut layouter,
            self.txs
                .iter()
                .chain(padding_txs.iter())
                .map(|tx| tx.into())
                .collect(),
            &challenges,
        )?;
        self.assign_dev_block_table(config.clone(), &mut layouter)?;
        println!("tx circuit synthesize_sub begin");
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}
