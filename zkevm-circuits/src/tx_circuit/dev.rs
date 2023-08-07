/// TxCircuitTester is the combined circuit of tx circuit and sig circuit.
use std::marker::PhantomData;

use super::get_sign_data;
pub use super::TxCircuit;

use crate::{
    sig_circuit::{SigCircuit, SigCircuitConfig, SigCircuitConfigArgs},
    table::{
        BlockTable, KeccakTable, RlpFsmRlpTable as RlpTable, SigTable, TxTable, U16Table, U8Table,
    },
    tx_circuit::{TxCircuitConfig, TxCircuitConfigArgs},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::Transaction,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};

/// Circuit configuration arguments
pub struct TxCircuitTesterConfigArgs<F: Field> {
    /// TxTable
    pub tx_table: TxTable,
    /// Block Table
    pub block_table: BlockTable,
    /// RlpTable
    pub rlp_table: RlpTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// SigTable
    pub sig_table: SigTable,
    /// u8 lookup table,
    pub u8_table: U8Table,
    /// u16 lookup table,
    pub u16_table: U16Table,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

/// TxCircuitTesterConfig
#[derive(Clone, Debug)]
pub struct TxCircuitTesterConfig<F: Field> {
    tx_config: TxCircuitConfig<F>,
    // SigTable is assigned inside SigCircuit
    sig_config: SigCircuitConfig<F>,
    /// u16 lookup table,
    pub u8_table: U8Table,
    /// u16 lookup table,
    pub u16_table: U16Table,
}

impl<F: Field> SubCircuitConfig<F> for TxCircuitTesterConfig<F> {
    type ConfigArgs = TxCircuitTesterConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            tx_table,
            block_table,
            keccak_table,
            rlp_table,
            sig_table,
            u8_table,
            u16_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        let sig_config = SigCircuitConfig::new(
            meta,
            SigCircuitConfigArgs {
                sig_table,
                challenges: challenges.clone(),
                keccak_table: keccak_table.clone(),
            },
        );
        let tx_config = TxCircuitConfig::new(
            meta,
            TxCircuitConfigArgs {
                sig_table,
                block_table,
                tx_table,
                keccak_table,
                rlp_table,
                u8_table,
                u16_table,
                challenges,
            },
        );
        TxCircuitTesterConfig {
            tx_config,
            sig_config,
            u8_table,
            u16_table,
        }
    }
}

/// The difference of this tester circuit and TxCircuit is that sig_circuit is included here.
#[derive(Clone, Debug, Default)]
pub struct TxCircuitTester<F: Field> {
    pub(super) sig_circuit: SigCircuit<F>,
    pub(super) tx_circuit: TxCircuit<F>,
}

impl<F: Field> TxCircuitTester<F> {
    /// Return a new TxCircuit
    pub fn new(max_txs: usize, max_calldata: usize, chain_id: u64, txs: Vec<Transaction>) -> Self {
        TxCircuitTester::<F> {
            sig_circuit: SigCircuit {
                max_verif: max_txs,
                signatures: get_sign_data(&txs, max_txs, chain_id as usize).unwrap(),
                _marker: PhantomData,
            },
            tx_circuit: TxCircuit::new(max_txs, max_calldata, chain_id, txs),
        }
    }
}

impl<F: Field> SubCircuit<F> for TxCircuitTester<F> {
    type Config = TxCircuitTesterConfig<F>;

    fn new_from_block(block: &crate::witness::Block<F>) -> Self {
        let txs = block.txs.clone();
        let max_txs = block.circuits_params.max_txs;
        let chain_id = block.chain_id;
        let max_calldata = block.circuits_params.max_calldata;
        Self::new(max_txs, max_calldata, chain_id, txs)
    }

    fn synthesize_sub(
        &self,
        _config: &Self::Config,
        _challenges: &Challenges<halo2_proofs::circuit::Value<F>>,
        _layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        unimplemented!("not needed")
    }

    fn min_num_rows_block(block: &crate::witness::Block<F>) -> (usize, usize) {
        // TODO
        SigCircuit::min_num_rows_block(block)
    }
}

// SigCircuit is embedded inside TxCircuitTester to make testing easier
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
        let u8_table = U8Table::construct(meta);
        let u16_table = U16Table::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            let sig_config = SigCircuitConfig::new(
                meta,
                SigCircuitConfigArgs {
                    sig_table,
                    challenges: challenges.clone(),
                    keccak_table: keccak_table.clone(),
                },
            );
            let tx_config = TxCircuitConfig::new(
                meta,
                TxCircuitConfigArgs {
                    sig_table,
                    block_table,
                    tx_table,
                    keccak_table,
                    rlp_table,
                    u8_table,
                    u16_table,
                    challenges,
                },
            );
            TxCircuitTesterConfig {
                tx_config,
                sig_config,
                u8_table,
                u16_table,
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
        config.u8_table.load(&mut layouter)?;
        config.u16_table.load(&mut layouter)?;

        let padding_txs = (self.tx_circuit.txs.len()..self.tx_circuit.max_txs)
            .into_iter()
            .map(|i| {
                let mut tx = Transaction::dummy(self.tx_circuit.chain_id);
                tx.id = i + 1;
                tx
            })
            .collect::<Vec<Transaction>>();

        config.tx_config.keccak_table.dev_load(
            &mut layouter,
            &self.tx_circuit.keccak_inputs()?,
            &challenges,
        )?;

        config.tx_config.tx_table.load(
            &mut layouter,
            &self.tx_circuit.txs,
            self.tx_circuit.max_txs,
            self.tx_circuit.max_calldata,
            self.tx_circuit.chain_id,
            &challenges,
        )?;
        config.tx_config.rlp_table.dev_load(
            &mut layouter,
            self.tx_circuit
                .txs
                .iter()
                .chain(padding_txs.iter())
                .cloned()
                .collect(),
            &challenges,
        )?;

        self.tx_circuit
            .assign_dev_block_table(config.tx_config.clone(), &mut layouter)?;
        self.tx_circuit
            .synthesize_sub(&config.tx_config, &challenges, &mut layouter)?;
        self.sig_circuit
            .synthesize_sub(&config.sig_config, &challenges, &mut layouter)?;
        Ok(())
    }
}
