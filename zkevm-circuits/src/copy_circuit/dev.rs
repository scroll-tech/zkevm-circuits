pub use super::CopyCircuit;

use crate::{
    copy_circuit::{CopyCircuitConfig, CopyCircuitConfigArgs},
    table::{BytecodeTable, CopyTable, RwTable, TxTable},
    util::{Challenges, Field, SubCircuit, SubCircuitConfig},
    witness::Block,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Challenge, Circuit, ConstraintSystem, Error},
};

impl<F: Field> Circuit<F> for CopyCircuit<F> {
    type Config = (CopyCircuitConfig<F>, Challenges<Challenge>);
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = TxTable::construct(meta);
        let rw_table = RwTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        #[cfg(feature = "dual_bytecode")]
        let bytecode_table1 = BytecodeTable::construct(meta);

        let q_enable = meta.fixed_column();
        let copy_table = CopyTable::construct(meta, q_enable);
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);

        (
            CopyCircuitConfig::new(
                meta,
                CopyCircuitConfigArgs {
                    tx_table,
                    rw_table,
                    bytecode_table,
                    #[cfg(feature = "dual_bytecode")]
                    bytecode_table1,
                    copy_table,
                    q_enable,
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenge_values = config.1.values(&layouter);

        config.0.tx_table.load(
            &mut layouter,
            &self.external_data.txs,
            self.external_data.max_txs,
            self.external_data.max_calldata,
            0, // chain id
            &challenge_values,
        )?;

        config.0.rw_table.load(
            &mut layouter,
            &self.external_data.rws.table_assignments(),
            self.external_data.max_rws,
            challenge_values.evm_word(),
        )?;

        #[cfg(not(feature = "dual_bytecode"))]
        config.0.bytecode_table.dev_load(
            &mut layouter,
            self.external_data.bytecodes.values(),
            &challenge_values,
        )?;

        // when enable feature "dual_bytecode", get two sets of bytecodes here.
        #[cfg(feature = "dual_bytecode")]
        {
            let (first_bytecodes, second_bytecodes) = Block::split_bytecodes_for_dual_sub_circuits(
                &self.external_data.bytecodes,
                &self.bytecode_map,
            );
            config
                .0
                .bytecode_table
                .dev_load(&mut layouter, first_bytecodes, &challenge_values)?;
            config.0.bytecode_table1.dev_load(
                &mut layouter,
                second_bytecodes,
                &challenge_values,
            )?;
        }
        self.synthesize_sub(&config.0, &challenge_values, &mut layouter)
    }
}
