//! The EVM circuit implementation.
use halo2::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Column, ConstraintSystem, Error, Fixed, Instance},
};

mod execution;
mod param;
mod step;
mod table;
mod util;

pub use execution::bus_mapping_tmp;
use execution::{bus_mapping_tmp::Block, ExecutionConfig};
use table::{FixedTableTag, LookupTable};

/// EvmCircuit implements verification of execution trace of a block.
#[derive(Clone, Debug)]
pub struct EvmCircuit<F> {
    fixed_table: [Column<Fixed>; 4],
    execution: ExecutionConfig<F>,
}

impl<F: FieldExt> EvmCircuit<F> {
    /// Configure EvmCircuit
    pub fn configure<TxTable, RwTable, BytecodeTable>(
        meta: &mut ConstraintSystem<F>,
        randomness: Column<Instance>,
        tx_table: TxTable,
        rw_table: RwTable,
        bytecode_table: BytecodeTable,
    ) -> Self
    where
        TxTable: LookupTable<F, 4>,
        RwTable: LookupTable<F, 8>,
        BytecodeTable: LookupTable<F, 3>,
    {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());

        let execution = ExecutionConfig::configure(
            meta,
            randomness,
            fixed_table,
            tx_table,
            rw_table,
            bytecode_table,
        );

        Self {
            fixed_table,
            execution,
        }
    }

    /// Load fixed table
    pub fn load_fixed_table(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                for (offset, row) in FixedTableTag::build_all::<F>().enumerate()
                {
                    for (column, value) in
                        self.fixed_table.iter().zip(row.into_iter())
                    {
                        region.assign_fixed(
                            || "",
                            *column,
                            offset,
                            || Ok(value),
                        )?;
                    }
                }

                Ok(())
            },
        )
    }

    /// Assign block
    pub fn assign_block(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        self.execution.assign_block(layouter, block)
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{Block, Bytecode, Rw, Transaction},
        param::STEP_HEIGHT,
        util::RandomLinearCombination,
        EvmCircuit,
    };
    use bus_mapping::eth_types::{ToLittleEndian, Word};
    use halo2::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use pasta_curves::pallas::Base;
    use rand::random;

    pub(crate) fn rand_bytes(n: usize) -> Vec<u8> {
        vec![random(); n]
    }

    pub(crate) fn rand_bytes_array<const N: usize>() -> [u8; N] {
        [(); N].map(|_| random())
    }

    pub(crate) fn rand_word() -> Word {
        Word::from_big_endian(&rand_bytes_array::<32>())
    }

    #[derive(Clone)]
    pub(crate) struct TestCircuitConfig<F> {
        tx_table: [Column<Advice>; 4],
        rw_table: [Column<Advice>; 8],
        bytecode_table: [Column<Advice>; 3],
        evm_circuit: EvmCircuit<F>,
    }

    impl<F: FieldExt> TestCircuitConfig<F> {
        fn load_txs(
            &self,
            _layouter: &mut impl Layouter<F>,
            _txs: &[Transaction<F>],
            _randomness: F,
        ) -> Result<(), Error> {
            Ok(())
        }

        fn load_rws(
            &self,
            layouter: &mut impl Layouter<F>,
            rws: &[Rw],
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "rw table",
                |mut region| {
                    let mut offset = 0;
                    for column in self.rw_table {
                        region.assign_advice(
                            || "rw table all-zero row",
                            column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;

                    for rw in rws.iter() {
                        for (column, value) in self
                            .rw_table
                            .iter()
                            .zip(rw.table_assignment(randomness))
                        {
                            region.assign_advice(
                                || format!("rw table row {}", offset),
                                *column,
                                offset,
                                || Ok(value),
                            )?;
                        }
                        offset += 1;
                    }
                    Ok(())
                },
            )
        }

        fn load_bytecodes(
            &self,
            layouter: &mut impl Layouter<F>,
            bytecodes: &[Bytecode],
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "bytecode table",
                |mut region| {
                    let mut offset = 0;
                    for column in self.bytecode_table {
                        region.assign_advice(
                            || "bytecode table all-zero row",
                            column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;

                    for bytecode in bytecodes.iter() {
                        let hash =
                            RandomLinearCombination::random_linear_combine(
                                bytecode.hash.to_le_bytes(),
                                randomness,
                            );
                        for (idx, byte) in bytecode.bytes.iter().enumerate() {
                            for (column, value) in
                                self.bytecode_table.iter().zip([
                                    hash,
                                    F::from_u64(idx as u64),
                                    F::from_u64(*byte as u64),
                                ])
                            {
                                region.assign_advice(
                                    || format!("bytecode table row {}", offset),
                                    *column,
                                    offset,
                                    || Ok(value),
                                )?;
                            }
                            offset += 1;
                        }
                    }
                    Ok(())
                },
            )
        }
    }

    #[derive(Default)]
    pub(crate) struct TestCircuit<F> {
        block: Block<F>,
    }

    impl<F> TestCircuit<F> {
        pub fn new(block: Block<F>) -> Self {
            Self { block }
        }
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let tx_table = [(); 4].map(|_| meta.advice_column());
            let rw_table = [(); 8].map(|_| meta.advice_column());
            let bytecode_table = [(); 3].map(|_| meta.advice_column());
            let randomness = meta.instance_column();

            Self::Config {
                tx_table,
                rw_table,
                bytecode_table,
                evm_circuit: EvmCircuit::configure(
                    meta,
                    randomness,
                    tx_table,
                    rw_table,
                    bytecode_table,
                ),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.evm_circuit.load_fixed_table(&mut layouter)?;
            config.load_txs(
                &mut layouter,
                &self.block.txs,
                self.block.randomness,
            )?;
            config.load_rws(
                &mut layouter,
                &self.block.rws,
                self.block.randomness,
            )?;
            config.load_bytecodes(
                &mut layouter,
                &self.block.bytecodes,
                self.block.randomness,
            )?;
            config.evm_circuit.assign_block(&mut layouter, &self.block)
        }
    }

    pub(crate) fn try_test_circuit(
        block: Block<Base>,
        result: Result<(), Vec<VerifyFailure>>,
    ) {
        let k = 11;

        let randomness =
            vec![
                block.randomness;
                block.txs.iter().map(|tx| tx.steps.len()).sum::<usize>()
                    * STEP_HEIGHT
            ];
        let circuit = TestCircuit::<Base>::new(block);
        let prover =
            MockProver::<Base>::run(k, &circuit, vec![randomness]).unwrap();

        assert_eq!(prover.verify(), result);
    }
}
