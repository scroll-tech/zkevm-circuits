#![cfg(feature = "circuits")]

use bus_mapping::circuit_input_builder::BuilderClient;
use halo2::dev::MockProver;
use integration_tests::{get_client, log_init, GenDataOutput};
use lazy_static::lazy_static;
use log::trace;
use zkevm_circuits::evm_circuit::witness::block_convert;
use zkevm_circuits::state_circuit::StateCircuit;

lazy_static! {
    pub static ref GEN_DATA: GenDataOutput = GenDataOutput::load();
}

/// This module contains a definition of a Circuit for the EVM Circuit that can
/// be used for testing.  This is required because there's no public directly
/// usable EVM Circuit yet.  The code in this module is copied from
/// `zkevm_circuits::evm_circuit::test` at `zkevm-circuits/src/evm_circuit.rs`.
mod test_evm_circuit {
    use halo2::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::*,
        poly::Rotation,
    };
    use zkevm_circuits::evm_circuit::{
        param::STEP_HEIGHT,
        table::FixedTableTag,
        witness::{Block, Bytecode, Rw, Transaction},
        EvmCircuit,
    };

    #[derive(Clone)]
    struct TestCircuitConfig<F> {
        tx_table: [Column<Advice>; 4],
        rw_table: [Column<Advice>; 10],
        bytecode_table: [Column<Advice>; 4],
        evm_circuit: EvmCircuit<F>,
    }

    impl<F: FieldExt> TestCircuitConfig<F> {
        fn load_txs(
            &self,
            layouter: &mut impl Layouter<F>,
            txs: &[Transaction<F>],
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "tx table",
                |mut region| {
                    let mut offset = 0;
                    for column in self.rw_table {
                        region.assign_advice(
                            || "tx table all-zero row",
                            column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;

                    for tx in txs.iter() {
                        for row in tx.table_assignments(randomness) {
                            for (column, value) in self.tx_table.iter().zip(row)
                            {
                                region.assign_advice(
                                    || format!("tx table row {}", offset),
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
                        for row in bytecode.table_assignments(randomness) {
                            for (column, value) in
                                self.bytecode_table.iter().zip(row)
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
    struct TestCircuit<F> {
        block: Block<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    }

    impl<F> TestCircuit<F> {
        fn new(block: Block<F>, fixed_table_tags: Vec<FixedTableTag>) -> Self {
            Self {
                block,
                fixed_table_tags,
            }
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
            let rw_table = [(); 10].map(|_| meta.advice_column());
            let bytecode_table = [(); 4].map(|_| meta.advice_column());
            let block_table = [(); 3].map(|_| meta.advice_column());

            let power_of_randomness = {
                let columns = [(); 31].map(|_| meta.instance_column());
                let mut power_of_randomness = None;

                meta.create_gate("", |meta| {
                    power_of_randomness = Some(columns.map(|column| {
                        meta.query_instance(column, Rotation::cur())
                    }));

                    [Expression::Constant(F::zero())]
                });

                power_of_randomness.unwrap()
            };

            Self::Config {
                tx_table,
                rw_table,
                bytecode_table,
                evm_circuit: EvmCircuit::configure(
                    meta,
                    power_of_randomness,
                    tx_table,
                    rw_table,
                    bytecode_table,
                    block_table,
                ),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.evm_circuit.load_fixed_table(
                &mut layouter,
                self.fixed_table_tags.clone(),
            )?;
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

    pub fn run_test_circuit_complete_fixed_table<F: FieldExt>(
        block: Block<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        run_test_circuit(block, FixedTableTag::iterator().collect())
    }

    fn run_test_circuit<F: FieldExt>(
        block: Block<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let log2_ceil = |n| {
            u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32
        };

        let k = log2_ceil(
            64 + fixed_table_tags
                .iter()
                .map(|tag| tag.build::<F>().count())
                .sum::<usize>(),
        );
        let k = k.max(log2_ceil(
            64 + block
                .bytecodes
                .iter()
                .map(|bytecode| bytecode.bytes.len())
                .sum::<usize>(),
        ));

        let randomness =
            vec![
                block.randomness;
                block.txs.iter().map(|tx| tx.steps.len()).sum::<usize>()
                    * STEP_HEIGHT
            ];
        let circuit = TestCircuit::<F>::new(block, fixed_table_tags);

        let prover =
            MockProver::<F>::run(k, &circuit, vec![randomness]).unwrap();
        prover.verify()
    }
}

#[tokio::test]
async fn test_evm_circuit_block_a() {
    use test_evm_circuit::*;

    log_init();
    let (block_num, _address) = GEN_DATA.deployments.get("Greeter").unwrap();
    let cli = get_client();

    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli.gen_inputs(*block_num).await.unwrap();

    // Generate evm_circuit proof
    let code_hash = builder.block.txs()[0].calls()[0].code_hash;
    let bytecode = builder
        .code_db
        .0
        .get(&code_hash)
        .expect("code_hash not found");
    let block = block_convert(bytecode, &builder.block);
    run_test_circuit_complete_fixed_table(block)
        .expect("evm_circuit verification failed");
}

#[tokio::test]
async fn test_state_circuit_block_a() {
    log_init();
    let (block_num, _address) = GEN_DATA.deployments.get("Greeter").unwrap();
    let cli = get_client();

    let cli = BuilderClient::new(cli).await.unwrap();
    let builder = cli.gen_inputs(*block_num).await.unwrap();

    // Generate state proof
    let stack_ops = builder.block.container.sorted_stack();
    trace!("stack_ops: {:#?}", stack_ops);
    let memory_ops = builder.block.container.sorted_memory();
    trace!("memory_ops: {:#?}", memory_ops);
    let storage_ops = builder.block.container.sorted_storage();
    trace!("storage_ops: {:#?}", storage_ops);

    const DEGREE: usize = 16;
    const MEMORY_ADDRESS_MAX: usize = 2000;
    const STACK_ADDRESS_MAX: usize = 1300;

    const MEMORY_ROWS_MAX: usize = 1 << (DEGREE - 2);
    const STACK_ROWS_MAX: usize = 1 << (DEGREE - 2);
    const STORAGE_ROWS_MAX: usize = 1 << (DEGREE - 2);
    const GLOBAL_COUNTER_MAX: usize =
        MEMORY_ROWS_MAX + STACK_ROWS_MAX + STORAGE_ROWS_MAX;

    let circuit = StateCircuit::<
        GLOBAL_COUNTER_MAX,
        MEMORY_ROWS_MAX,
        MEMORY_ADDRESS_MAX,
        STACK_ROWS_MAX,
        STACK_ADDRESS_MAX,
        STORAGE_ROWS_MAX,
    > {
        memory_ops,
        stack_ops,
        storage_ops,
    };

    use pairing::bn256::Fr as Fp;
    let prover =
        MockProver::<Fp>::run(DEGREE as u32, &circuit, vec![]).unwrap();
    prover.verify().expect("state_circuit verification failed");
}
