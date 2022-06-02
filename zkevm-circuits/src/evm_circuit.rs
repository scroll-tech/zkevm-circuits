//! The EVM circuit implementation.

#![allow(missing_docs)]
use halo2_proofs::{circuit::Layouter, plonk::*};

mod execution;
pub mod param;
mod step;
pub(crate) mod util;

pub mod table;
pub mod witness;

use eth_types::Field;
use execution::ExecutionConfig;
use itertools::Itertools;
use table::{FixedTableTag, LookupTable};
use witness::Block;

/// EvmCircuit implements verification of execution trace of a block.
#[derive(Clone, Debug)]
pub struct EvmCircuit<F> {
    fixed_table: [Column<Fixed>; 4],
    byte_table: [Column<Fixed>; 1],
    execution: ExecutionConfig<F>,
}

impl<F: Field> EvmCircuit<F> {
    /// Configure EvmCircuit
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        power_of_randomness: [Expression<F>; 31],
        tx_table: &dyn LookupTable<F>,
        rw_table: &dyn LookupTable<F>,
        bytecode_table: &dyn LookupTable<F>,
        block_table: &dyn LookupTable<F>,
    ) -> Self {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());
        let byte_table = [(); 1].map(|_| meta.fixed_column());

        let execution = ExecutionConfig::configure(
            meta,
            power_of_randomness,
            &fixed_table,
            &byte_table,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
        );

        Self {
            fixed_table,
            byte_table,
            execution,
        }
    }

    /// Load fixed table
    pub fn load_fixed_table(
        &self,
        layouter: &mut impl Layouter<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                for (offset, row) in std::iter::once([F::zero(); 4])
                    .chain(fixed_table_tags.iter().flat_map(|tag| tag.build()))
                    .enumerate()
                {
                    for (column, value) in self.fixed_table.iter().zip_eq(row) {
                        region.assign_fixed(|| "", *column, offset, || Ok(value))?;
                    }
                }

                Ok(())
            },
        )
    }

    /// Load byte table
    pub fn load_byte_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "byte table",
            |mut region| {
                for offset in 0..256 {
                    region.assign_fixed(
                        || "",
                        self.byte_table[0],
                        offset,
                        || Ok(F::from(offset as u64)),
                    )?;
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
        self.execution.assign_block(layouter, block, false)
    }

    /// Assign exact steps in block without padding for unit test purpose
    #[cfg(any(feature = "test", test))]
    pub fn assign_block_exact(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        self.execution.assign_block(layouter, block, true)
    }

    /// Calculate which rows are "actually" used in the circuit
    pub fn get_active_rows(&self, block: &Block<F>) -> (Vec<usize>, Vec<usize>) {
        let max_offset = self.get_num_rows_required(block);
        // some gates are enabled on all rows
        let gates_row_ids = (0..max_offset).collect();
        // lookups are enabled at "q_step" rows and byte lookup rows
        let lookup_row_ids = (0..max_offset).collect();
        (gates_row_ids, lookup_row_ids)
    }

    pub fn get_num_rows_required(&self, block: &Block<F>) -> usize {
        // Start at 1 so we can be sure there is an unused `next` row available
        let mut num_rows = 1;
        for transaction in &block.txs {
            for step in &transaction.steps {
                num_rows += self.execution.get_step_height(step.execution_state);
            }
        }
        num_rows
    }
}

#[cfg(any(feature = "test", test))]
pub mod test {

    use std::convert::TryInto;

    use crate::{
        evm_circuit::{
            table::FixedTableTag,
            witness::{Block, BlockContext, Bytecode, RwMap, Transaction},
            EvmCircuit,
        },
        rw_table::RwTableRlc,
        util::DEFAULT_RAND,
    };
    use eth_types::{Field, Word};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression},
    };
    use itertools::Itertools;
    use rand::{
        distributions::uniform::{SampleRange, SampleUniform},
        random, thread_rng, Rng,
    };
    use strum::IntoEnumIterator;

    pub(crate) fn rand_range<T, R>(range: R) -> T
    where
        T: SampleUniform,
        R: SampleRange<T>,
    {
        thread_rng().gen_range(range)
    }

    pub(crate) fn rand_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|_| random()).collect()
    }

    pub(crate) fn rand_bytes_array<const N: usize>() -> [u8; N] {
        [(); N].map(|_| random())
    }

    pub(crate) fn rand_word() -> Word {
        Word::from_big_endian(&rand_bytes_array::<32>())
    }

    #[derive(Clone)]
    pub struct TestCircuitConfig<F> {
        tx_table: [Column<Advice>; 4],
        rw_table: RwTableRlc,
        bytecode_table: [Column<Advice>; 5],
        block_table: [Column<Advice>; 3],
        evm_circuit: EvmCircuit<F>,
    }

    impl<F: Field> TestCircuitConfig<F> {
        fn load_txs(
            &self,
            layouter: &mut impl Layouter<F>,
            txs: &[Transaction],
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "tx table",
                |mut region| {
                    let mut offset = 0;
                    for column in self.tx_table {
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
                            for (column, value) in self.tx_table.iter().zip_eq(row) {
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
            rws: &RwMap,
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "rw table",
                |mut region| {
                    let mut offset = 0;
                    self.rw_table
                        .assign(&mut region, offset, &Default::default(), randomness)?;
                    offset += 1;

                    let mut rows = rws
                        .0
                        .values()
                        .flat_map(|rws| rws.iter())
                        .collect::<Vec<_>>();

                    rows.sort_by_key(|a| a.rw_counter());
                    let mut expected_rw_counter = 1;
                    for rw in rows {
                        assert!(rw.rw_counter() == expected_rw_counter);
                        expected_rw_counter += 1;

                        self.rw_table.assign(
                            &mut region,
                            offset,
                            &rw.table_assignment(randomness),
                            randomness,
                        )?;
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
                            for (column, value) in self.bytecode_table.iter().zip_eq(row) {
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

        fn load_block(
            &self,
            layouter: &mut impl Layouter<F>,
            block: &BlockContext,
            randomness: F,
        ) -> Result<(), Error> {
            layouter.assign_region(
                || "block table",
                |mut region| {
                    let mut offset = 0;
                    for column in self.block_table {
                        region.assign_advice(
                            || "block table all-zero row",
                            column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;

                    for row in block.table_assignments(randomness) {
                        for (column, value) in self.block_table.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("block table row {}", offset),
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
    }

    #[derive(Default)]
    pub struct TestCircuit<F> {
        block: Block<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    }

    impl<F> TestCircuit<F> {
        pub fn new(block: Block<F>, fixed_table_tags: Vec<FixedTableTag>) -> Self {
            Self {
                block,
                fixed_table_tags,
            }
        }
    }

    impl<F: Field> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let tx_table = [(); 4].map(|_| meta.advice_column());
            let rw_table = RwTableRlc::construct(meta);
            let bytecode_table = [(); 5].map(|_| meta.advice_column());
            let block_table = [(); 3].map(|_| meta.advice_column());

            let power_of_randomness: [Expression<F>; 31] = (1..32)
                .map(|exp| Expression::Constant(F::from_u128(DEFAULT_RAND).pow(&[exp, 0, 0, 0])))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            Self::Config {
                tx_table,
                rw_table,
                bytecode_table,
                block_table,
                evm_circuit: EvmCircuit::configure(
                    meta,
                    power_of_randomness,
                    &tx_table,
                    &rw_table,
                    &bytecode_table,
                    &block_table,
                ),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config
                .evm_circuit
                .load_fixed_table(&mut layouter, self.fixed_table_tags.clone())?;
            config.evm_circuit.load_byte_table(&mut layouter)?;
            config.load_txs(&mut layouter, &self.block.txs, self.block.randomness)?;
            config.load_rws(&mut layouter, &self.block.rws, self.block.randomness)?;
            config.load_bytecodes(&mut layouter, &self.block.bytecodes, self.block.randomness)?;
            config.load_block(&mut layouter, &self.block.context, self.block.randomness)?;
            if self.block.pad_to != 0 {
                config.evm_circuit.assign_block(&mut layouter, &self.block)
            } else {
                config
                    .evm_circuit
                    .assign_block_exact(&mut layouter, &self.block)
            }?;
            Ok(())
        }
    }

    impl<F: Field> TestCircuit<F> {
        pub fn get_num_rows_required(block: &Block<F>) -> usize {
            let mut cs = ConstraintSystem::default();
            let config = TestCircuit::configure(&mut cs);
            config.evm_circuit.get_num_rows_required(block)
        }

        pub fn get_active_rows(block: &Block<F>) -> (Vec<usize>, Vec<usize>) {
            let mut cs = ConstraintSystem::default();
            let config = TestCircuit::configure(&mut cs);
            config.evm_circuit.get_active_rows(block)
        }
    }

    pub fn run_test_circuit<F: Field>(
        block: Block<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Vec<VerifyFailure>> {
        let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;

        let num_rows_required_for_steps = TestCircuit::get_num_rows_required(&block);

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
        let k = k.max(log2_ceil(64 + num_rows_required_for_steps));
        log::debug!("evm circuit uses k = {}", k);
        let (active_gate_rows, active_lookup_rows) = TestCircuit::get_active_rows(&block);
        let block = block;
        //block.pad_to = (1 << k) - 64;
        let circuit = TestCircuit::<F>::new(block, fixed_table_tags);
        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        prover.verify_at_rows(active_gate_rows.into_iter(), active_lookup_rows.into_iter())
    }

    pub fn run_test_circuit_incomplete_fixed_table<F: Field>(
        block: Block<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        run_test_circuit(
            block,
            vec![
                FixedTableTag::Zero,
                FixedTableTag::Range5,
                FixedTableTag::Range16,
                FixedTableTag::Range32,
                FixedTableTag::Range64,
                FixedTableTag::Range256,
                FixedTableTag::Range512,
                FixedTableTag::Range1024,
                FixedTableTag::SignByte,
                FixedTableTag::ResponsibleOpcode,
            ],
        )
    }

    pub fn run_test_circuit_complete_fixed_table<F: Field>(
        block: Block<F>,
    ) -> Result<(), Vec<VerifyFailure>> {
        run_test_circuit(block, FixedTableTag::iter().collect())
    }
}
