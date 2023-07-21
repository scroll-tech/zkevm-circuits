use std::iter;

use ark_std::test_rng;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, FirstPhase, Instance, Selector},
    poly::Rotation,
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base;
use snark_verifier_sdk::CircuitExt;

use crate::{
    constants::{ACC_LEN, DIGEST_LEN},
    ChunkHash, LOG_DEGREE,
};

/// This config is used to compute RLCs for bytes.
/// It requires a phase 2 column
#[derive(Debug, Clone, Copy)]
pub struct MockConfig {
    pub(crate) phase_1_column: Column<Advice>,
    pub(crate) _selector: Selector,
    /// Instance for public input; stores
    /// - accumulator from aggregation (12 elements); if not fresh
    /// - batch_public_input_hash (32 elements)
    pub(crate) instance: Column<Instance>,
}

impl MockConfig {
    pub(crate) fn load_private(
        &self,
        region: &mut Region<Fr>,
        f: &Fr,
        offset: &mut usize,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        let res = region.assign_advice(
            || "load private",
            self.phase_1_column,
            *offset,
            || Value::known(*f),
        );
        *offset += 1;
        res
    }

    pub(crate) fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let selector = meta.complex_selector();

        // CS requires existence of at least one phase 1 column if we operate on phase 2 columns.
        // This column is not really used.
        let phase_1_column = {
            let column = meta.advice_column_in(FirstPhase);
            meta.enable_equality(column);
            column
        };

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // phase_2_column | advice
        // ---------------|-------
        // a              | q
        // b              | 0
        // c              | 0
        // d              | 0
        //
        // constraint: q*(a*b+c-d) = 0

        meta.create_gate("rlc_gate", |meta| {
            let a = meta.query_advice(phase_1_column, Rotation(0));
            let b = meta.query_advice(phase_1_column, Rotation(1));
            let c = meta.query_advice(phase_1_column, Rotation(2));
            let d = meta.query_advice(phase_1_column, Rotation(3));
            let q = meta.query_selector(selector);
            vec![q * (a * b + c - d)]
        });
        Self {
            phase_1_column,
            _selector: selector,
            instance,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
/// A mock chunk circuit
///
/// This mock chunk circuit simulates a zkEVM circuit.
/// It's public inputs consists of 64 elements:
/// - data hash
/// - public input hash
pub(crate) struct MockChunkCircuit {
    pub(crate) is_fresh: bool,
    pub(crate) _chain_id: u64,
    pub(crate) chunk: ChunkHash,
}

impl MockChunkCircuit {
    #[allow(dead_code)]
    pub(crate) fn new(is_fresh: bool, chain_id: u64, chunk: ChunkHash) -> Self {
        MockChunkCircuit {
            is_fresh,
            _chain_id: chain_id,
            chunk,
        }
    }
}

impl MockChunkCircuit {
    pub(crate) fn random<R: rand::RngCore>(r: &mut R, is_fresh: bool) -> Self {
        Self {
            is_fresh,
            _chain_id: 0,
            chunk: ChunkHash::mock_random_chunk_hash_for_testing(r),
        }
    }
}

impl Circuit<Fr> for MockChunkCircuit {
    type Config = MockConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        meta.set_minimum_degree(4);
        MockConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let mut cells = vec![];

        layouter.assign_region(
            || "mock circuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                let acc_len = if self.is_fresh { 0 } else { ACC_LEN };
                let mut index = 0;
                for (_i, byte) in iter::repeat(0)
                    .take(acc_len)
                    .chain(self.chunk.public_input_hash().as_bytes().iter().copied())
                    .enumerate()
                {
                    let cell = config
                        .load_private(&mut region, &Fr::from(byte as u64), &mut index)
                        .unwrap();
                    cells.push(cell)
                }
                Ok(())
            },
        )?;

        println!("cells len: {}", cells.len());
        for (i, cell) in cells.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, i)?;
        }
        Ok(())
    }
}
impl CircuitExt<Fr> for MockChunkCircuit {
    /// 32 elements from digest
    fn num_instance(&self) -> Vec<usize> {
        let acc_len = if self.is_fresh { 0 } else { ACC_LEN };
        vec![DIGEST_LEN + acc_len]
    }

    /// return vec![data hash | public input hash]
    fn instances(&self) -> Vec<Vec<Fr>> {
        let acc_len = if self.is_fresh { 0 } else { ACC_LEN };
        vec![iter::repeat(0)
            .take(acc_len)
            .chain(self.chunk.public_input_hash().as_bytes().iter().copied())
            .map(|x| Fr::from(x as u64))
            .collect()]
    }
}

#[test]
fn test_mock_chunk_prover() {
    let mut rng = test_rng();

    let circuit = MockChunkCircuit::random(&mut rng, true);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();

    let circuit = MockChunkCircuit::random(&mut rng, false);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();
}
