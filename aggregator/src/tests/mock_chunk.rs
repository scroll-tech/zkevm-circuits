use std::iter;

use ark_std::test_rng;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::SKIP_FIRST_PASS;
use snark_verifier_sdk::CircuitExt;
use zkevm_circuits::util::Challenges;

use crate::{
    constants::{ACC_LEN, DIGEST_LEN},
    ChunkHash, RlcConfig, LOG_DEGREE,
};

/// This config is used to compute RLCs for bytes.
/// It requires a phase 2 column
#[derive(Debug, Clone, Copy)]
pub struct MockConfig {
    pub(crate) rlc_config: RlcConfig,
    /// Instance for public input; stores
    /// - accumulator from aggregation (12 elements); if not fresh
    /// - batch_public_input_hash (32 elements)
    pub(crate) instance: Column<Instance>,
}

#[derive(Debug, Default, Clone, Copy)]
/// A mock chunk circuit
///
/// This mock chunk circuit simulates a zkEVM circuit.
/// It's public inputs consists of 32 elements:
/// - public input hash
#[allow(dead_code)]
pub(crate) struct MockChunkCircuit {
    // This circuit has an accumulator if it has already gone through compression
    pub(crate) has_accumulator: bool,
    pub(crate) is_padding: bool,
    pub(crate) chunk: ChunkHash,
}

impl MockChunkCircuit {
    #[allow(dead_code)]
    pub(crate) fn new(has_accumulator: bool, chunk: ChunkHash) -> Self {
        MockChunkCircuit {
            has_accumulator,
            is_padding: chunk.is_padding,
            chunk,
        }
    }
}

impl MockChunkCircuit {
    pub(crate) fn random<R: rand::RngCore>(
        r: &mut R,
        has_accumulator: bool,
        is_padding: bool,
    ) -> Self {
        let chunk = ChunkHash::mock_random_chunk_hash_for_testing(r);
        Self {
            has_accumulator,
            is_padding,
            chunk: if is_padding {
                ChunkHash::mock_padded_chunk_hash_for_testing(&chunk)
            } else {
                chunk
            },
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

        let challenges = Challenges::construct(meta);
        let rlc_config = RlcConfig::configure(meta, challenges);
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        MockConfig {
            rlc_config,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let mut first_pass = SKIP_FIRST_PASS;

        let cells = layouter.assign_region(
            || "mock circuit",
            |mut region| -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }
                let mut cells = vec![];
                let mut index = 0;
                let acc_len = if self.has_accumulator { ACC_LEN } else { 0 };

                for byte in iter::repeat(0)
                    .take(acc_len)
                    .chain(self.chunk.public_input_hash().as_bytes().iter().copied())
                {
                    let cell = config
                        .rlc_config
                        .load_private(&mut region, &Fr::from(byte as u64), &mut index)
                        .unwrap();
                    cells.push(cell)
                }
                Ok(cells)
            },
        )?;

        log::trace!("cells len: {}", cells.len());
        for (i, cell) in cells.into_iter().enumerate() {
            layouter.constrain_instance(cell.cell(), config.instance, i)?;
        }
        Ok(())
    }
}

impl CircuitExt<Fr> for MockChunkCircuit {
    /// 32 elements from digest
    fn num_instance(&self) -> Vec<usize> {
        let acc_len = if self.has_accumulator { ACC_LEN } else { 0 };
        vec![DIGEST_LEN + acc_len]
    }

    /// return vec![acc | public input hash]
    fn instances(&self) -> Vec<Vec<Fr>> {
        let acc_len = if self.has_accumulator { ACC_LEN } else { 0 };
        vec![iter::repeat(0)
            .take(acc_len)
            .chain(self.chunk.public_input_hash().as_bytes().iter().copied())
            .map(|x| Fr::from(x as u64))
            .collect()]
    }
}

#[test]
fn test_mock_chunk_prover() {
    test_mock_chunk_prover_helper(true, true);
    test_mock_chunk_prover_helper(true, false);
    test_mock_chunk_prover_helper(false, true);
    test_mock_chunk_prover_helper(false, false);
}

fn test_mock_chunk_prover_helper(hash_accumulator: bool, is_padding: bool) {
    let mut rng = test_rng();

    let circuit = MockChunkCircuit::random(&mut rng, hash_accumulator, is_padding);
    let instance = circuit.instances();

    let mock_prover = MockProver::<Fr>::run(LOG_DEGREE, &circuit, instance).unwrap();

    mock_prover.assert_satisfied_par();
}
