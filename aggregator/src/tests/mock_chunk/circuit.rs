use std::iter;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};

use crate::ChunkHash;

use super::{config::MockPlonkConfig, MockChunkCircuit};

impl MockChunkCircuit {
    pub(crate) fn random<R: rand::RngCore>(r: &mut R, is_fresh: bool) -> Self {
        Self {
            is_fresh,
            chain_id: 0,
            chunk: ChunkHash::mock_chunk_hash(r),
        }
    }
}

impl Circuit<Fr> for MockChunkCircuit {
    type Config = MockPlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        meta.set_minimum_degree(4);
        MockPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "mock circuit",
            |mut region| {
                let acc_len = if self.is_fresh { 0 } else { 12 };

                for (i, byte) in iter::repeat(0)
                    .take(acc_len)
                    .chain(
                        self.chunk
                            .chain_id
                            .to_be_bytes()
                            .iter()
                            .chain(
                                self.chunk
                                    .data_hash
                                    .as_bytes()
                                    .iter()
                                    .chain(self.chunk.public_input_hash().as_bytes().iter()),
                            )
                            .copied(),
                    )
                    .enumerate()
                {
                    // "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
                    region.assign_advice(
                        || "a",
                        config.a,
                        i,
                        || Value::known(Fr::from(byte as u64)),
                    )?;
                    region.assign_advice(|| "b", config.b, i, || Value::known(Fr::zero()))?;
                    region.assign_advice(|| "c", config.c, i, || Value::known(Fr::zero()))?;

                    region.assign_fixed(|| "q_a", config.q_a, i, || Value::known(-Fr::one()))?;
                    region.assign_fixed(|| "q_b", config.q_b, i, || Value::known(Fr::zero()))?;
                    region.assign_fixed(|| "q_c", config.q_c, i, || Value::known(Fr::zero()))?;
                    region.assign_fixed(|| "q_ab", config.q_ab, i, || Value::known(Fr::zero()))?;
                    region.assign_fixed(
                        || "constant",
                        config.constant,
                        i,
                        || Value::known(Fr::zero()),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}
