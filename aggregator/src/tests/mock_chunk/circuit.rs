use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use zkevm_circuits::util::{Challenges, SubCircuitConfig};

use crate::ChunkHash;

use super::{
    config::{MockChunkCircuitConfig, MockChunkCircuitConfigArgs},
    MockChunkCircuit,
};

impl MockChunkCircuit {
    pub(crate) fn random<R: rand::RngCore>(r: &mut R) -> Self {
        Self {
            chain_id: 0,
            chunk: ChunkHash::mock_chunk_hash(r),
        }
    }

    /// Public input hash for a given chunk is defined as
    ///  keccak( chain id || prev state root || post state root || withdraw root || data hash )
    fn extract_hash_preimages(&self) -> Vec<u8> {
        self.chunk.extract_hash_preimage()
    }
}

impl Circuit<Fr> for MockChunkCircuit {
    type FloorPlanner = SimpleFloorPlanner;

    type Config = (MockChunkCircuitConfig, Challenges);

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenges_exprs = challenges.exprs(meta);
        let args = MockChunkCircuitConfigArgs {
            challenges: challenges_exprs,
        };
        let config = MockChunkCircuitConfig::new(meta, args);
        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (config, challenge) = config;
        let challenges = challenge.values(&layouter);

        // extract all the hashes and load them to the hash table
        let timer = start_timer!(|| ("extract hash").to_string());
        let preimages = self.extract_hash_preimages();
        end_timer!(timer);

        let timer = start_timer!(|| ("load aux table").to_string());
        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;
        end_timer!(timer);

        let timer = start_timer!(|| ("assign cells").to_string());
        config.assign(&mut layouter, challenges, &preimages)?;
        end_timer!(timer);
        Ok(())
    }
}
