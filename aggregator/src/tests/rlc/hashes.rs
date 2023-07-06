use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::multi_keccak, KeccakCircuitConfig, KeccakCircuitConfigArgs,
    },
    table::KeccakTable,
    util::{Challenges, SubCircuitConfig},
};

use crate::{
    core::assign_batch_hashes,
    rlc::{rlc, RlcConfig},
    util::capacity,
};

#[derive(Default, Debug, Clone)]
struct DynamicHashCircuit {
    inputs: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DynamicHashCircuitConfig {
    /// Keccak circuit configurations
    pub keccak_circuit_config: KeccakCircuitConfig<Fr>,
    /// RLC config
    pub rlc_config: RlcConfig,
}

impl Circuit<Fr> for DynamicHashCircuit {
    type Config = (DynamicHashCircuitConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // RLC configuration
        let rlc_config = RlcConfig::configure(meta);

        // hash config
        let challenges = Challenges::construct(meta);
        // hash configuration for aggregation circuit
        let keccak_circuit_config = {
            let keccak_table = KeccakTable::construct(meta);
            let challenges_exprs = challenges.exprs(meta);

            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table,
                challenges: challenges_exprs,
            };

            KeccakCircuitConfig::new(meta, keccak_circuit_config_args)
        };

        let config = DynamicHashCircuitConfig {
            rlc_config,
            keccak_circuit_config,
        };

        (config, challenges)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (config, challenges) = config;

        let challenge = challenges.values(&layouter);

        println!("challenge: {:?}", challenge);
        let witness = multi_keccak(&[self.inputs.clone()], challenge, capacity(1 << 19)).unwrap();
        let mut challenge_fr = Fr::zero();
        challenge.keccak_input().map(|x| challenge_fr = x);
        let rlc = rlc(
            &self
                .inputs
                .iter()
                .map(|&x| Fr::from(x as u64))
                .collect::<Vec<_>>(),
            &challenge_fr,
        );
        println!("rlc: {:?}", rlc);
        for row in witness.iter().take(1200) {
            if row.is_final {
                println!("{:?}", row);
                println!("======================");
            }
        }

        // let (hash_input_cells, hash_output_cells) = assign_batch_hashes(
        //     &config.keccak_circuit_config,
        //     &mut layouter,
        //     challenges,
        //     &[self.inputs.clone()],
        // )
        // .unwrap();

        layouter.assign_region(
            || "mock circuit",
            |mut region| {
                config.rlc_config.pad(&mut region, &0)?;
                Ok(())
            },
        )?;
        Ok(())
    }
}

#[test]
fn test_hashes() {
    let k = 19;
    const LEN: usize = 200;
    let a = (0..LEN).map(|x| x as u8).collect::<Vec<u8>>();
    // let a = vec![1; LEN];
    let circuit = DynamicHashCircuit { inputs: a };
    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    // prover.assert_satisfied();

    assert!(false);
}
