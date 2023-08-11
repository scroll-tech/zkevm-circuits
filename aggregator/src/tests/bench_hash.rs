use ark_std::{end_timer, start_timer, test_rng};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::multi_keccak, KeccakCircuitConfig, KeccakCircuitConfigArgs,
    },
    table::{KeccakTable, LookupTable},
    util::{Challenges, SubCircuitConfig},
};

use crate::{
    constants::{LOG_DEGREE, ROWS_PER_ROUND},
    util::keccak_round_capacity,
};

#[derive(Default, Debug, Clone)]
struct HashCircuit {
    inputs: Vec<u8>,
}

#[derive(Debug, Clone)]
struct HashCircuitConfig {
    /// Keccak circuit configurations
    pub keccak_circuit_config: KeccakCircuitConfig<Fr>,
}

impl Circuit<Fr> for HashCircuit {
    type Config = (HashCircuitConfig, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);

        // hash config
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
        // enable equality for the data RLC column
        meta.enable_equality(keccak_circuit_config.keccak_table.input_rlc);

        let config = HashCircuitConfig {
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

        config
            .keccak_circuit_config
            .load_aux_tables(&mut layouter)?;

        let challenge = challenges.values(&layouter);

        let hash_preimage = self
            .inputs
            .iter()
            .chain(vec![0; 320 - self.inputs.len()].iter())
            .copied()
            .collect::<Vec<_>>();

        let witness = multi_keccak(
            &[hash_preimage.clone()],
            challenge,
            keccak_round_capacity(1 << LOG_DEGREE),
        )
        .unwrap();

        layouter.assign_region(
            || "mock circuit",
            |mut region| -> Result<(), Error> {
                let mut data_rlc_cells = vec![];
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row =
                        config
                            .keccak_circuit_config
                            .set_row(&mut region, offset, keccak_row)?;
                    if offset % ROWS_PER_ROUND == 0 && data_rlc_cells.len() < 4 {
                        // second element is data rlc
                        data_rlc_cells.push(row[1].clone());
                    }
                }
                config
                    .keccak_circuit_config
                    .keccak_table
                    .annotate_columns_in_region(&mut region);
                config.keccak_circuit_config.annotate_circuit(&mut region);

                Ok(())
            },
        )?;
        Ok(())
    }
}

impl CircuitExt<Fr> for HashCircuit {}

#[test]
fn bench_hash() {
    let params = gen_srs(LOG_DEGREE);
    let mut rng = test_rng();
    const LEN: usize = 100;

    let a = (0..LEN).map(|x| x as u8).collect::<Vec<u8>>();
    let circuit = HashCircuit { inputs: a };

    let pk = gen_pk(&params, &circuit, None);
    let prover_timer = start_timer!(|| "proving");
    let snark = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
    end_timer!(prover_timer);
    let verifier_timer = start_timer!(|| "verify");
    assert!(verify_snark_shplonk::<HashCircuit>(
        &params,
        snark,
        pk.get_vk()
    ));
    end_timer!(verifier_timer);
}
