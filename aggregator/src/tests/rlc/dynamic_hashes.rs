use ark_std::test_rng;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier_sdk::{gen_pk, gen_snark_shplonk, verify_snark_shplonk, CircuitExt};
use zkevm_circuits::{
    keccak_circuit::{
        keccak_packed_multi::{self, multi_keccak},
        KeccakCircuit, KeccakCircuitConfig, KeccakCircuitConfigArgs,
    },
    table::{KeccakTable, LookupTable},
    util::{Challenges, SubCircuitConfig},
};

use crate::{aggregation::RlcConfig, constants::LOG_DEGREE};

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
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let challenges = Challenges::construct(meta);

        // RLC configuration
        let rlc_config = RlcConfig::configure(meta, challenges);

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
        let keccak_f_rows = keccak_packed_multi::get_num_rows_per_update();

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
            KeccakCircuit::<Fr>::capacity_for_row(1 << LOG_DEGREE),
        )
        .unwrap();

        layouter.assign_region(
            || "mock circuit",
            |mut region| -> Result<(), Error> {
                config.rlc_config.init(&mut region)?;

                // ==============================
                // keccak part
                // ==============================
                let mut data_rlc_cells = vec![];
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row =
                        config
                            .keccak_circuit_config
                            .set_row(&mut region, offset, keccak_row)?;
                    if offset % keccak_f_rows == 0 && data_rlc_cells.len() < 4 {
                        // second element is data rlc
                        data_rlc_cells.push(row[1].clone());
                    }
                }
                config
                    .keccak_circuit_config
                    .keccak_table
                    .annotate_columns_in_region(&mut region);
                config.keccak_circuit_config.annotate_circuit(&mut region);

                // ==============================
                // rlc part
                // ==============================
                let mut offset = 0;
                let challenge = {
                    let mut tmp = Fr::zero();
                    challenge.keccak_input().map(|x| tmp = x);
                    config
                        .rlc_config
                        .load_private(&mut region, &tmp, &mut offset)?
                };

                let rlc_inputs = hash_preimage
                    .iter()
                    .map(|&x| {
                        config
                            .rlc_config
                            .load_private(&mut region, &Fr::from(x as u64), &mut offset)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();

                let rlc_cell =
                    config
                        .rlc_config
                        .rlc(&mut region, &rlc_inputs, &challenge, &mut offset)?;

                // rlc should be either one of data_rlc_cells[1], data_rlc_cells[2] and
                // data_rlc_cells[3] so we compute
                //   prod = (data_rlc_cells[1]-rlc)
                //        * (data_rlc_cells[2]-rlc)
                //        * (data_rlc_cells[3]-rlc)
                // and constraint prod is zero
                let tmp1 = config.rlc_config.sub(
                    &mut region,
                    &data_rlc_cells[1],
                    &rlc_cell,
                    &mut offset,
                )?;
                let tmp2 = config.rlc_config.sub(
                    &mut region,
                    &data_rlc_cells[2],
                    &rlc_cell,
                    &mut offset,
                )?;
                let tmp3 = config.rlc_config.sub(
                    &mut region,
                    &data_rlc_cells[3],
                    &rlc_cell,
                    &mut offset,
                )?;
                let tmp = config
                    .rlc_config
                    .mul(&mut region, &tmp1, &tmp2, &mut offset)?;
                let tmp = config
                    .rlc_config
                    .mul(&mut region, &tmp, &tmp3, &mut offset)?;

                config.rlc_config.enforce_zero(&mut region, &tmp)?;

                Ok(())
            },
        )?;
        Ok(())
    }
}

impl CircuitExt<Fr> for DynamicHashCircuit {}

#[test]
fn test_hash_circuit() {
    const LEN: usize = 100;
    let a = (0..LEN).map(|x| x as u8).collect::<Vec<u8>>();
    let circuit = DynamicHashCircuit { inputs: a };
    let prover = MockProver::run(LOG_DEGREE, &circuit, vec![]).unwrap();
    prover.assert_satisfied_par();
    println!("circuit satisfied");
}

#[ignore = "it takes too much time"]
#[test]
fn test_dynamic_hash_circuit() {
    let params = gen_srs(LOG_DEGREE);
    let mut rng = test_rng();
    const LEN: usize = 100;

    let a = (0..LEN).map(|x| x as u8).collect::<Vec<u8>>();
    let circuit = DynamicHashCircuit { inputs: a };
    let prover = MockProver::run(LOG_DEGREE, &circuit, vec![]).unwrap();
    prover.assert_satisfied_par();
    println!("circuit satisfied");

    let pk = gen_pk(&params, &circuit, None);

    // pk verifies the original circuit
    {
        let snark = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
        assert!(verify_snark_shplonk::<DynamicHashCircuit>(
            &params,
            snark,
            pk.get_vk()
        ));
        println!("1 round keccak verified with same pk");
    }
    // pk verifies the circuit with 3 round of keccak
    {
        let a: Vec<u8> = (0..LEN * 3).map(|x| x as u8).collect::<Vec<u8>>();
        let circuit = DynamicHashCircuit { inputs: a };

        let snark = gen_snark_shplonk(&params, &pk, circuit, &mut rng, None::<String>);
        assert!(verify_snark_shplonk::<DynamicHashCircuit>(
            &params,
            snark,
            pk.get_vk()
        ));
        println!("3 round keccak verified with same pk");
    }
}
