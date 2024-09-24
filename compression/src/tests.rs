use std::{fmt::write, path::{Path, PathBuf}};
use rand::{
    RngCore,
    rngs::OsRng
};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::gen_snark_shplonk as old_gen_snark_shplonk;
use ce_snark_verifier_sdk::{
    evm::{gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
    gen_pk,
    halo2::{aggregation::{AggregationCircuit, AggregationConfigParams, VerifierUniversality}, gen_snark_shplonk},
    Snark,
    CircuitExt, SHPLONK
};
use ce_snark_verifier::halo2_base::{
    gates::circuit::CircuitBuilderStage,
    halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
        poly::Rotation,
    },
    utils::fs::gen_srs,
};
use ark_std::test_rng;
use halo2_proofs::dev::MockProver;
use crate::{params, CompressionCircuit};
use crate::circuit::to_ce_snark;
use aggregator::MockChunkCircuit;

fn gen_rng() -> impl rand::Rng + Send {
    use rand::SeedableRng;
    let seed = [0u8; 16];
    rand_xorshift::XorShiftRng::from_seed(seed)
}

#[derive(Clone, Copy)]
pub struct StandardPlonkConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    q_a: Column<Fixed>,
    q_b: Column<Fixed>,
    q_c: Column<Fixed>,
    q_ab: Column<Fixed>,
    constant: Column<Fixed>,
    #[allow(dead_code)]
    instance: Column<Instance>,
}

impl StandardPlonkConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let [a, b, c] = [(); 3].map(|_| meta.advice_column());
        let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
        let instance = meta.instance_column();

        [a, b, c].map(|column| meta.enable_equality(column));

        meta.create_gate(
            "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
            |meta| {
                let [a, b, c] =
                    [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                    .map(|column| meta.query_fixed(column, Rotation::cur()));
                let instance = meta.query_instance(instance, Rotation::cur());
                Some(
                    q_a * a.clone()
                        + q_b * b.clone()
                        + q_c * c
                        + q_ab * a * b
                        + constant
                        + instance,
                )
            },
        );

        StandardPlonkConfig { a, b, c, q_a, q_b, q_c, q_ab, constant, instance }
    }
}

#[derive(Clone, Default)]
pub struct StandardPlonk(Fr);

impl StandardPlonk {
    pub fn rand<R: RngCore>(mut rng: R) -> Self {
        Self(Fr::from(rng.next_u32() as u64))
    }
}

impl CircuitExt<Fr> for StandardPlonk {
    fn num_instance(&self) -> Vec<usize> {
        vec![1]
    }

    fn instances(&self) -> Vec<Vec<Fr>> {
        vec![vec![self.0]]
    }
}

impl Circuit<Fr> for StandardPlonk {
    type Config = StandardPlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        meta.set_minimum_degree(4);
        StandardPlonkConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "",
            |mut region| {
                region.assign_advice(|| "", config.a, 0, || Value::known(self.0))?;
                region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::one()))?;
                region.assign_advice(
                    || "",
                    config.a,
                    1,
                    || Value::known(-Fr::from(5u64)),
                )?;
                for (idx, column) in (1..).zip([
                    config.q_a,
                    config.q_b,
                    config.q_c,
                    config.q_ab,
                    config.constant,
                ]) {
                    region.assign_fixed(
                        || "",
                        column,
                        1,
                        || Value::known(Fr::from(idx as u64)),
                    )?;
                }
                let a =
                    region.assign_advice(|| "", config.a, 2, || Value::known(Fr::one()))?;
                a.copy_advice(|| "", &mut region, config.b, 3)?;
                a.copy_advice(|| "", &mut region, config.c, 4)?;

                Ok(())
            },
        )
    }
}

fn gen_application_snark(params: &ParamsKZG<Bn256>) -> Snark {
    let circuit = StandardPlonk::rand(OsRng);

    let pk = gen_pk(params, &circuit, None);
    gen_snark_shplonk(params, &pk, circuit, None::<&str>)
}

#[test]
fn test_standard_plonk_compression() {
    let params_app = gen_srs(8);

    let k = 21u32;
    let params = gen_srs(k);
    let snarks = [(); 1].map(|_| gen_application_snark(&params_app));

    let layer1_agg_params = AggregationConfigParams {
        degree: 21,
        num_advice: 15,
        num_lookup_advice: 2,
        num_fixed: 1,
        lookup_bits: 20,
    };

    let rng = test_rng();
    let compression_circuit = CompressionCircuit::new_from_ce_snark(layer1_agg_params, &params, snarks[0].clone(), false, rng).unwrap();
    let num_instances = compression_circuit.num_instance();
    let instances = compression_circuit.instances();

    println!("num_instances {:?}", num_instances);
    println!("instance length {:?}", instances.len());

    let mock_prover = MockProver::<Fr>::run(k, &compression_circuit, instances).unwrap();

    mock_prover.assert_satisfied_par();
}

#[test]
fn test_mock_compression() {
    let k0 = 8u32;
    let params_app = gen_srs(k0);

    let circuit = MockChunkCircuit::random(OsRng, false, false);

    let pk = gen_pk(&params_app, &circuit, None);

    let mut rng = test_rng();
    let old_snark = old_gen_snark_shplonk(&params_app, &pk, circuit, &mut rng, None::<String>).unwrap();

    let k1 = 21u32;
    let params = gen_srs(k1);

    let layer1_agg_params = AggregationConfigParams {
        degree: 21,
        num_advice: 15,
        num_lookup_advice: 2,
        num_fixed: 1,
        lookup_bits: 20,
    };

    let mut rng = test_rng();
    let compression_circuit =
        CompressionCircuit::new_from_ce_snark(layer1_agg_params, &params, to_ce_snark(&old_snark), false, &mut rng).unwrap();
    let instance = compression_circuit.instances();
    println!("instance length {:?}", instance.len());

    let mock_prover = MockProver::<Fr>::run(k1, &compression_circuit, instance).unwrap();

    mock_prover.assert_satisfied_par()
}

fn dump_snark(path: &str, path2: &str, snark: &Snark) {
    let mut fd = std::fs::File::create(path).expect("File::create: should be OK");
    serde_json::to_writer(&mut fd, snark).expect("serde_json::to_writer: should be OK");
    let mut fd = std::fs::File::create(path2).expect("File::create: should be OK");
    serde_json::to_writer(&mut fd, &snark.protocol).expect("serde_json::to_writer: should be OK");
}

#[test]
fn test_two_layer_compression() {
    // Generate base layer snark
    // let k0 = 8u32;
    // let params_app = gen_srs(k0);
    // let circuit = MockChunkCircuit::random(OsRng, false, false);

    // let pk_layer0 = gen_pk(&params_app, &circuit, None);
    // let mut rng = test_rng();
    // let old_snark = old_gen_snark_shplonk(&params_app, &pk_layer0, circuit, &mut rng, None::<String>).unwrap();

    // Generate base layer snark
    let params_app = gen_srs(8);
    let k = 21u32;
    let params = gen_srs(k);
    let inner_snark = gen_application_snark(&params_app);
    dump_snark("./src/layer0.json", "./src/layer0_protocol.json", &inner_snark);
    let mut rng = gen_rng();

    // First layer of compression
    let layer1_agg_params = AggregationConfigParams {
        degree: 21,
        num_advice: 15,
        num_lookup_advice: 2,
        num_fixed: 1,
        lookup_bits: 20,
    };
    let compression_circuit = CompressionCircuit::new_from_ce_snark(
        layer1_agg_params,
        &params,
        inner_snark,
        false,
        &mut rng,
    )
    .unwrap();
    let pk_layer1 = gen_pk(&params, &compression_circuit, None);
    let compression_snark = gen_snark_shplonk(
        &params,
        &pk_layer1,
        compression_circuit.clone(),
        None::<String>,
    );
    dump_snark("./src/layer1.json", "./src/layer1_protocol.json", &compression_snark);

    // Second layer of compression
    let layer2_agg_params = AggregationConfigParams {
        degree: 21,
        num_advice: 1,
        num_lookup_advice: 1,
        num_fixed: 1,
        lookup_bits: 20,
    };
    let mut rng = test_rng();
    let _compression_circuit_layer2 = CompressionCircuit::new_from_ce_snark(
        layer2_agg_params,
        &params,
        compression_snark,
        true,
        &mut rng,
    )
    .unwrap();

    // let pk_layer2 = gen_pk(&params, &compression_circuit_layer2, None);
    // let compression_snark_layer2 = gen_snark_shplonk(
    //     &params2,
    //     &pk_layer2,
    //     compression_circuit_layer2.clone(),
    //     None::<String>,
    // );

//     verify_compression_layer_evm(layer_1_snark, layer_2_params, k2, path, 2);
}

#[test]
fn test_to_ce_snark() {
    let k0 = 8u32;
    let params_app = gen_srs(k0);
    let circuit = MockChunkCircuit::random(OsRng, false, false);

    let pk = gen_pk(&params_app, &circuit, None);
    let snark = gen_snark_shplonk(&params_app, &pk, circuit, None::<String>);

    assert_snark_roundtrip(&snark);
}
fn from_ce_snark(snark: &Snark) -> snark_verifier_sdk::Snark {
    serde_json::from_str(&serde_json::to_string(snark).unwrap()).unwrap()
}
fn assert_snark_roundtrip(snark: &Snark) {
    assert_eq!(
        serde_json::to_string(snark).unwrap(),
        serde_json::to_string(&to_ce_snark(&from_ce_snark(snark))).unwrap()
    );
}

#[test]
fn test_read_inner_snark() {
    let inner_snark: snark_verifier_sdk::Snark =
        prover::io::from_json_file("./src/inner_snark_inner_4176564.json").unwrap();
    // test that we are able to deserialize the inner snark without hitting the recursion limit.
    to_ce_snark(&inner_snark);
}

#[test]
fn test_read_snark_compression() {
    use std::io;
    use std::io::Write;

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    write!(handle, "Start testing!").unwrap();

    let _k0 = 20u32;
    let inner_snark: snark_verifier_sdk::Snark =
        prover::io::from_json_file("./src/inner_snark_inner_4176564.json").unwrap();

    // First layer of compression
    let k1 = 24u32;
    let layer1_agg_params = AggregationConfigParams {
        degree: 21,
        num_advice: 15,
        num_lookup_advice: 2,
        num_fixed: 1,
        lookup_bits: 20,
    };
    let params = gen_srs(k1);
    let mut rng = test_rng();
    let compression_circuit =
        CompressionCircuit::new_from_ce_snark(layer1_agg_params, &params, to_ce_snark(&inner_snark), false, &mut rng).unwrap();
    let pk_layer1 = gen_pk(&params, &compression_circuit, None);
    let _compression_snark = gen_snark_shplonk(
        &params,
        &pk_layer1,
        compression_circuit.clone(),
        None::<String>,
    );
}

// fn verify_compression_layer_evm(
//     previous_snark: Snark,
//     param: ParamsKZG<Bn256>,
//     degree: u32,
//     path: &Path,
//     layer_index: usize,
// ) {
//     let timer = start_timer!(|| format!("gen layer {} snark", layer_index));

//     let param = {
//         let mut param = param.clone();
//         param.downsize(degree);
//         param
//     };

//     let compression_circuit =
//         CompressionCircuit::new_from_ce_snark(&param, previous_snark, false, test_rng()).unwrap();

//     let instances = compression_circuit.instances();

//     let pk = gen_pk(&param, &compression_circuit, None);
//     // build the snark for next layer
//     let proof = gen_evm_proof_shplonk(&param, &pk, compression_circuit.clone(), instances.clone());

//     log::trace!("finished layer 4 aggregation generation");
//     log::trace!("proof size: {}", proof.len());

//     // verify proof via EVM
//     let deployment_code = gen_evm_verifier::<CompressionCircuit, KzgAs<Bn256, Bdfg21>>(
//         &param,
//         pk.get_vk(),
//         compression_circuit.num_instance(),
//         Some(&path.join(Path::new("contract.sol"))),
//     );
//     log::trace!("finished layer 4 bytecode generation");

//     evm_verify(
//         deployment_code,
//         compression_circuit.instances(),
//         proof.clone(),
//     );
//     log::trace!("layer 2 evm verification finished");

//     end_timer!(timer);
// }
