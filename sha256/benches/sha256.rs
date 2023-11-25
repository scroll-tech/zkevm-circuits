use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
//use halo2curves::pasta::{pallas, EqAffine};
use rand::rngs::OsRng;

use std::{
    fs::{create_dir, File},
    io::{prelude::*, BufReader},
    path::Path,
};

use criterion::{criterion_group, criterion_main, Criterion};

use sha256::{circuit::*, BLOCK_SIZE};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr},
    plonk::{Advice, Any, Column, Expression, Fixed},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};

const CAP_BLK: usize = 16;

#[allow(dead_code)]
fn bench(name: &str, k: u32, c: &mut Criterion) {
    #[derive(Default, Clone, Copy)]
    struct MyCircuit {}

    impl Circuit<Fr> for MyCircuit {
        type Config = CircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            struct DevTable {
                s_enable: Column<Fixed>,
                input_rlc: Column<Advice>,
                input_len: Column<Advice>,
                hashes_rlc: Column<Advice>,
                is_effect: Column<Advice>,
            }

            impl SHA256Table for DevTable {
                fn cols(&self) -> [Column<Any>; 5] {
                    [
                        self.s_enable.into(),
                        self.input_rlc.into(),
                        self.input_len.into(),
                        self.hashes_rlc.into(),
                        self.is_effect.into(),
                    ]
                }
            }

            let dev_table = DevTable {
                s_enable: meta.fixed_column(),
                input_rlc: meta.advice_column(),
                input_len: meta.advice_column(),
                hashes_rlc: meta.advice_column(),
                is_effect: meta.advice_column(),
            };
            meta.enable_constant(dev_table.s_enable);

            let chng = Expression::Constant(Fr::from(0x100u64));
            Self::Config::configure(meta, dev_table, chng)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chng_v = Value::known(Fr::from(0x100u64));
            let mut hasher = Hasher::new(config, &mut layouter)?;

            let input = [b'a'; BLOCK_SIZE];
            for _ in 0..CAP_BLK {
                hasher.update(&mut layouter, chng_v, &input)?;
                hasher.finalize(&mut layouter, chng_v)?;
            }

            Ok(())
        }
    }

    // Initialize the polynomial commitment parameters
    let path_str = format!("./benches/sha256_assets/sha256_params_{k}");
    let params_path = Path::new(&path_str);
    if File::open(params_path).is_err() {
        let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
        let mut buf = Vec::new();

        params.write(&mut buf).expect("Failed to write params");

        create_dir("./benches/sha256_assets")
            .unwrap_or_else(|_| println!("Params dir already exists"));
        let mut file = File::create(params_path).expect("Failed to create sha256_params");

        file.write_all(&buf[..])
            .expect("Failed to write params to file");
    }

    let params_fs = File::open(params_path).expect("couldn't load sha256_params");
    let params: ParamsKZG<Bn256> =
        ParamsKZG::read::<_>(&mut BufReader::new(params_fs)).expect("Failed to read params");

    let empty_circuit: MyCircuit = MyCircuit {};

    // Initialize the proving key
    let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");

    let circuit: MyCircuit = MyCircuit {};

    let prover_name = format!("{}-{}-bytes-prover", name, CAP_BLK * 64);
    let verifier_name = format!("{}-{}-bytes-verifier", name, CAP_BLK * 64);

    // Benchmark proof creation
    c.bench_function(&prover_name, |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
            create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
                &params,
                &pk,
                &[circuit],
                &[],
                OsRng,
                &mut transcript,
            )
            .expect("proof generation should not fail");
            let _proof: Vec<u8> = transcript.finalize();
        });
    });

    // Create a proof
    let path_str = format!("./benches/sha256_assets/sha256_proof_{k}");
    let proof_path = Path::new(&path_str);
    if File::open(proof_path).is_err() {
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<_>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[],
            OsRng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();
        let mut file = File::create(proof_path).expect("Failed to create sha256_proof");
        file.write_all(&proof[..]).expect("Failed to write proof");
    }

    let mut proof_fs = File::open(proof_path).expect("couldn't load sha256_proof");
    let mut proof = Vec::<u8>::new();
    proof_fs
        .read_to_end(&mut proof)
        .expect("Couldn't read proof");

    c.bench_function(&verifier_name, |b| {
        b.iter(|| {
            let strategy = SingleStrategy::new(&params);
            let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
            verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
                &params,
                pk.get_vk(),
                strategy,
                &[],
                &mut transcript,
            )
            .unwrap();
        });
    });
}

#[allow(dead_code)]
fn criterion_benchmark(c: &mut Criterion) {
    bench("sha256", 17, c);
    // bench("sha256", 20, c);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = criterion_benchmark
}
criterion_main!(benches);
