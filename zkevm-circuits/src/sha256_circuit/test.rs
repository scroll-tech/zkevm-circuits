use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::rngs::OsRng;

use super::{circuit::*, BLOCK_SIZE};

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

const CAP_BLK: usize = 24;

#[derive(Default, Clone, Copy)]
struct MyCircuit {
    blocks: usize,
}

impl Circuit<Fr> for MyCircuit {
    type Config = CircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
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

        for _ in 0..self.blocks {
            hasher.update(&mut layouter, chng_v, &[b'a'; BLOCK_SIZE * 4])?;
        }
        if hasher.updated_size() > 0 {
            hasher.finalize(&mut layouter, chng_v)?;
        }

        for _ in hasher.blocks()..CAP_BLK {
            hasher.update(&mut layouter, chng_v, &[])?;
            hasher.finalize(&mut layouter, chng_v)?;
        }

        Ok(())
    }
}

#[test]
fn vk_stable() {
    let k = 17;

    let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
    let empty_circuit: MyCircuit = MyCircuit { blocks: 0 };

    // Initialize the proving key
    let vk_from_empty = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");

    let circuit = MyCircuit { blocks: 16 };
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    // Create a proof
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

    let strategy = SingleStrategy::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<_>, _, _, _>(
        &params,
        &vk_from_empty,
        strategy,
        &[],
        &mut transcript,
    )
    .unwrap();
}
