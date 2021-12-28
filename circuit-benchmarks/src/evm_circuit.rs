//! Evm circuit benchmarks

use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use zkevm_circuits::evm_circuit::{witness::Block, EvmCircuit};

#[derive(Debug, Default)]
pub struct TestCircuit<F> {
    block: Block<F>,
}

impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
    type Config = EvmCircuit<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = [(); 4].map(|_| meta.advice_column());
        let rw_table = [(); 8].map(|_| meta.advice_column());
        let bytecode_table = [(); 4].map(|_| meta.advice_column());
        let block_table = [(); 3].map(|_| meta.advice_column());
        let randomness = meta.instance_column();

        EvmCircuit::configure(
            meta,
            randomness,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign_block(&mut layouter, &self.block)
    }
}

#[cfg(test)]
mod evm_circ_benches {
    use super::*;
    use ark_std::{end_timer, start_timer};
    use halo2::plonk::{create_proof, keygen_pk, keygen_vk};
    use halo2::{
        plonk::verify_proof,
        poly::commitment::Setup,
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use pairing::bn256::Bn256;
    use pairing::bn256::Fr;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::env::var;

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_evm_circuit_prover() {
        let degree: u32 = var("DEGREE")
            .expect("No DEGREE env var was provided")
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        let circuit = TestCircuit::<Fr>::default();
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37,
            0x32, 0x54, 0x06, 0xbc, 0xe5,
        ]);

        // Bench setup generation
        let setup_message =
            format!("Setup generation with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let params = Setup::<Bn256>::new(degree, rng);
        end_timer!(start1);

        let vk = keygen_vk(&params, &circuit).unwrap();
        let pk = keygen_pk(&params, vk, &circuit).unwrap();

        // Prove
        let mut transcript =
            Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message =
            format!("EVM Proof generation with {} rows", degree);
        let start2 = start_timer!(|| proof_message);
        create_proof(&params, &pk, &[circuit], &[&[&[]]], &mut transcript)
            .unwrap();
        let proof = transcript.finalize();
        end_timer!(start2);

        // Verify
        let params = Setup::<Bn256>::verifier_params(&params, 0).unwrap();
        let mut transcript =
            Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        // Bench verification time
        let start3 = start_timer!(|| "EVM Proof verification");
        verify_proof(&params, pk.get_vk(), &[&[&[]]], &mut transcript).unwrap();
        end_timer!(start3);
    }
}
