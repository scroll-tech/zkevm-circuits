//! State circuit benchmarks
#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use eth_types::Word;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG};
    use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
    use halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::ParamsProver,
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand_xorshift::XorShiftRng;
    use std::env::var;
    use zkevm_circuits::pi_circuit::{PiCircuit, PiTestCircuit, PublicData};
    use zkevm_circuits::test_util::rand_tx;
    use zkevm_circuits::util::SubCircuit;

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_pi_circuit_prover() {
        let degree: u32 = var("DEGREE")
            .unwrap_or_else(|_| "15".to_string())
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        const MAX_TXS: usize = 10;
        const MAX_CALLDATA: usize = 128;

        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let randomness = Fr::random(&mut rng);
        let rand_rpi = Fr::random(&mut rng);
        let public_data = generate_publicdata::<MAX_TXS, MAX_CALLDATA>();
        let circuit = PiTestCircuit::<Fr, MAX_TXS, MAX_CALLDATA>(PiCircuit::<Fr>::new(
            MAX_TXS,
            MAX_CALLDATA,
            randomness,
            rand_rpi,
            public_data,
        ));
        let public_inputs = circuit.0.instance();
        let instance: Vec<&[Fr]> = public_inputs.iter().map(|input| &input[..]).collect();
        let instances = &[&instance[..]][..];

        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // Bench setup generation
        let setup_message = format!("Setup generation with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
        let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();
        end_timer!(start1);

        // Initialize the proving key
        let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("PI_circuit Proof generation with {} rows", degree);
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            XorShiftRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            PiTestCircuit<Fr, MAX_TXS, MAX_CALLDATA>,
        >(
            &general_params,
            &pk,
            &[circuit],
            instances,
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        // Bench verification time
        let start3 = start_timer!(|| "PI_circuit Proof verification");
        let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleStrategy::new(&general_params);

        verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &verifier_params,
            pk.get_vk(),
            strategy,
            instances,
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }

    fn generate_publicdata<const MAX_TXS: usize, const MAX_CALLDATA: usize>() -> PublicData {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let mut public_data = PublicData::default();
        let chain_id = 1337u64;
        public_data.chain_id = Word::from(chain_id);

        let n_tx = MAX_TXS;
        for _ in 0..n_tx {
            let eth_tx = eth_types::Transaction::from(&rand_tx(&mut rng, chain_id, true));
            public_data.transactions.push(eth_tx);
        }
        public_data
    }
}
