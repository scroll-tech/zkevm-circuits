//! Public input circuit benchmarks
#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use bus_mapping::mock::BlockData;
    use eth_types::bytecode;
    use eth_types::geth_types::GethData;
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
    use mock::TestContext;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::env::var;
    use zkevm_circuits::pi_circuit::{PiCircuit, PiTestCircuit};
    use zkevm_circuits::util::SubCircuit;
    use zkevm_circuits::witness::{block_convert, Block};

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_pi_circuit_prover() {
        let degree: u32 = var("DEGREE")
            .unwrap_or_else(|_| "15".to_string())
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        const MAX_TXS: usize = 10;
        const MAX_CALLDATA: usize = 128;
        const MAX_INNER_BLOCKS: usize = 64;

        let block = generate_block::<MAX_TXS, MAX_CALLDATA>();
        let circuit = PiTestCircuit::<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>(
            PiCircuit::<Fr>::new(MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS, &block),
        );
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
            PiTestCircuit<Fr, MAX_TXS, MAX_CALLDATA, MAX_INNER_BLOCKS>,
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

    fn generate_block<const MAX_TXS: usize, const MAX_CALLDATA: usize>() -> Block<Fr> {
        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode! {
            STOP
        })
        .unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        block_convert(&builder.block, &builder.code_db).unwrap()
    }
}
