//! Copy circuit benchmarks

#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use bus_mapping::mock::BlockData;
    use eth_types::geth_types::GethData;
    use eth_types::{bytecode, Word};
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
    use mock::test_ctx::helpers::*;
    use mock::test_ctx::TestContext;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::env::var;
    use zkevm_circuits::copy_circuit::CopyCircuit;
    use zkevm_circuits::evm_circuit::witness::{block_convert, Block};
    use zkevm_circuits::util::SubCircuit;

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_copy_circuit_prover() {
        let degree: u32 = var("DEGREE")
            .unwrap_or_else(|_| "14".to_string())
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        //Unique string used by bench results module for parsing the result
        const BENCHMARK_ID: &str = "Copy Circuit";

        // Initialize the polynomial commitment parameters
        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // Create the circuit
        let block = generate_full_events_block(degree);
        let circuit = CopyCircuit::<Fr>::new_from_block(&block);

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
        let proof_message = format!("{} Proof generation with degree = {}", BENCHMARK_ID, degree);
        let start2 = start_timer!(|| proof_message);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            XorShiftRng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            CopyCircuit<Fr>,
        >(&general_params, &pk, &[circuit], &[], rng, &mut transcript)
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        // Bench verification time
        let start3 = start_timer!(|| format!("{} Proof verification", BENCHMARK_ID));
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
            &[],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }

    /// generate enough copy events to fillup copy circuit
    fn generate_full_events_block(degree: u32) -> Block<Fr> {
        // A empiric value 55 here to let the code generate enough copy event without
        // exceed the max_rws limit.
        let copy_event_num = (1 << degree) / 55;
        let calldata = vec![0, 1, 2, 3];
        let code = bytecode! {
            PUSH32(Word::from(copy_event_num))  // config loop counter
            JUMPDEST                            // PC offset 0x21
            PUSH32(Word::from(0x04))
            PUSH32(Word::from(0x00))
            PUSH32(Word::from(0x00))
            CALLDATACOPY                        // do calldatacopy to generate copy event
            PUSH32(Word::from(0x01))
            SWAP1
            SUB
            DUP1
            PUSH32(Word::from(0x21))
            JUMPI                               // goto JUMPDEST(0x21) if (--copy_event_num > 0)
            STOP
        };

        let test_ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .input(calldata.into())
                    .gas((1e16 as u64).into());
            },
            |block, _txs| block.number(0xcafeu64),
        )
        .unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data_with_params(
            block.clone(),
            CircuitsParams {
                max_rws: 1 << (degree - 1),
                ..Default::default()
            },
        )
        .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        assert_eq!(block.copy_events.len(), copy_event_num);
        block
    }
}
