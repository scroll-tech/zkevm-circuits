//! Tx circuit benchmarks

#[cfg(test)]
mod tests {
    use ark_std::{end_timer, start_timer};
    use bus_mapping::circuit_input_builder::{BuilderClient, CircuitsParams};
    use env_logger::Env;
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
    use log;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::env::var;
    use zkevm_circuits::tx_circuit::TxCircuit;
    use zkevm_circuits::util::SubCircuit;
    use zkevm_circuits::witness::block_convert;

    use bus_mapping::rpc::GethClient;
    use ethers::providers::Http;
    use url::Url;
    fn get_client() -> GethClient<Http> {
        let geth_url = "http://52.37.45.56:30303";
        let transport = Http::new(Url::parse(geth_url).expect("invalid url"));
        GethClient::new(transport)
    }

    async fn build_circuit_from_mainnet_block() -> (usize, TxCircuit<Fr>) {
        let degree = std::env::var("DEGREE")
            .expect("DEGREE Not Set")
            .parse::<usize>()
            .expect("DEGREE should be int");
        let block_num = 16140307_u64;
        log::info!("test super circuit, block number: {}", block_num);
        let cli = get_client();
        // target k = 19
        let params = CircuitsParams {
            max_rws: 4_000_000,
            max_copy_rows: 4_000_000,
            max_txs: 500,
            max_calldata: 2_000_000,
            max_inner_blocks: 64,
            max_bytecode: 3_000_000,
            keccak_padding: None, // FIXME: can this be none?
            max_exp_steps: 100_000,
            max_evm_rows: 4_000_000,
        };
        let cli = BuilderClient::new(cli, params).await.unwrap();
        let (builder, _) = cli.gen_inputs(block_num).await.unwrap();

        if builder.block.txs.is_empty() {
            log::info!("skip empty block");
            std::process::exit(0);
        }
        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        let circuit = TxCircuit::new_from_block(&block);
        (degree, circuit)
    }

    fn build_circuit_from_mock_txs() -> (usize, TxCircuit<Fr>) {
        // Approximate value, adjust with changes on the TxCircuit.
        const ROWS_PER_TX: usize = 175_000;

        const MAX_CALLDATA: usize = 1024;
        let degree: u32 = var("DEGREE")
            .unwrap_or_else(|_| "19".to_string())
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        let max_txs: usize = 2_usize.pow(degree) / ROWS_PER_TX;

        let chain_id: u64 = mock::MOCK_CHAIN_ID.low_u64();
        let txs = vec![mock::CORRECT_MOCK_TXS[0].clone().into()];
        let circuit = TxCircuit::<Fr>::new(max_txs, MAX_CALLDATA, chain_id, txs);
        (degree as usize, circuit)
    }

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[tokio::test]
    async fn bench_tx_circuit_prover() {
        env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

        let mut rng = ChaCha20Rng::seed_from_u64(42);

        //Unique string used by bench results module for parsing the result
        const BENCHMARK_ID: &str = "Tx Circuit";

        let mock_mode = true;
        let (degree, circuit) = if mock_mode {
            build_circuit_from_mock_txs()
        } else {
            build_circuit_from_mainnet_block().await
        };

        // Bench setup generation
        let setup_message = format!("Setup generation with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params = ParamsKZG::<Bn256>::setup(degree as u32, &mut rng);
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
            ChaCha20Rng,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
            TxCircuit<Fr>,
        >(
            &general_params,
            &pk,
            &[circuit],
            &[&[&[]]],
            rng,
            &mut transcript,
        )
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
            &[&[&[]]],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
