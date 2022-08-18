//! Tx circuit benchmarks

#[cfg(test)]
mod tests {
    use crate::bench_params::DEGREE;
    use ark_std::{end_timer, start_timer};
    use env_logger::Env;
    use eth_types::{address, geth_types::Transaction, word, Bytes};
    use group::{Curve, Group};
    use halo2_proofs::arithmetic::{BaseExt, CurveAffine, Field};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::{
        pairing::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use secp256k1::Secp256k1Affine;
    use std::marker::PhantomData;
    use zkevm_circuits::tx_circuit::{
        sign_verify::{SignVerifyChip, POW_RAND_SIZE, VERIF_HEIGHT},
        TxCircuit,
    };

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_tx_circuit_prover() {
        env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

        // Approximate value, adjust with changes on the TxCircuit.
        const ROWS_PER_TX: usize = 175_000;
        const MAX_TXS: usize = 2_usize.pow(DEGREE as u32) / ROWS_PER_TX;
        const MAX_CALLDATA: usize = 1024;

        let mut rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);
        let aux_generator =
            <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();
        let chain_id: u64 = 1337;

        // Transaction generated with `zkevm-circuits/src/tx_circuit.rs:rand_tx` using
        // `rng = ChaCha20Rng::seed_from_u64(42)`
        let txs = vec![Transaction {
            from: address!("0x5f9b7e36af4ff81688f712fb738bbbc1b7348aae"),
            to: Some(address!("0x701653d7ae8ddaa5c8cee1ee056849f271827926")),
            nonce: word!("0x3"),
            gas_limit: word!("0x7a120"),
            value: word!("0x3e8"),
            gas_price: word!("0x4d2"),
            gas_fee_cap: word!("0x0"),
            gas_tip_cap: word!("0x0"),
            call_data: Bytes::from(b"hello"),
            access_list: None,
            v: 2710,
            r: word!("0xaf180d27f90b2b20808bc7670ce0aca862bc2b5fa39c195ab7b1a96225ee14d7"),
            s: word!("0x61159fa4664b698ea7d518526c96cd94cf4d8adf418000754be106a3a133f866"),
        }];

        let randomness = Fr::random(&mut rng);
        let mut instance: Vec<Vec<Fr>> = (1..POW_RAND_SIZE + 1)
            .map(|exp| vec![randomness.pow(&[exp as u64, 0, 0, 0]); MAX_TXS * VERIF_HEIGHT])
            .collect();
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        instance.push(vec![]);
        let circuit = TxCircuit::<Fr, MAX_TXS, MAX_CALLDATA> {
            sign_verify: SignVerifyChip {
                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            },
            randomness,
            txs,
            chain_id,
        };

        // Bench setup generation
        let setup_message = format!(
            "Setup generation with degree = {} (MAX_TXS = {})",
            DEGREE, MAX_TXS
        );
        let start1 = start_timer!(|| setup_message);
        let general_params: Params<G1Affine> =
            Params::<G1Affine>::unsafe_setup::<Bn256>(DEGREE.try_into().unwrap());
        let verifier_params: ParamsVerifier<Bn256> =
            general_params.verifier(MAX_TXS * VERIF_HEIGHT).unwrap();
        end_timer!(start1);

        // Initialize the proving key
        let vk = keygen_vk(&general_params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&general_params, vk, &circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("Tx Proof generation with {} degree", DEGREE);
        let start2 = start_timer!(|| proof_message);
        let instance_slices: Vec<&[Fr]> = instance.iter().map(|v| &v[..]).collect();
        create_proof(
            &general_params,
            &pk,
            &[circuit],
            &[&instance_slices[..]],
            rng,
            &mut transcript,
        )
        .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        // Bench verification time
        let start3 = start_timer!(|| "Tx Proof verification");
        let mut verifier_transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&verifier_params);

        verify_proof(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[&instance_slices[..]],
            &mut verifier_transcript,
        )
        .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
