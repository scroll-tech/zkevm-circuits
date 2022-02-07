//! State circuit benchmarks

#[cfg(test)]
mod tests {
    use crate::bench_params::{DEGREE, MEMORY_ADDRESS_MAX, STACK_ADDRESS_MAX};
    use ark_std::{end_timer, start_timer};
    use halo2::transcript::{Blake2bRead, Blake2bWrite, Challenge255};
    use halo2::{plonk::*, poly::commitment::Setup};
    use pairing::bn256::Bn256;
    use pairing::bn256::Fr;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use zkevm_circuits::state_circuit::StateCircuit;

    const MEMORY_ROWS_MAX: usize = 1 << (DEGREE - 2);
    const STACK_ROWS_MAX: usize = 1 << (DEGREE - 2);
    const STORAGE_ROWS_MAX: usize = 1 << (DEGREE - 2);
    const GLOBAL_COUNTER_MAX: usize = MEMORY_ROWS_MAX + STACK_ROWS_MAX + STORAGE_ROWS_MAX;

    #[cfg_attr(not(feature = "benches"), ignore)]
    #[test]
    fn bench_state_circuit_prover() {
        let public_inputs_size = 0;
        let empty_circuit = StateCircuit::<
            Fr,
            true,
            GLOBAL_COUNTER_MAX,
            MEMORY_ROWS_MAX,
            MEMORY_ADDRESS_MAX,
            STACK_ROWS_MAX,
            STACK_ADDRESS_MAX,
            STORAGE_ROWS_MAX,
        >::default();

        // Initialize the polynomial commitment parameters
        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // Bench setup generation
        let setup_message = format!("Setup generation with degree = {}", DEGREE);
        let start1 = start_timer!(|| setup_message);
        let params = Setup::<Bn256>::new(DEGREE as u32, rng);
        let verifier_params = Setup::<Bn256>::verifier_params(&params, public_inputs_size).unwrap();
        end_timer!(start1);

        // Initialize the proving key
        let vk = keygen_vk(&params, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &empty_circuit).expect("keygen_pk should not fail");
        // Create a proof
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("State Proof generation with {} rows", DEGREE);
        let start2 = start_timer!(|| proof_message);
        create_proof(&params, &pk, &[empty_circuit], &[&[]], &mut transcript)
            .expect("proof generation should not fail");
        let proof = transcript.finalize();
        end_timer!(start2);

        // Bench verification time
        let start3 = start_timer!(|| "State Proof verification");
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

        verify_proof(&verifier_params, pk.get_vk(), &[&[]], &mut transcript)
            .expect("failed to verify bench circuit");
        end_timer!(start3);
    }
}
