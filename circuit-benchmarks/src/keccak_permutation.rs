//! Evm circuit benchmarks

use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use keccak256::{
    common::NEXT_INPUTS_LANES, keccak_arith::KeccakFArith, permutation::circuit::KeccakFConfig,
};

#[derive(Default, Clone)]
struct KeccakRoundTestCircuit<F> {
    in_state: [F; 25],
    out_state: [F; 25],
    next_mixing: Option<[F; NEXT_INPUTS_LANES]>,
    is_mixing: bool,
}

impl<F: Field> Circuit<F> for KeccakRoundTestCircuit<F> {
    type Config = KeccakFConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Self::Config::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Load the table
        config.load(&mut layouter)?;
        let offset: usize = 0;

        let in_state = layouter.assign_region(
            || "Keccak round witnes & flag assignment",
            |mut region| {
                // Witness `state`
                let in_state: [AssignedCell<F, F>; 25] = {
                    let mut state: Vec<AssignedCell<F, F>> = Vec::with_capacity(25);
                    for (idx, val) in self.in_state.iter().enumerate() {
                        let cell = region.assign_advice(
                            || "witness input state",
                            config.state[idx],
                            offset,
                            || Ok(*val),
                        )?;
                        state.push(cell)
                    }
                    state.try_into().unwrap()
                };
                Ok(in_state)
            },
        )?;

        config.assign_all(
            &mut layouter,
            in_state,
            self.out_state,
            self.is_mixing,
            self.next_mixing,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier};
    use halo2_proofs::{
        pairing::bn256::{Bn256, Fr, G1Affine},
        poly::commitment::{Params, ParamsVerifier},
        transcript::{Blake2bRead, Blake2bWrite, Challenge255},
    };
    use itertools::Itertools;
    use keccak256::common::PERMUTATION;
    use keccak256::{
        arith_helpers::*,
        common::{State, ROUND_CONSTANTS},
        gate_helpers::biguint_to_f,
    };
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::env::var;

    #[test]
    fn bench_keccak_round() {
        let in_state: State = [
            [1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        let next_input: State = [
            [2, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        let mut in_state_biguint = StateBigInt::default();

        // Generate in_state as `[Fr;25]`
        let mut in_state_fp: [Fr; 25] = [Fr::zero(); 25];
        for (x, y) in (0..5).cartesian_product(0..5) {
            in_state_fp[5 * x + y] = biguint_to_f(&convert_b2_to_b13(in_state[x][y]));
            in_state_biguint[(x, y)] = convert_b2_to_b13(in_state[x][y]);
        }

        // Compute out_state_mix
        let mut out_state_mix = in_state_biguint.clone();
        KeccakFArith::permute_and_absorb(&mut out_state_mix, Some(&next_input));

        // Compute out_state_non_mix
        let mut out_state_non_mix = in_state_biguint.clone();
        KeccakFArith::permute_and_absorb(&mut out_state_non_mix, None);

        // Generate out_state as `[Fr;25]`
        let out_state_non_mix: [Fr; 25] = state_bigint_to_field(out_state_non_mix);

        let constants_b13: Vec<Fr> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b13(*num)))
            .collect();

        let constants_b9: Vec<Fr> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
            .collect();

        // Build the circuit
        let circuit = KeccakRoundTestCircuit::<Fr> {
            in_state: in_state_fp,
            out_state: out_state_non_mix,
            next_mixing: None,
            is_mixing: false,
        };

        let degree: u32 = var("DEGREE")
            .expect("No DEGREE env var was provided")
            .parse()
            .expect("Cannot parse DEGREE env var as u32");

        let rng = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06,
            0xbc, 0xe5,
        ]);

        // Bench setup generation
        let setup_message = format!("Setup generation with degree = {}", degree);
        let start1 = start_timer!(|| setup_message);
        let general_params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(degree);
        end_timer!(start1);

        let vk = keygen_vk(&general_params, &circuit).unwrap();
        let pk = keygen_pk(&general_params, vk, &circuit).unwrap();

        // Prove
        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

        // Bench proof generation time
        let proof_message = format!("Keccak Proof generation with {} degree", degree);
        let start2 = start_timer!(|| proof_message);
        create_proof(
            &general_params,
            &pk,
            &[circuit],
            &[&[constants_b9.as_slice(), constants_b13.as_slice()]],
            rng,
            &mut transcript,
        )
        .unwrap();
        let proof = transcript.finalize();
        end_timer!(start2);

        // Verify
        let verifier_params: ParamsVerifier<Bn256> =
            general_params.verifier(PERMUTATION * 2).unwrap();
        let mut verifier_transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let strategy = SingleVerifier::new(&verifier_params);

        // Bench verification time
        let start3 = start_timer!(|| "Keccak Proof verification");
        verify_proof(
            &verifier_params,
            pk.get_vk(),
            strategy,
            &[&[constants_b9.as_slice(), constants_b13.as_slice()]],
            &mut verifier_transcript,
        )
        .unwrap();
        end_timer!(start3);
    }
}
