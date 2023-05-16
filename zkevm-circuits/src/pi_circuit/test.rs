#![allow(unused_imports)]
use super::{dev::*, *};
use crate::util::unusable_rows;
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use mock::{CORRECT_MOCK_TXS, MOCK_CHAIN_ID};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn pi_circuit_unusable_rows() {
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 8;
    assert_eq!(
        PiCircuit::<Fr>::unusable_rows(),
        unusable_rows::<Fr, PiTestCircuit::<Fr, MAX_TXS, MAX_CALLDATA>>(),
    )
}

fn run<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    k: u32,
    public_data: PublicData,
) -> Result<(), Vec<VerifyFailure>> {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let randomness = F::random(&mut rng);
    let rand_rpi = F::random(&mut rng);
    let mut public_data = public_data;
    public_data.chain_id = *MOCK_CHAIN_ID;

    let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
        MAX_TXS,
        MAX_CALLDATA,
        randomness,
        rand_rpi,
        public_data,
    ));
    let public_inputs = circuit.0.instance();

    let prover = match MockProver::run(k, &circuit, public_inputs) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.verify()
}

#[test]
fn test_default_pi() {
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 8;
    let public_data = PublicData::default();

    let k = 17;
    assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
}

#[test]
fn test_simple_pi() {
    const MAX_TXS: usize = 8;
    const MAX_CALLDATA: usize = 200;

    let mut public_data = PublicData::default();

    let n_tx = 4;
    for i in 0..n_tx {
        public_data
            .transactions
            .push(CORRECT_MOCK_TXS[i].clone().into());
    }

    let k = 17;
    assert_eq!(run::<Fr, MAX_TXS, MAX_CALLDATA>(k, public_data), Ok(()));
}

fn run_size_check<F: Field, const MAX_TXS: usize, const MAX_CALLDATA: usize>(
    public_data: [PublicData; 2],
) {
    let mut rng = ChaCha20Rng::seed_from_u64(2);
    let randomness = F::random(&mut rng);
    let rand_rpi = F::random(&mut rng);

    let circuit = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
        MAX_TXS,
        MAX_CALLDATA,
        randomness,
        rand_rpi,
        public_data[0].clone(),
    ));
    let public_inputs = circuit.0.instance();
    let prover1 = MockProver::run(20, &circuit, public_inputs).unwrap();

    let circuit2 = PiTestCircuit::<F, MAX_TXS, MAX_CALLDATA>(PiCircuit::new(
        MAX_TXS,
        MAX_CALLDATA,
        randomness,
        rand_rpi,
        public_data[1].clone(),
    ));
    let public_inputs = circuit2.0.instance();
    let prover2 = MockProver::run(20, &circuit, public_inputs).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}

#[test]
fn variadic_size_check() {
    const MAX_TXS: usize = 8;
    const MAX_CALLDATA: usize = 200;

    let mut pub_dat_1 = PublicData {
        chain_id: *MOCK_CHAIN_ID,
        ..Default::default()
    };

    let n_tx = 2;
    for i in 0..n_tx {
        pub_dat_1
            .transactions
            .push(CORRECT_MOCK_TXS[i].clone().into());
    }

    let mut pub_dat_2 = PublicData {
        chain_id: *MOCK_CHAIN_ID,
        ..Default::default()
    };

    let n_tx = 4;
    for i in 0..n_tx {
        pub_dat_2
            .transactions
            .push(CORRECT_MOCK_TXS[i].clone().into());
    }

    run_size_check::<Fr, MAX_TXS, MAX_CALLDATA>([pub_dat_1, pub_dat_2]);
}
