use std::marker::PhantomData;

use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;

use crate::sig_circuit::SigCircuit;

use eth_types::{
    sign_types::{sign, SignData},
    Field,
};
use halo2_proofs::{
    arithmetic::Field as HaloField,
    dev::MockProver,
    halo2curves::{bn256::Fr, group::Curve, secp256k1},
};
use rand::{Rng, RngCore};

#[test]
fn sign_verify() {
    use super::utils::LOG_TOTAL_NUM_ROWS;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use sha3::{Digest, Keccak256};
    let mut rng = XorShiftRng::seed_from_u64(1);
    let max_sigs = [16];
    for max_sig in max_sigs.iter() {
        log::debug!("testing for {} signatures", max_sig);
        let mut signatures = Vec::new();
        for _ in 0..*max_sig {
            let (sk, pk) = gen_key_pair(&mut rng);
            let msg = gen_msg(&mut rng);
            let msg_hash: [u8; 32] = Keccak256::digest(&msg)
                .as_slice()
                .to_vec()
                .try_into()
                .expect("hash length isn't 32 bytes");
            let msg_hash = secp256k1::Fq::from_bytes(&msg_hash).unwrap();
            let (r, s, v) = sign_with_rng(&mut rng, sk, msg_hash);
            signatures.push(SignData {
                signature: (r, s, v),
                pk,
                msg: msg.into(),
                msg_hash,
            });
        }

        let k = LOG_TOTAL_NUM_ROWS as u32;
        run::<Fr>(k, *max_sig, signatures);

        log::debug!("end of testing for {} signatures", max_sig);
    }
}

// Generate a test key pair
fn gen_key_pair(rng: impl RngCore) -> (secp256k1::Fq, Secp256k1Affine) {
    // generate a valid signature
    let generator = Secp256k1Affine::generator();
    let sk = secp256k1::Fq::random(rng);
    let pk = generator * sk;
    let pk = pk.to_affine();

    (sk, pk)
}

// Generate a test message hash
fn gen_msg_hash(rng: impl RngCore) -> secp256k1::Fq {
    secp256k1::Fq::random(rng)
}

// Generate a test message.
fn gen_msg(mut rng: impl RngCore) -> Vec<u8> {
    let msg_len: usize = rng.gen_range(0..128);
    let mut msg = vec![0; msg_len];
    rng.fill_bytes(&mut msg);
    msg
}

// Returns (r, s, v)
fn sign_with_rng(
    rng: impl RngCore,
    sk: secp256k1::Fq,
    msg_hash: secp256k1::Fq,
) -> (secp256k1::Fq, secp256k1::Fq, u8) {
    let randomness = secp256k1::Fq::random(rng);
    sign(randomness, sk, msg_hash)
}

fn run<F: Field>(k: u32, max_verif: usize, signatures: Vec<SignData>) {
    // SignVerifyChip -> ECDSAChip -> MainGate instance column
    let circuit = SigCircuit::<Fr> {
        max_verif,
        signatures,
        _marker: PhantomData,
    };

    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };
    assert_eq!(prover.verify(), Ok(()));
}
