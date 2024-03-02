use eth_types::{
    sign_types::{sign, SignData},
    Field,
};
use halo2_proofs::{
    arithmetic::Field as HaloField,
    dev::MockProver,
    halo2curves::{
        group::Curve,
        secp256k1::{self, Secp256k1Affine},
    },
};
use rand::{Rng, RngCore};
use std::marker::PhantomData;

use crate::sig_circuit::SigCircuit;

#[test]
fn test_edge_cases() {
    use super::utils::LOG_TOTAL_NUM_ROWS;
    use eth_types::{
        sign_types::{biguint_to_32bytes_le, recover_pk2, SECP256K1_Q},
        word, ToBigEndian, ToLittleEndian, Word,
    };
    use halo2_proofs::halo2curves::{bn256::Fr, group::ff::PrimeField, secp256k1::Fq};
    use num::{BigUint, Integer};
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use snark_verifier::util::arithmetic::PrimeCurveAffine;

    let mut rng = XorShiftRng::seed_from_u64(1);

    // helper
    let to_sig = |(r, s, v): (Word, Word, u8)| -> (Fq, Fq, u8) {
        (
            Fq::from_bytes(&r.to_le_bytes()).unwrap(),
            Fq::from_bytes(&s.to_le_bytes()).unwrap(),
            v,
        )
    };

    // Vec<(msg_hash, r, s, v)>
    //
    // good data for ecrecover is (big-endian):
    // - msg_hash: 0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3
    // - r: 0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608
    // - s: 0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada
    // - v: 28, i.e. v == 1 for sig circuit
    let good_ecrecover_data = (
        word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"),
        word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"),
        word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"),
        1u8,
    );
    let ecrecover_data = vec![
        // 1. good data
        good_ecrecover_data,
        // 2. msg_hash == 0
        (
            Word::zero(),
            good_ecrecover_data.1,
            good_ecrecover_data.2,
            good_ecrecover_data.3,
        ),
        // 3. r == 0
        (
            good_ecrecover_data.0,
            Word::zero(),
            good_ecrecover_data.2,
            good_ecrecover_data.3,
        ),
        // 4. s == 0
        (
            good_ecrecover_data.0,
            good_ecrecover_data.1,
            Word::zero(),
            good_ecrecover_data.3,
        ),
        // 5. r == 0 and s == 0
        (
            good_ecrecover_data.0,
            Word::zero(),
            Word::zero(),
            good_ecrecover_data.3,
        ),
        // 6. random r and s for random msg hash
        {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes[..]);
            let msg_hash = Word::from_big_endian(&bytes);
            rng.fill(&mut bytes[..]);
            let r = Word::from_big_endian(&bytes);
            rng.fill(&mut bytes[..]);
            let s = Word::from_big_endian(&bytes);
            (msg_hash, r, s, 0u8)
        },
        // 7. v == 0 when v should be 1
        (
            good_ecrecover_data.0,
            good_ecrecover_data.1,
            good_ecrecover_data.2,
            1 - good_ecrecover_data.3,
        ),
        // 8. msg_hash outside FQ::MODULUS
        (
            Word::MAX,
            good_ecrecover_data.1,
            good_ecrecover_data.2,
            good_ecrecover_data.3,
        ),
        // 9. valid msg_hash, r, s, v but pubkey not recovered
        (
            word!("0x571b659b539a9da729fca1f2efdd8b07d6a7042e0640ac5ce3a8c5e3445523d7"),
            word!("0x5d14c6d7824ddecc43d307891c4fae49307e370f827fae93e014796665705800"),
            word!("0x6b0c5c6fb456b976d50eb155a6a15c9e9e93c4afa99d4cad4d86f4ba0cc175fd"),
            1u8,
        ),
        // 10. special case: u1.G + u2.PK == point at infinity
        //
        // where m * s^{-1} (mod n) and r * s^{-1} (mod n)
        // i.e. m == -r (mod n)
        {
            let m = BigUint::from_bytes_le(&secp256k1::Fq::random(&mut rng).to_bytes());
            let r = &*SECP256K1_Q - m.clone();
            (
                Word::from_little_endian(&biguint_to_32bytes_le(m)),
                Word::from_little_endian(&biguint_to_32bytes_le(r)),
                Word::from_little_endian(&secp256k1::Fq::random(&mut rng).to_bytes()),
                0,
            )
        },
    ];
    let signatures = ecrecover_data
        .iter()
        .map(|&(msg_hash, r, s, v)| SignData {
            signature: to_sig((r, s, v)),
            pk: recover_pk2(v, &r, &s, &msg_hash.to_be_bytes())
                .unwrap_or(Secp256k1Affine::identity()),
            msg_hash: {
                let msg_hash = BigUint::from_bytes_be(&msg_hash.to_be_bytes());
                let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
                let msg_hash_le = biguint_to_32bytes_le(msg_hash);
                secp256k1::Fq::from_repr(msg_hash_le).unwrap()
            },
            ..Default::default()
        })
        .collect();
    log::debug!("signatures=");
    log::debug!("{:#?}", signatures);

    run::<Fr>(LOG_TOTAL_NUM_ROWS as u32, 10, signatures);
}

#[test]
fn sign_verify() {
    use super::utils::LOG_TOTAL_NUM_ROWS;
    use crate::sig_circuit::utils::MAX_NUM_SIG;
    use halo2_proofs::halo2curves::bn256::Fr;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use sha3::{Digest, Keccak256};
    let mut rng = XorShiftRng::seed_from_u64(1);

    // msg_hash == 0
    {
        log::debug!("testing for msg_hash = 0");
        let mut signatures = Vec::new();

        let (sk, pk) = gen_key_pair(&mut rng);
        let msg = gen_msg(&mut rng);
        let msg_hash = secp256k1::Fq::zero();
        let (r, s, v) = sign_with_rng(&mut rng, sk, msg_hash);
        signatures.push(SignData {
            signature: (r, s, v),
            pk,
            msg: msg.into(),
            msg_hash,
        });

        let k = LOG_TOTAL_NUM_ROWS as u32;
        run::<Fr>(k, 1, signatures);

        log::debug!("end of testing for msg_hash = 0");
    }
    // msg_hash == 1
    {
        log::debug!("testing for msg_hash = 1");
        let mut signatures = Vec::new();

        let (sk, pk) = gen_key_pair(&mut rng);
        let msg = gen_msg(&mut rng);
        let msg_hash = secp256k1::Fq::one();
        let (r, s, v) = sign_with_rng(&mut rng, sk, msg_hash);
        signatures.push(SignData {
            signature: (r, s, v),
            pk,
            msg: msg.into(),
            msg_hash,
        });

        let k = LOG_TOTAL_NUM_ROWS as u32;
        run::<Fr>(k, 1, signatures);

        log::debug!("end of testing for msg_hash = 1");
    }
    // random msg_hash
    let max_sigs = [1, 16, MAX_NUM_SIG];
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
    let circuit = SigCircuit::<F> {
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
