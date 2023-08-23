use std::{
    marker::PhantomData,
    ops::{Add, Mul, Neg},
};

use bus_mapping::circuit_input_builder::{
    EcAddOp, EcMulOp, EcPairingOp, EcPairingPair, PrecompileEcParams,
};
use eth_types::{Field, U256};
use halo2_proofs::{
    arithmetic::Field as ArithmeticField,
    dev::MockProver,
    halo2curves::bn256::{Fr, G1Affine, G2Affine},
};
use rand::{CryptoRng, Rng, RngCore};

use crate::ecc_circuit::EccCircuit;

fn run<F: Field, const MUST_FAIL: bool>(
    k: u32,
    max_ec_ops: PrecompileEcParams,
    add_ops: Vec<EcAddOp>,
    mul_ops: Vec<EcMulOp>,
    pairing_ops: Vec<EcPairingOp>,
) {
    let circuit = EccCircuit::<F, 9> {
        max_add_ops: max_ec_ops.ec_add,
        max_mul_ops: max_ec_ops.ec_mul,
        max_pairing_ops: max_ec_ops.ec_pairing,
        add_ops,
        mul_ops,
        pairing_ops,
        _marker: PhantomData,
    };

    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };

    if MUST_FAIL {
        if let Ok(()) = prover.verify() {
            panic!("expected failure, found success");
        }
    } else if let Err(e) = prover.verify() {
        panic!("{e:#?}");
    }
}

trait GenRand {
    fn gen_rand<R: RngCore + CryptoRng>(r: &mut R, is_neg: bool) -> Self;
}

impl GenRand for EcAddOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R, is_neg: bool) -> Self {
        let p = G1Affine::random(&mut r);
        let q = G1Affine::random(&mut r);
        let r = if is_neg {
            G1Affine::random(&mut r)
        } else {
            p.add(&q).into()
        };
        Self {
            p: (
                U256::from_little_endian(&p.x.to_bytes()),
                U256::from_little_endian(&p.y.to_bytes()),
            ),
            q: (
                U256::from_little_endian(&q.x.to_bytes()),
                U256::from_little_endian(&q.y.to_bytes()),
            ),
            r: Some(r),
        }
    }
}

impl GenRand for EcMulOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R, is_neg: bool) -> Self {
        let p = G1Affine::random(&mut r);
        let s = <Fr as halo2_proofs::arithmetic::Field>::random(&mut r);
        let r = if is_neg {
            G1Affine::random(&mut r)
        } else {
            p.mul(&s).into()
        };
        Self {
            p: (
                U256::from_little_endian(&p.x.to_bytes()),
                U256::from_little_endian(&p.y.to_bytes()),
            ),
            s,
            r: Some(r),
        }
    }
}

impl GenRand for EcPairingOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R, is_neg: bool) -> Self {
        let alpha = Fr::random(&mut r);
        let beta = Fr::random(&mut r);
        let point_p = G1Affine::from(G1Affine::generator() * alpha);
        let point_p_negated = point_p.neg();
        let point_q = G2Affine::from(G2Affine::generator() * beta);
        let point_s = G1Affine::from(G1Affine::generator() * alpha * beta);
        let point_t = G2Affine::generator();

        let alpha = Fr::random(&mut r);
        let beta = Fr::random(&mut r);
        let point_a = G1Affine::from(G1Affine::generator() * alpha);
        let point_a_negated = point_a.neg();
        let point_b = G2Affine::from(G2Affine::generator() * beta);
        let point_c = G1Affine::from(G1Affine::generator() * alpha * beta);
        let point_d = G2Affine::generator();

        let mut pairs = [
            EcPairingPair::new(point_p_negated, point_q),
            EcPairingPair::new(point_s, point_t),
            EcPairingPair::new(point_a_negated, point_b),
            EcPairingPair::new(point_c, point_d),
        ];
        let output = eth_types::U256::one();

        if is_neg {
            match r.gen::<bool>() {
                // change output.
                true => Self {
                    pairs,
                    output: eth_types::U256::one() - output,
                },
                // change a point in one of the pairs.
                false => {
                    let altered: G1Affine = point_p_negated.add(&G1Affine::generator()).into();
                    pairs[0].g1_point.0 = U256::from_little_endian(&altered.x.to_bytes());
                    pairs[0].g1_point.1 = U256::from_little_endian(&altered.y.to_bytes());
                    Self { pairs, output }
                }
            }
        } else {
            Self { pairs, output }
        }
    }
}

fn gen<T: GenRand, R: RngCore + CryptoRng>(mut r: &mut R, max_len: usize, is_neg: bool) -> Vec<T> {
    std::iter::repeat(0)
        .take(max_len)
        .map(move |_| T::gen_rand(&mut r, is_neg))
        .collect()
}

#[test]
fn test_ecc_circuit_valid_invalid() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use eth_types::word;
    use halo2_proofs::halo2curves::bn256::Fr;
    use snark_verifier::util::arithmetic::PrimeCurveAffine;

    let mut rng = rand::thread_rng();

    lazy_static::lazy_static! {
        static ref EC_ADD_OPS: Vec<EcAddOp> = {
            vec![
                // 1. valid: P == Q == G1::generator
                {
                    let p = G1Affine::generator();
                    EcAddOp {
                        p: (U256::from(1), U256::from(2)),
                        q: (U256::from(1), U256::from(2)),
                        r: Some(p.add(&p).into()),
                    }
                },
                // 2. invalid: P not on curve
                EcAddOp {
                    p: (U256::from(2), U256::from(3)),
                    q: (U256::from(1), U256::from(2)),
                    r: None,
                },
                // 3. valid: all zeroes
                EcAddOp {
                    p: (U256::zero(), U256::zero()),
                    q: (U256::zero(), U256::zero()),
                    r: Some(G1Affine::identity()),
                },
                // 4. invalid: Px and Py > Fq::MODULUS
                EcAddOp {
                    p: (
                        word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD48"), // p + 1
                        word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49"), // p + 2
                    ),
                    q: (U256::from(1), U256::from(2)),
                    r: None,
                },
                // 5. valid: P == -Q
                EcAddOp {
                    p: (U256::from(1), U256::from(2)),
                    q: (
                        U256::from(1),
                        word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"),
                    ),
                    r: Some(G1Affine::identity()),
                },
            ]
        };
        static ref EC_MUL_OPS: Vec<EcMulOp> = {
            vec![
                // 1. valid: P = G1::generator, s = 3
                EcMulOp {
                    p: (U256::from(1), U256::from(2)),
                    s: Fr::from(3),
                    r: Some({
                        let p = G1Affine::generator();
                        let s = Fr::from(3);
                        p.mul(s).into()
                    }),
                },
                // 2. invalid: P = (2, 3), i.e. not on curve
                EcMulOp {
                    p: (U256::from(2), U256::from(3)),
                    s: Fr::from(3),
                    r: None,
                },
                // 3. invalid: P == (p + 1, p + 2), i.e. > Fq::MODULUS
                EcMulOp {
                    p: (
                        word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD48"), // p + 1
                        word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49"), // p + 2
                    ),
                    s: Fr::from(3),
                    r: None,
                },
            ]
        };
    }

    run::<Fr, false>(
        LOG_TOTAL_NUM_ROWS,
        PrecompileEcParams::default(),
        EC_ADD_OPS.clone(),
        EC_MUL_OPS.clone(),
        gen(&mut rng, 2, false),
    );
}

#[test]
fn test_ecc_circuit_positive() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut rng = rand::thread_rng();

    run::<Fr, false>(
        LOG_TOTAL_NUM_ROWS,
        PrecompileEcParams::default(),
        gen(&mut rng, 9, false),
        gen(&mut rng, 9, false),
        gen(&mut rng, 1, false),
    );
}

#[test]
fn test_ecc_circuit_negative() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut rng = rand::thread_rng();

    run::<Fr, true>(
        LOG_TOTAL_NUM_ROWS,
        PrecompileEcParams::default(),
        gen(&mut rng, 9, true),
        gen(&mut rng, 9, true),
        gen(&mut rng, 1, true),
    );
}

#[test]
fn variadic_size_check() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut rng = rand::thread_rng();

    let default_params = PrecompileEcParams::default();

    let circuit = EccCircuit::<Fr, 9> {
        max_add_ops: default_params.ec_add,
        max_mul_ops: default_params.ec_mul,
        max_pairing_ops: default_params.ec_pairing,
        add_ops: gen(&mut rng, 25, false),
        mul_ops: gen(&mut rng, 20, false),
        pairing_ops: gen(&mut rng, 2, false),
        _marker: PhantomData,
    };
    let prover1 = MockProver::<Fr>::run(LOG_TOTAL_NUM_ROWS, &circuit, vec![]).unwrap();

    let circuit = EccCircuit::<Fr, 9> {
        max_add_ops: default_params.ec_add,
        max_mul_ops: default_params.ec_mul,
        max_pairing_ops: default_params.ec_pairing,
        add_ops: gen(&mut rng, 20, false),
        mul_ops: gen(&mut rng, 15, false),
        pairing_ops: gen(&mut rng, 1, false),
        _marker: PhantomData,
    };
    let prover2 = MockProver::<Fr>::run(LOG_TOTAL_NUM_ROWS, &circuit, vec![]).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}
