use std::{
    marker::PhantomData,
    ops::{Add, Mul, Neg},
};

use bus_mapping::circuit_input_builder::{
    EcAddOp, EcMulOp, EcPairingOp, EcPairingPair, PrecompileEcParams,
};
use eth_types::Field;
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
        assert!(prover.verify().is_err())
    } else {
        assert!(prover.verify().is_ok())
    }
}

trait GenRand {
    fn gen_rand<R: RngCore + CryptoRng>(r: &mut R) -> Self;

    fn gen_rand_neg<R: RngCore + CryptoRng>(r: &mut R) -> Self;
}

impl GenRand for EcAddOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R) -> Self {
        let p = G1Affine::random(&mut r);
        let q = G1Affine::random(&mut r);
        let r = p.add(&q).into();
        Self { p, q, r }
    }

    fn gen_rand_neg<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        let valid = Self::gen_rand(r);
        Self {
            p: valid.p,
            q: valid.q,
            r: valid.r.add(&G1Affine::generator()).into(),
        }
    }
}

impl GenRand for EcMulOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R) -> Self {
        let p = G1Affine::random(&mut r);
        let s = <Fr as halo2_proofs::arithmetic::Field>::random(&mut r);
        let r = p.mul(&s).into();
        Self { p, s, r }
    }

    fn gen_rand_neg<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        let valid = Self::gen_rand(r);
        Self {
            p: valid.p,
            s: valid.s,
            r: valid.r.add(&G1Affine::generator()).into(),
        }
    }
}

impl GenRand for EcPairingOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R) -> Self {
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
        Self {
            pairs: [
                EcPairingPair::new(point_p_negated, point_q),
                EcPairingPair::new(point_s, point_t),
                EcPairingPair::new(point_a_negated, point_b),
                EcPairingPair::new(point_c, point_d),
            ],
            output: eth_types::U256::one(),
        }
    }

    fn gen_rand_neg<R: RngCore + CryptoRng>(r: &mut R) -> Self {
        let mut valid = Self::gen_rand(r);
        match r.gen::<bool>() {
            // change output.
            true => Self {
                pairs: valid.pairs,
                output: eth_types::U256::one() - valid.output,
            },
            // change a point in one of the pairs.
            false => {
                valid.pairs[0].g1_point =
                    valid.pairs[0].g1_point.add(&G1Affine::generator()).into();
                Self {
                    pairs: valid.pairs,
                    output: valid.output,
                }
            }
        }
    }
}

fn gen<T: GenRand, R: RngCore + CryptoRng>(mut r: &mut R, max_len: usize) -> Vec<T> {
    std::iter::repeat(0)
        .take(max_len)
        .map(move |_| T::gen_rand(&mut r))
        .collect()
}

fn gen_neg<T: GenRand, R: RngCore + CryptoRng>(mut r: &mut R, max_len: usize) -> Vec<T> {
    std::iter::repeat(0)
        .take(max_len)
        .map(move |_| T::gen_rand_neg(&mut r))
        .collect()
}
#[test]
fn test_ecc_circuit_positive() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut rng = rand::thread_rng();

    run::<Fr, false>(
        LOG_TOTAL_NUM_ROWS,
        PrecompileEcParams::default(),
        gen(&mut rng, 9),
        gen(&mut rng, 9),
        gen(&mut rng, 1),
    )
}

#[test]
fn test_ecc_circuit_negative() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut rng = rand::thread_rng();

    run::<Fr, true>(
        LOG_TOTAL_NUM_ROWS,
        PrecompileEcParams::default(),
        gen_neg(&mut rng, 9),
        gen_neg(&mut rng, 9),
        gen_neg(&mut rng, 1),
    )
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
        add_ops: gen(&mut rng, 25),
        mul_ops: gen(&mut rng, 20),
        pairing_ops: gen(&mut rng, 2),
        _marker: PhantomData,
    };
    let prover1 = MockProver::<Fr>::run(LOG_TOTAL_NUM_ROWS, &circuit, vec![]).unwrap();

    let circuit = EccCircuit::<Fr, 9> {
        max_add_ops: default_params.ec_add,
        max_mul_ops: default_params.ec_mul,
        max_pairing_ops: default_params.ec_pairing,
        add_ops: gen(&mut rng, 20),
        mul_ops: gen(&mut rng, 15),
        pairing_ops: gen(&mut rng, 1),
        _marker: PhantomData,
    };
    let prover2 = MockProver::<Fr>::run(LOG_TOTAL_NUM_ROWS, &circuit, vec![]).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}
