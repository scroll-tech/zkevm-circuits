use std::{
    marker::PhantomData,
    ops::{Add, Mul, Neg},
};

use bus_mapping::circuit_input_builder::{EcAddOp, EcMulOp, EcPairingOp, PrecompileEcParams};
use eth_types::Field;
use halo2_proofs::{
    arithmetic::Field as ArithmeticField,
    dev::MockProver,
    halo2curves::{
        bn256::{Fr, G1Affine, G2Affine},
        group::cofactor::CofactorCurveAffine,
    },
};
use rand::{CryptoRng, RngCore};

use crate::ecc_circuit::EccCircuit;

fn run<F: Field>(
    k: u32,
    _max_ec_ops: PrecompileEcParams,
    add_ops: Vec<EcAddOp>,
    mul_ops: Vec<EcMulOp>,
    pairing_ops: Vec<EcPairingOp>,
) {
    let circuit = EccCircuit::<F> {
        ec_add_unequal_ops: 5,
        ec_double_ops: 5,
        ec_mul_nonzero_ops: 5,
        ec_pairing1_ops: 1,
        ec_pairing2_ops: 2,
        ec_pairing3_ops: 1,
        ec_pairing4_ops: 2,
        add_ops,
        mul_ops,
        pairing_ops,
        _marker: PhantomData,
    };

    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

trait GenRand {
    fn gen_rand<R: RngCore + CryptoRng>(r: &mut R) -> Self;
}

impl GenRand for EcAddOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R) -> Self {
        let p = G1Affine::random(&mut r);
        let q = G1Affine::random(&mut r);
        let r = p.add(&q).into();
        Self { p, q, r }
    }
}

impl GenRand for EcMulOp {
    fn gen_rand<R: RngCore + CryptoRng>(mut r: &mut R) -> Self {
        let p = G1Affine::random(&mut r);
        let s = <Fr as halo2_proofs::arithmetic::Field>::random(&mut r);
        let r = p.mul(&s).into();
        Self { p, s, r }
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
        Self {
            inputs: [
                (point_p_negated, point_q),
                (point_s, point_t),
                (G1Affine::identity(), G2Affine::identity()),
                (G1Affine::identity(), G2Affine::identity()),
            ],
            output: 1u64.into(),
        }
    }
}

fn gen<T: GenRand, R: RngCore + CryptoRng>(mut r: &mut R, max_len: usize) -> Vec<T> {
    std::iter::repeat(0)
        .take(max_len)
        .map(move |_| T::gen_rand(&mut r))
        .collect()
}

#[test]
fn test_ecc_circuit() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut rng = rand::thread_rng();

    run::<Fr>(
        LOG_TOTAL_NUM_ROWS,
        PrecompileEcParams {
            ec_add: 10,
            ec_mul: 10,
            ec_pairing: 2,
        },
        gen(&mut rng, 4),
        gen(&mut rng, 3),
        gen(&mut rng, 2),
    )
}

#[test]
fn variadic_size_check() {
    use crate::ecc_circuit::util::LOG_TOTAL_NUM_ROWS;
    use halo2_proofs::halo2curves::bn256::Fr;

    let mut rng = rand::thread_rng();

    let circuit = EccCircuit::<Fr> {
        ec_add_unequal_ops: 5,
        ec_double_ops: 5,
        ec_mul_nonzero_ops: 5,
        ec_pairing1_ops: 1,
        ec_pairing2_ops: 2,
        ec_pairing3_ops: 1,
        ec_pairing4_ops: 2,
        add_ops: gen(&mut rng, 4),
        mul_ops: gen(&mut rng, 3),
        pairing_ops: gen(&mut rng, 2),
        _marker: PhantomData,
    };
    let prover1 = MockProver::<Fr>::run(LOG_TOTAL_NUM_ROWS, &circuit, vec![]).unwrap();

    let circuit = EccCircuit::<Fr> {
        ec_add_unequal_ops: 5,
        ec_double_ops: 5,
        ec_mul_nonzero_ops: 5,
        ec_pairing1_ops: 1,
        ec_pairing2_ops: 2,
        ec_pairing3_ops: 1,
        ec_pairing4_ops: 2,
        add_ops: gen(&mut rng, 3),
        mul_ops: gen(&mut rng, 2),
        pairing_ops: gen(&mut rng, 1),
        _marker: PhantomData,
    };
    let prover2 = MockProver::<Fr>::run(LOG_TOTAL_NUM_ROWS, &circuit, vec![]).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}
