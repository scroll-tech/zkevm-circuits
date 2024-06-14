use eth_types::{ToLittleEndian, U256};
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions},
    utils::{fe_to_biguint, modulus},
    AssignedValue, QuantumCell,
};
use halo2_ecc::{
    bigint::{CRTInteger, OverflowInteger},
    fields::{fp::FpConfig, FieldChip},
    halo2_base::{utils::decompose_bigint_option, Context},
};
use halo2_proofs::{
    circuit::Value,
    halo2curves::{bls12_381::Scalar, bn256::Fr, ff::PrimeField},
};
use itertools::Itertools;
use num_bigint::{BigInt, Sign};
use std::{iter::successors, sync::LazyLock};

use crate::{
    blob::BLOB_WIDTH,
    constants::{BITS, LIMBS},
};

/// Base 2 logarithm of BLOB_WIDTH.
const LOG_BLOB_WIDTH: usize = 12;

pub static BLS_MODULUS: LazyLock<U256> = LazyLock::new(|| {
    U256::from_str_radix(Scalar::MODULUS, 16).expect("BLS_MODULUS from bls crate")
});

pub static ROOTS_OF_UNITY: LazyLock<Vec<Scalar>> = LazyLock::new(|| {
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#constants
    let primitive_root_of_unity = Scalar::from(7);
    let modulus = *BLS_MODULUS;

    let exponent = (modulus - U256::one()) / U256::from(4096);
    let root_of_unity = primitive_root_of_unity.pow(&exponent.0);

    let ascending_order: Vec<_> = successors(Some(Scalar::one()), |x| Some(*x * root_of_unity))
        .take(BLOB_WIDTH)
        .collect();
    (0..BLOB_WIDTH)
        .map(|i| {
            let j = u16::try_from(i).unwrap().reverse_bits() >> (16 - LOG_BLOB_WIDTH);
            ascending_order[usize::from(j)]
        })
        .collect()
});

#[derive(Clone, Debug)]
pub struct BarycentricEvaluationConfig {
    pub scalar: FpConfig<Fr, Scalar>,
}

#[derive(Default)]
pub struct AssignedBarycentricEvaluationConfig {
    /// CRTIntegers for the BLOB_WIDTH number of blob polynomial coefficients, followed by a
    /// CRTInteger for the challenge digest.
    pub(crate) barycentric_assignments: Vec<CRTInteger<Fr>>,
    /// 32 Assigned cells representing the LE-bytes of challenge z.
    pub(crate) z_le: Vec<AssignedValue<Fr>>,
    /// 32 Assigned cells representing the LE-bytes of evaluation y.
    pub(crate) y_le: Vec<AssignedValue<Fr>>,
}

impl BarycentricEvaluationConfig {
    pub fn construct(range: RangeConfig<Fr>) -> Self {
        Self {
            scalar: FpConfig::construct(range, BITS, LIMBS, modulus::<Scalar>()),
        }
    }

    fn load_u256(&self, ctx: &mut Context<Fr>, a: U256) -> CRTInteger<Fr> {
        // borrowed from halo2-ecc/src/fields/fp.rs
        // similar to FpChip.load_private without range check.

        let a_val = Value::known(BigInt::from_bytes_le(Sign::Plus, &a.to_le_bytes()));
        let a_vec = decompose_bigint_option::<Fr>(
            a_val.as_ref(),
            self.scalar.num_limbs,
            self.scalar.limb_bits,
        );
        let limbs = self.scalar.range().gate.assign_witnesses(ctx, a_vec);

        let a_native = OverflowInteger::<Fr>::evaluate(
            &self.scalar.range().gate,
            //&self.bigint_chip,
            ctx,
            &limbs,
            self.scalar.limb_bases.iter().cloned(),
        );

        CRTInteger::construct(
            OverflowInteger::construct(limbs, self.scalar.limb_bits),
            a_native,
            a_val,
        )
    }

    pub fn assign(
        &self,
        ctx: &mut Context<Fr>,
        blob: &[U256; BLOB_WIDTH],
        challenge_digest: U256,
        evaluation: U256,
    ) -> AssignedBarycentricEvaluationConfig {
        // some constants for later use.
        let one = self.scalar.load_constant(ctx, fe_to_biguint(&Fr::one()));
        let blob_width = self
            .scalar
            .load_constant(ctx, fe_to_biguint(&Fr::from(BLOB_WIDTH as u64)));

        let powers_of_256 =
            std::iter::successors(Some(Fr::one()), |coeff| Some(Fr::from(256) * coeff))
                .take(11)
                .map(QuantumCell::Constant)
                .collect::<Vec<_>>();

        let roots_of_unity = ROOTS_OF_UNITY
            .iter()
            .map(|x| self.scalar.load_constant(ctx, fe_to_biguint(x)))
            .collect::<Vec<_>>();

        ////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// PRECHECKS z /////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////

        let (_, challenge) = challenge_digest.div_mod(*BLS_MODULUS);
        let challenge_scalar = Scalar::from_raw(challenge.0);

        let challenge_digest_crt = self.load_u256(ctx, challenge_digest);
        let challenge_le = self.scalar.range().gate.assign_witnesses(
            ctx,
            challenge
                .to_le_bytes()
                .iter()
                .map(|&x| Value::known(Fr::from(x as u64))),
        );
        let challenge_digest_mod = self.scalar.carry_mod(ctx, &challenge_digest_crt);
        let challenge_crt = self
            .scalar
            .load_private(ctx, Value::known(fe_to_biguint(&challenge_scalar).into()));
        self.scalar
            .assert_equal(ctx, &challenge_digest_mod, &challenge_crt);
        let challenge_limb1 = self.scalar.range().gate.inner_product(
            ctx,
            challenge_le[0..11]
                .iter()
                .map(|&x| QuantumCell::Existing(x)),
            powers_of_256[0..11].to_vec(),
        );
        let challenge_limb2 = self.scalar.range().gate.inner_product(
            ctx,
            challenge_le[11..22]
                .iter()
                .map(|&x| QuantumCell::Existing(x)),
            powers_of_256[0..11].to_vec(),
        );
        let challenge_limb3 = self.scalar.range().gate.inner_product(
            ctx,
            challenge_le[22..32]
                .iter()
                .map(|&x| QuantumCell::Existing(x)),
            powers_of_256[0..11].to_vec(),
        );
        self.scalar.range().gate.assert_equal(
            ctx,
            QuantumCell::Existing(challenge_limb1),
            QuantumCell::Existing(challenge_crt.truncation.limbs[0]),
        );
        self.scalar.range().gate.assert_equal(
            ctx,
            QuantumCell::Existing(challenge_limb2),
            QuantumCell::Existing(challenge_crt.truncation.limbs[1]),
        );
        self.scalar.range().gate.assert_equal(
            ctx,
            QuantumCell::Existing(challenge_limb3),
            QuantumCell::Existing(challenge_crt.truncation.limbs[2]),
        );

        ////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// PRECHECKS y /////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let evaluation_le = self.scalar.range().gate.assign_witnesses(
            ctx,
            evaluation
                .to_le_bytes()
                .iter()
                .map(|&x| Value::known(Fr::from(x as u64))),
        );
        let evaluation_scalar = Scalar::from_raw(evaluation.0);
        let evaluation_crt = self
            .scalar
            .load_private(ctx, Value::known(fe_to_biguint(&evaluation_scalar).into()));
        let evaluation_limb1 = self.scalar.range().gate.inner_product(
            ctx,
            evaluation_le[0..11]
                .iter()
                .map(|&x| QuantumCell::Existing(x)),
            powers_of_256[0..11].to_vec(),
        );
        let evaluation_limb2 = self.scalar.range().gate.inner_product(
            ctx,
            evaluation_le[11..22]
                .iter()
                .map(|&x| QuantumCell::Existing(x)),
            powers_of_256[0..11].to_vec(),
        );
        let evaluation_limb3 = self.scalar.range().gate.inner_product(
            ctx,
            evaluation_le[22..32]
                .iter()
                .map(|&x| QuantumCell::Existing(x)),
            powers_of_256[0..11].to_vec(),
        );
        self.scalar.range().gate.assert_equal(
            ctx,
            QuantumCell::Existing(evaluation_limb1),
            QuantumCell::Existing(evaluation_crt.truncation.limbs[0]),
        );
        self.scalar.range().gate.assert_equal(
            ctx,
            QuantumCell::Existing(evaluation_limb2),
            QuantumCell::Existing(evaluation_crt.truncation.limbs[1]),
        );
        self.scalar.range().gate.assert_equal(
            ctx,
            QuantumCell::Existing(evaluation_limb3),
            QuantumCell::Existing(evaluation_crt.truncation.limbs[2]),
        );

        ////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////// BARYCENTRIC EVALUATION //////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let mut blob_crts = Vec::with_capacity(BLOB_WIDTH);
        let mut evaluation_computed = self.scalar.load_constant(ctx, fe_to_biguint(&Fr::zero()));
        blob.iter()
            .zip_eq(roots_of_unity.iter())
            .for_each(|(blob_i, root_i_crt)| {
                // assign LE-bytes of blob scalar field element.
                let blob_i_le = self.scalar.range().gate.assign_witnesses(
                    ctx,
                    blob_i
                        .to_le_bytes()
                        .iter()
                        .map(|&x| Value::known(Fr::from(x as u64))),
                );
                let blob_i_scalar = Scalar::from_raw(blob_i.0);
                let blob_i_crt = self
                    .scalar
                    .load_private(ctx, Value::known(fe_to_biguint(&blob_i_scalar).into()));

                // compute the limbs for blob scalar field element.
                let limb1 = self.scalar.range().gate.inner_product(
                    ctx,
                    blob_i_le[0..11].iter().map(|&x| QuantumCell::Existing(x)),
                    powers_of_256[0..11].to_vec(),
                );
                let limb2 = self.scalar.range().gate.inner_product(
                    ctx,
                    blob_i_le[11..22].iter().map(|&x| QuantumCell::Existing(x)),
                    powers_of_256[0..11].to_vec(),
                );
                let limb3 = self.scalar.range().gate.inner_product(
                    ctx,
                    blob_i_le[22..32].iter().map(|&x| QuantumCell::Existing(x)),
                    powers_of_256[0..11].to_vec(),
                );
                self.scalar.range().gate.assert_equal(
                    ctx,
                    QuantumCell::Existing(limb1),
                    QuantumCell::Existing(blob_i_crt.truncation.limbs[0]),
                );
                self.scalar.range().gate.assert_equal(
                    ctx,
                    QuantumCell::Existing(limb2),
                    QuantumCell::Existing(blob_i_crt.truncation.limbs[1]),
                );
                self.scalar.range().gate.assert_equal(
                    ctx,
                    QuantumCell::Existing(limb3),
                    QuantumCell::Existing(blob_i_crt.truncation.limbs[2]),
                );

                // the most-significant byte of blob scalar field element is 0 as we expect this
                // representation to be in its canonical form.
                self.scalar.range().gate.assert_equal(
                    ctx,
                    QuantumCell::Existing(blob_i_le[31]),
                    QuantumCell::Constant(Fr::zero()),
                );

                // a = int(polynomial[i]) * int(roots_of_unity_brp[i]) % BLS_MODULUS
                let a = self.scalar.mul(ctx, &blob_i_crt, root_i_crt);

                // b = (int(BLS_MODULUS) + int(z) - int(roots_of_unity_brp[i])) % BLS_MODULUS
                let b = self.scalar.sub_no_carry(ctx, &challenge_crt, root_i_crt);
                let b = self.scalar.carry_mod(ctx, &b);

                // y += int(div(a, b) % BLS_MODULUS)
                let a_by_b = self.scalar.divide(ctx, &a, &b);
                evaluation_computed = self.scalar.add_no_carry(ctx, &evaluation_computed, &a_by_b);
                evaluation_computed = self.scalar.carry_mod(ctx, &evaluation_computed);
                blob_crts.push(blob_i_crt);
            });

        let z_to_blob_width = (0..LOG_BLOB_WIDTH).fold(challenge_crt.clone(), |acc, _| {
            self.scalar.mul(ctx, &acc, &acc)
        });
        let z_to_blob_width_minus_one = self.scalar.sub_no_carry(ctx, &z_to_blob_width, &one);
        let z_to_blob_width_minus_one = self.scalar.carry_mod(ctx, &z_to_blob_width_minus_one);
        let factor = self
            .scalar
            .divide(ctx, &z_to_blob_width_minus_one, &blob_width);
        evaluation_computed = self.scalar.mul(ctx, &evaluation_computed, &factor);
        evaluation_computed = self.scalar.carry_mod(ctx, &evaluation_computed);

        // computed evaluation matches the expected evaluation.
        self.scalar
            .assert_equal(ctx, &evaluation_computed, &evaluation_crt);

        ////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////// EXPORT //////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        AssignedBarycentricEvaluationConfig {
            barycentric_assignments: blob_crts
                .into_iter()
                .chain(std::iter::once(challenge_digest_crt))
                .collect(),
            z_le: challenge_le,
            y_le: evaluation_le,
        }
    }
}

pub fn interpolate(z: Scalar, coefficients: &[Scalar; BLOB_WIDTH]) -> Scalar {
    let blob_width = u64::try_from(BLOB_WIDTH).unwrap();
    (z.pow(&[blob_width, 0, 0, 0]) - Scalar::one())
        * ROOTS_OF_UNITY
            .iter()
            .zip_eq(coefficients)
            .map(|(root, f)| f * root * (z - root).invert().unwrap())
            .sum::<Scalar>()
        * Scalar::from(blob_width).invert().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        blob::{BatchData, KZG_TRUSTED_SETUP},
        MAX_AGG_SNARKS,
    };
    use c_kzg::{Blob as RethBlob, KzgProof};
    use std::collections::BTreeSet;

    #[test]
    fn log_blob_width() {
        assert_eq!(2_usize.pow(LOG_BLOB_WIDTH.try_into().unwrap()), BLOB_WIDTH);
    }

    #[test]
    fn scalar_field_modulus() {
        let bls_modulus = *BLS_MODULUS;
        // BLS_MODULUS as decimal string from https://eips.ethereum.org/EIPS/eip-4844.
        let expected_bls_modulus = U256::from_str_radix(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
            10,
        )
        .unwrap();
        assert_eq!(bls_modulus, expected_bls_modulus);
    }

    #[test]
    fn roots_of_unity() {
        for root_of_unity in ROOTS_OF_UNITY.iter() {
            assert_eq!(
                root_of_unity.pow(&[BLOB_WIDTH.try_into().unwrap(), 0, 0, 0]),
                Scalar::one()
            );
        }
        assert_eq!(
            ROOTS_OF_UNITY.iter().collect::<BTreeSet<_>>().len(),
            BLOB_WIDTH
        );
    }

    #[test]
    fn interpolate_matches_reth_implementation() {
        let batch = BatchData::<MAX_AGG_SNARKS>::from(&vec![
            vec![30; 56],
            vec![200; 100],
            vec![0; 340],
            vec![10; 23],
        ]);

        for z in 0..10 {
            let z = Scalar::from(u64::try_from(13241234 + z).unwrap());
            assert_eq!(
                reth_point_evaluation(z, &batch.get_coefficients().map(|c| Scalar::from_raw(c.0))),
                interpolate(z, &batch.get_coefficients().map(|c| Scalar::from_raw(c.0)))
            );
        }
    }

    fn reth_point_evaluation(z: Scalar, coefficients: &[Scalar]) -> Scalar {
        assert_eq!(coefficients.len(), BLOB_WIDTH);
        let blob = RethBlob::from_bytes(
            &coefficients
                .iter()
                .cloned()
                .flat_map(to_be_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let (_proof, y) =
            KzgProof::compute_kzg_proof(&blob, &to_be_bytes(z).into(), &KZG_TRUSTED_SETUP).unwrap();
        from_canonical_be_bytes(*y)
    }

    #[test]
    fn reth_kzg_implementation() {
        // check that we are calling the reth implementation correctly
        for z in 0..10 {
            let z = Scalar::from(u64::try_from(z).unwrap());
            assert_eq!(reth_point_evaluation(z, &ROOTS_OF_UNITY), z)
        }
    }

    fn to_be_bytes(x: Scalar) -> [u8; 32] {
        let mut bytes = x.to_bytes();
        bytes.reverse();
        bytes
    }

    fn from_canonical_be_bytes(bytes: [u8; 32]) -> Scalar {
        let mut bytes = bytes;
        bytes.reverse();
        Scalar::from_bytes(&bytes).expect("non-canonical bytes")
    }

    #[test]
    fn test_be_bytes() {
        let mut be_bytes_one = [0; 32];
        be_bytes_one[31] = 1;
        assert_eq!(to_be_bytes(Scalar::one()), be_bytes_one);
    }
}
