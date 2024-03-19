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
    blob::{BLOB_WIDTH, LOG_BLOG_WIDTH},
    constants::{BITS, LIMBS},
};

mod scalar_field_element;
use scalar_field_element::ScalarFieldElement;

pub static ROOTS_OF_UNITY: LazyLock<[Scalar; BLOB_WIDTH]> = LazyLock::new(|| {
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#constants
    let primitive_root_of_unity = Scalar::from(7);
    let modulus = U256::from_str_radix(Scalar::MODULUS, 16).unwrap();

    let exponent = (modulus - U256::one()) / U256::from(4096);
    let root_of_unity = primitive_root_of_unity.pow(&exponent.0);

    let ascending_order: Vec<_> = successors(Some(Scalar::one()), |x| Some(*x * root_of_unity))
        .take(BLOB_WIDTH)
        .collect();
    let bit_reversed_order: Vec<_> = (0..BLOB_WIDTH)
        .map(|i| {
            let j = u16::try_from(i).unwrap().reverse_bits() >> (16 - LOG_BLOG_WIDTH);
            ascending_order[usize::try_from(j).unwrap()]
        })
        .collect();
    bit_reversed_order.try_into().unwrap()
});

#[derive(Clone, Debug)]
pub struct BarycentricEvaluationConfig {
    pub scalar: FpConfig<Fr, Scalar>,
}

#[allow(dead_code)]
pub struct BarycentricEvaluationAssignments {
    z: CRTInteger<Fr>,
    y: CRTInteger<Fr>,
    blob: [CRTInteger<Fr>; BLOB_WIDTH],
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

    pub fn assign2(
        &self,
        ctx: &mut Context<Fr>,
        blob: [U256; BLOB_WIDTH],
        challenge_digest: U256,
        evaluation: U256,
    ) -> (
        Vec<CRTInteger<Fr>>,
        Vec<AssignedValue<Fr>>,
        Vec<AssignedValue<Fr>>,
    ) {
        // prechecks (challenge point z)
        let bls_modulus = U256::from_dec_str(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513",
        )
        .expect("BLS_MODULUS from decimal string");
        let (_, challenge) = challenge_digest.div_mod(bls_modulus);
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

        // prechecks (evaluation y)
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
        let powers_of_256 =
            std::iter::successors(Some(Fr::one()), |coeff| Some(Fr::from(256) * coeff))
                .take(32)
                .map(QuantumCell::Constant)
                .collect::<Vec<_>>();
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
            powers_of_256[11..22].to_vec(),
        );
        let challenge_limb3 = self.scalar.range().gate.inner_product(
            ctx,
            challenge_le[22..32]
                .iter()
                .map(|&x| QuantumCell::Existing(x)),
            powers_of_256[22..32].to_vec(),
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
            powers_of_256[11..22].to_vec(),
        );
        let evaluation_limb3 = self.scalar.range().gate.inner_product(
            ctx,
            evaluation_le[22..32]
                .iter()
                .map(|&x| QuantumCell::Existing(x)),
            powers_of_256[22..32].to_vec(),
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

        // compute evaluation.
        let mut blob_crts = Vec::with_capacity(BLOB_WIDTH);
        let mut evaluation_computed = self.scalar.load_constant(ctx, fe_to_biguint(&Fr::zero()));
        blob.iter()
            .zip_eq(ROOTS_OF_UNITY.map(|x| self.scalar.load_constant(ctx, fe_to_biguint(&x))))
            .for_each(|(blob_i, root_i_crt)| {
                let blob_i_le = blob_i
                    .to_le_bytes()
                    .iter()
                    .map(|&x| QuantumCell::Witness(Value::known(Fr::from(x as u64))))
                    .collect::<Vec<_>>();
                let blob_i_scalar = Scalar::from_raw(blob_i.0);
                let blob_i_crt = self
                    .scalar
                    .load_private(ctx, Value::known(fe_to_biguint(&blob_i_scalar).into()));
                let limb1 = self.scalar.range().gate.inner_product(
                    ctx,
                    blob_i_le[0..11].to_vec(),
                    powers_of_256[0..11].to_vec(),
                );
                let limb2 = self.scalar.range().gate.inner_product(
                    ctx,
                    blob_i_le[11..22].to_vec(),
                    powers_of_256[11..22].to_vec(),
                );
                let limb3 = self.scalar.range().gate.inner_product(
                    ctx,
                    blob_i_le[22..32].to_vec(),
                    powers_of_256[22..32].to_vec(),
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
                self.scalar.range().gate.assert_equal(
                    ctx,
                    blob_i_le[31].clone(),
                    QuantumCell::Constant(Fr::zero()),
                );

                // a = int(polynomial[i]) * int(roots_of_unity_brp[i]) % BLS_MODULUS
                let a = self.scalar.mul(ctx, &blob_i_crt, &root_i_crt);

                // b = (int(BLS_MODULUS) + int(z) - int(roots_of_unity_brp[i])) % BLS_MODULUS
                let b = self.scalar.sub_no_carry(ctx, &challenge_crt, &root_i_crt);
                let b = self.scalar.carry_mod(ctx, &b);

                // y += int(div(a, b) % BLS_MODULUS)
                let a_by_b = self.scalar.divide(ctx, &a, &b);
                evaluation_computed = self.scalar.add_no_carry(ctx, &evaluation_computed, &a_by_b);
                evaluation_computed = self.scalar.carry_mod(ctx, &evaluation_computed);
                blob_crts.push(blob_i_crt);
            });

        let one = self.scalar.load_constant(ctx, fe_to_biguint(&Fr::one()));
        let blob_width = self
            .scalar
            .load_constant(ctx, fe_to_biguint(&Fr::from(BLOB_WIDTH as u64)));
        let z_to_blob_width = (0..LOG_BLOG_WIDTH).fold(challenge_crt.clone(), |acc, _| {
            self.scalar.mul(ctx, &acc, &acc)
        });
        let z_to_blob_width_minus_one = self.scalar.sub_no_carry(ctx, &z_to_blob_width, &one);
        let z_to_blob_width_minus_one = self.scalar.carry_mod(ctx, &z_to_blob_width_minus_one);
        let factor = self
            .scalar
            .divide(ctx, &z_to_blob_width_minus_one, &blob_width);
        evaluation_computed = self.scalar.mul(ctx, &evaluation_computed, &factor);
        evaluation_computed = self.scalar.carry_mod(ctx, &evaluation_computed);

        // The evaluation we computed is correct.
        self.scalar
            .assert_equal(ctx, &evaluation_computed, &evaluation_crt);

        (
            blob_crts
                .into_iter()
                .chain(std::iter::once(challenge_digest_crt))
                .chain(std::iter::once(challenge_crt))
                .chain(std::iter::once(evaluation_crt))
                .collect(),
            challenge_le,
            evaluation_le,
        )
    }

    pub fn assign(
        &self,
        ctx: &mut Context<Fr>,
        blob: [Scalar; BLOB_WIDTH],
        z: Scalar,
    ) -> BarycentricEvaluationAssignments {
        let one = ScalarFieldElement::constant(Scalar::one());
        let blob_width = ScalarFieldElement::constant(u64::try_from(BLOB_WIDTH).unwrap().into());

        let z = self
            .scalar
            .load_private(ctx, Value::known(fe_to_biguint(&z).into()));
        let blob = blob.map(|e| {
            self.scalar
                .load_private(ctx, Value::known(fe_to_biguint(&e).into()))
        });
        let z_to_blob_width = successors(Some(ScalarFieldElement::private(z.clone())), |z| {
            Some(z.clone() * z.clone())
        })
        .take(LOG_BLOG_WIDTH)
        .last()
        .unwrap();
        let y = (z_to_blob_width - one)
            * ROOTS_OF_UNITY
                .map(ScalarFieldElement::constant)
                .into_iter()
                .zip_eq(blob.clone().map(ScalarFieldElement::private))
                .map(|(root, f)| {
                    f * (root.clone() / (ScalarFieldElement::private(z.clone()) - root)).carry()
                })
                .sum()
            / blob_width;

        BarycentricEvaluationAssignments {
            z,
            y: y.resolve(ctx, &self.scalar),
            blob,
        }
    }
}

pub fn interpolate(z: Scalar, coefficients: [Scalar; BLOB_WIDTH]) -> Scalar {
    let blob_width = u64::try_from(BLOB_WIDTH).unwrap();
    (z.pow(&[blob_width, 0, 0, 0]) - Scalar::one())
        * ROOTS_OF_UNITY
            .into_iter()
            .zip_eq(coefficients)
            .map(|(root, f)| f * root * (z - root).invert().unwrap())
            .sum::<Scalar>()
        * Scalar::from(blob_width).invert().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn log_blob_width() {
        assert_eq!(2_usize.pow(LOG_BLOG_WIDTH.try_into().unwrap()), BLOB_WIDTH);
    }

    #[test]
    fn scalar_field_modulus() {
        let bls_modulus = U256::from_str_radix(Scalar::MODULUS, 16).unwrap();
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
}
