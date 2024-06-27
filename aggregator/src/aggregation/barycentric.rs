use aggregator_snark_verifier::loader::halo2::IntegerInstructions;
use aggregator_snark_verifier::{
    halo2_base::{
        gates::{
            circuit::BaseCircuitBuilder,
            flex_gate::GateChip,
            range::{RangeChip, RangeConfig},
            GateInstructions,
        },
        halo2_proofs::circuit::Value,
        utils::{decompose_biguint, fe_to_biguint, modulus},
        AssignedValue, QuantumCell,
    },
    halo2_ecc::{
        bigint::{CRTInteger, OverflowInteger},
        fields::{
            fp::{FpChip, FpConfig},
            FieldChip,
        },
        halo2_base::{utils::decompose_bigint_option, Context},
    },
};
use eth_types::{ToLittleEndian, U256};
use halo2curves::{bls12_381::Scalar, bn256::Fr, ff::PrimeField};
use itertools::Itertools;
use num_bigint::{BigInt, BigUint, Sign};
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
    pub scalar: FpConfig<Fr>,
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
            // scalar: FpConfig::construct(range, BITS, LIMBS, modulus::<Scalar>()),
            scalar: range,
        }
    }

    fn load_u256(&self, ctx: &mut Context<Fr>, a: U256) -> CRTInteger<Fr> {
        // borrowed from halo2-ecc/src/fields/fp.rs
        // similar to FpChip.load_private without range check.
        let a = BigUint::from_bytes_le(&a.to_le_bytes());
        let a_vec = decompose_biguint::<Fr>(&a, LIMBS, BITS);
        let limbs = ctx.assign_witnesses(a_vec);

        // TODO: probably this will panic because it's not fully built.
        let builder = BaseCircuitBuilder::default();
        let fp_chip = FpChip::<Fr, Scalar>::new(&builder.range_chip(), BITS, LIMBS);
        let a_native =
            OverflowInteger::<Fr>::evaluate_native(ctx, fp_chip.gate(), limbs, &fp_chip.limb_bases);

        CRTInteger::new(OverflowInteger::new(limbs, BITS), a_native, a.into())
    }

    pub fn assign(
        &self,
        ctx: &mut Context<Fr>,
        blob: &[U256; BLOB_WIDTH],
        challenge_digest: U256,
        evaluation: U256,
    ) -> AssignedBarycentricEvaluationConfig {
        // some constants for later use.
        // todo: move builder up...
        let builder = BaseCircuitBuilder::default();
        let fp_chip = FpChip::<Fr, Scalar>::new(&builder.range_chip(), BITS, LIMBS);

        let one = fp_chip.load_constant(ctx, Scalar::one());
        let blob_width =
            fp_chip.load_constant(ctx, Scalar::from(u64::try_from(BLOB_WIDTH).unwrap()));

        let powers_of_256 =
            std::iter::successors(Some(Fr::one()), |coeff| Some(Fr::from(256) * coeff))
                .take(11)
                .map(QuantumCell::Constant)
                .collect::<Vec<_>>();

        let roots_of_unity = ROOTS_OF_UNITY
            .iter()
            .map(|&x| fp_chip.load_constant(ctx, x))
            .collect::<Vec<_>>();

        ////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// PRECHECKS z /////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////

        let (_, challenge) = challenge_digest.div_mod(*BLS_MODULUS);
        let challenge_scalar = Scalar::from_raw(challenge.0);

        let challenge_digest_crt = self.load_u256(ctx, challenge_digest);
        let challenge_le =
            ctx.assign_witnesses(challenge.to_le_bytes().iter().map(|&x| Fr::from(x as u64)));
        assert_le_bytes_equal_crt(
            ctx,
            fp_chip.gate(),
            &challenge_le,
            &challenge_digest_crt,
            &powers_of_256,
        );

        let challenge_digest_mod = fp_chip.carry_mod(ctx, &challenge_digest_crt);
        let challenge_crt = fp_chip.load_private(ctx, challenge_scalar);
        fp_chip.assert_equal(ctx, &challenge_digest_mod, &challenge_crt);

        ////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// PRECHECKS y /////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let evaluation_le = ctx.assign_witnesses(
            evaluation
                .to_le_bytes()
                .iter()
                .map(|&x| Fr::from(u64::from(x))),
        );
        let evaluation_crt = fp_chip.load_private(
            ctx,
            Value::known(fe_to_biguint(&Scalar::from_raw(evaluation.0)).into()),
        );

        assert_le_bytes_equal_crt(
            ctx,
            fp_chip.gate(),
            &evaluation_le,
            &evaluation_crt,
            &powers_of_256,
        );

        ////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////// BARYCENTRIC EVALUATION //////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        let mut blob_crts = Vec::with_capacity(BLOB_WIDTH);
        let mut evaluation_computed = fp_chip.load_constant(ctx, Scalar::zero());
        blob.iter()
            .zip_eq(roots_of_unity.iter())
            .for_each(|(blob_i, root_i_crt)| {
                // assign LE-bytes of blob scalar field element.
                let blob_i_le = ctx
                    .assign_witnesses(blob_i.to_le_bytes().iter().map(|&x| Fr::from(u64::from(x))));
                let blob_i_scalar = Scalar::from_raw(blob_i.0);
                let blob_i_crt = fp_chip.load_private(ctx, fe_to_biguint(&blob_i_scalar));

                assert_le_bytes_equal_crt(
                    ctx,
                    fp_chip.gate(),
                    &blob_i_le,
                    &blob_i_crt,
                    &powers_of_256,
                );

                // the most-significant byte of blob scalar field element is 0 as we expect this
                // representation to be in its canonical form.
                fp_chip.gate().assert_equal(ctx, &blob_i_le[31], Fr::zero());

                // a = int(polynomial[i]) * int(roots_of_unity_brp[i]) % BLS_MODULUS
                let a = fp_chip.mul(ctx, &blob_i_crt, root_i_crt);

                // b = (int(BLS_MODULUS) + int(z) - int(roots_of_unity_brp[i])) % BLS_MODULUS
                let b = fp_chip.sub_no_carry(ctx, &challenge_crt, root_i_crt);
                let b = fp_chip.carry_mod(ctx, b);

                // y += int(div(a, b) % BLS_MODULUS)
                let a_by_b = fp_chip.divide(ctx, &a, &b);
                let add_no_carry = fp_chip.add_no_carry(ctx, &evaluation_computed, &a_by_b);
                evaluation_computed = fp_chip.carry_mod(ctx, add_no_carry);
                blob_crts.push(blob_i_crt);
            });

        let z_to_blob_width =
            (0..LOG_BLOB_WIDTH).fold(challenge_crt.clone(), |acc, _| fp_chip.mul(ctx, &acc, &acc));
        let z_to_blob_width_minus_one = fp_chip.sub_no_carry(ctx, &z_to_blob_width, &one);
        let z_to_blob_width_minus_one = fp_chip.carry_mod(ctx, z_to_blob_width_minus_one);
        let factor = fp_chip.divide(ctx, &z_to_blob_width_minus_one, &blob_width);
        evaluation_computed = fp_chip.mul(ctx, &evaluation_computed, &factor);
        evaluation_computed = fp_chip.carry_mod(ctx, evaluation_computed.into());

        // computed evaluation matches the expected evaluation.
        fp_chip.assert_equal(ctx, &evaluation_computed, &evaluation_crt);

        ////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////// EXPORT //////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////
        AssignedBarycentricEvaluationConfig {
            barycentric_assignments: blob_crts
                .into_iter()
                .chain(std::iter::once(ProperCrtUint::from(challenge_digest_crt)))
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

fn assert_le_bytes_equal_crt(
    ctx: &mut Context<Fr>,
    gate: &GateChip<Fr>,
    le_bytes: &[AssignedValue<Fr>],
    crt: &CRTInteger<Fr>,
    powers_of_256: &[QuantumCell<Fr>],
) {
    assert_eq!(le_bytes.len(), 32);
    assert_eq!(powers_of_256.len(), 11);

    for (limb_le_bytes, limb) in [
        le_bytes[0..11].iter(),
        le_bytes[11..22].iter(),
        le_bytes[22..32].iter(),
    ]
    .iter()
    .zip_eq(crt.limbs())
    {
        let limb_from_le_bytes = gate.inner_product(
            ctx,
            limb_le_bytes.map(|&x| QuantumCell::Existing(x)),
            &powers_of_256[..limb_le_bytes.len()],
        );
        gate.assert_equal(ctx, limb, &limb_from_le_bytes);
    }
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
