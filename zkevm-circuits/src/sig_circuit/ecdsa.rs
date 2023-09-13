//! This module implements the ECDSA circuit. Modified from
//! <https://github.com/scroll-tech/halo2-lib/blob/530e744232860641f9533c9b9f8c1fee57f54cab/halo2-ecc/src/ecc/ecdsa.rs#L16>

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{fe_to_biguint, modulus, CurveAffineExt},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use halo2_ecc::{
    bigint::{big_less_than, CRTInteger},
    ecc::{ec_add_unequal, ec_sub_unequal, fixed_base, scalar_multiply, EcPoint, EccChip},
    fields::{fp::FpConfig, FieldChip, PrimeField, Selectable},
};

// CF is the coordinate field of GA
// SF is the scalar field of GA
// p = coordinate field modulus
// n = scalar field modulus
// Only valid when p is very close to n in size (e.g. for Secp256k1)
// returns
// - if the signature is valid
// - the y coordinate for rG (will be used for ECRecovery later)
#[allow(clippy::too_many_arguments)]
pub(crate) fn ecdsa_verify_no_pubkey_check<F: PrimeField, CF: PrimeField, SF: PrimeField, GA>(
    base_chip: &FpConfig<F, CF>,
    ctx: &mut Context<F>,
    pubkey: &EcPoint<F, <FpConfig<F, CF> as FieldChip<F>>::FieldPoint>,
    r: &CRTInteger<F>,
    s: &CRTInteger<F>,
    msghash: &CRTInteger<F>,
    var_window_bits: usize,
    fixed_window_bits: usize,
) -> (
    AssignedValue<F>,
    AssignedValue<F>,
    CRTInteger<F>,
    AssignedValue<F>,
)
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let ecc_chip = EccChip::<F, FpConfig<F, CF>>::construct(base_chip.clone());
    let scalar_chip = FpConfig::<F, SF>::construct(
        base_chip.range.clone(),
        base_chip.limb_bits,
        base_chip.num_limbs,
        modulus::<SF>(),
    );
    let n = scalar_chip.load_constant(ctx, scalar_chip.p.to_biguint().unwrap());

    // check whether the pubkey is (0, 0), i.e. in the case of ecrecover, no pubkey could be
    // recovered.
    let (is_pubkey_zero, is_pubkey_not_zero) = {
        let is_pubkey_x_zero = ecc_chip.field_chip().is_zero(ctx, &pubkey.x);
        let is_pubkey_y_zero = ecc_chip.field_chip().is_zero(ctx, &pubkey.y);
        let is_pubkey_zero = ecc_chip.field_chip().range().gate().and(
            ctx,
            Existing(is_pubkey_x_zero),
            Existing(is_pubkey_y_zero),
        );
        (
            is_pubkey_zero,
            ecc_chip
                .field_chip()
                .range()
                .gate()
                .not(ctx, Existing(is_pubkey_zero)),
        )
    };

    // check r,s are in [1, n - 1]
    let r_is_zero = scalar_chip.is_soft_zero(ctx, r);
    let r_in_range = scalar_chip.is_soft_nonzero(ctx, r);
    let r_is_valid = base_chip
        .range()
        .gate()
        .or(ctx, Existing(r_is_zero), Existing(r_in_range));
    let s_is_zero = scalar_chip.is_soft_zero(ctx, s);
    let s_in_range = scalar_chip.is_soft_nonzero(ctx, s);
    let s_is_valid = base_chip
        .range()
        .gate()
        .or(ctx, Existing(s_is_zero), Existing(s_in_range));

    // load required constants
    let zero = scalar_chip.load_constant(ctx, FpConfig::<F, SF>::fe_to_constant(SF::zero()));
    let one = scalar_chip.load_constant(ctx, FpConfig::<F, SF>::fe_to_constant(SF::one()));
    let neg_one = scalar_chip.load_constant(ctx, FpConfig::<F, SF>::fe_to_constant(-SF::one()));

    // compute u1 = m * s^{-1} mod n
    let s2 = scalar_chip.select(ctx, &one, s, &s_is_zero);
    let u1 = scalar_chip.divide(ctx, msghash, &s2);
    let u1 = scalar_chip.select(ctx, &zero, &u1, &s_is_zero);
    let u1_is_one = {
        let diff = scalar_chip.sub_no_carry(ctx, &u1, &one);
        let diff = scalar_chip.carry_mod(ctx, &diff);
        scalar_chip.is_zero(ctx, &diff)
    };

    // compute u2 = r * s^{-1} mod n
    let u2 = scalar_chip.divide(ctx, r, &s2);
    let u2 = scalar_chip.select(ctx, &zero, &u2, &s_is_zero);

    // u3 = 1 if u1 == 1
    // u3 = -1 if u1 != 1
    // this ensures u1 + u3 != 0
    let u3 = scalar_chip.select(ctx, &one, &neg_one, &u1_is_one);

    let u1_plus_u3 = scalar_chip.add_no_carry(ctx, &u1, &u3);
    let u1_plus_u3 = scalar_chip.carry_mod(ctx, &u1_plus_u3);

    // compute (u1+u3) * G
    let u1u3_mul = fixed_base::scalar_multiply::<F, _, _>(
        base_chip,
        ctx,
        &GA::generator(),
        &u1_plus_u3.truncation.limbs,
        base_chip.limb_bits,
        fixed_window_bits,
    );
    // compute u2 * pubkey
    let u2_prime = scalar_chip.select(ctx, &one, &u2, &s_is_zero);
    let pubkey_prime = ecc_chip.load_random_point::<GA>(ctx);
    let pubkey_prime = ecc_chip.select(ctx, &pubkey_prime, pubkey, &is_pubkey_zero);
    let u2_mul = scalar_multiply::<F, _>(
        base_chip,
        ctx,
        &pubkey_prime,
        &u2_prime.truncation.limbs,
        base_chip.limb_bits,
        var_window_bits,
    );
    let point_at_infinity = EcPoint::construct(
        ecc_chip
            .field_chip()
            .load_constant(ctx, fe_to_biguint(&CF::zero())),
        ecc_chip
            .field_chip()
            .load_constant(ctx, fe_to_biguint(&CF::zero())),
    );
    let u2_is_zero =
        base_chip
            .range()
            .gate()
            .or(ctx, Existing(s_is_zero), Existing(is_pubkey_zero));
    let u2_mul = ecc_chip.select(ctx, &point_at_infinity, &u2_mul, &u2_is_zero);
    // compute u3*G this is directly assigned for G so no scalar_multiply is required
    let u3_mul = {
        let generator = GA::generator();
        let neg_generator = -generator;
        let generator = ecc_chip.assign_constant_point(ctx, generator);
        let neg_generator = ecc_chip.assign_constant_point(ctx, neg_generator);
        ecc_chip.select(ctx, &generator, &neg_generator, &u1_is_one)
    };

    // compute u2 * pubkey + u3 * G
    base_chip.enforce_less_than_p(ctx, u2_mul.x());
    base_chip.enforce_less_than_p(ctx, u3_mul.x());
    let u2_pk_u3_g = ec_add_unequal(base_chip, ctx, &u2_mul, &u3_mul, false);

    // check
    // - (u1 + u3) * G
    // - u2 * pubkey + u3 * G
    // are not equal
    let u1_u2_x_eq = ecc_chip.is_equal(ctx, &u1u3_mul, &u2_pk_u3_g);
    let u1_u2_not_eq = base_chip.range.gate().not(ctx, Existing(u1_u2_x_eq));

    // compute (x1, y1) = u1 * G + u2 * pubkey and check (r mod n) == x1 as integers
    // which is basically u1u3_mul + u2_mul - u3_mul
    // WARNING: For optimization reasons, does not reduce x1 mod n, which is
    //          invalid unless p is very close to n in size.
    //
    // WARNING: this may be trigger errors if:
    // - u1u3_mul == u2_mul
    //
    // if r is sampled truly from random then this will not happen
    // to completely ensure the correctness we may need to sample u3 from random, but it is quite
    // costly.
    let sum = ec_add_unequal(base_chip, ctx, &u1u3_mul, &u2_mul, false);

    // safe: we have already checked u1.G + u2.pk != 0
    // so u1.G + u3.G + u2.pk != u3.G
    let sum = ec_sub_unequal(base_chip, ctx, &sum, &u3_mul, false);
    let equal_check = base_chip.is_equal(ctx, &sum.x, r);

    // TODO: maybe the big_less_than is optional?
    let u1_small = big_less_than::assign::<F>(
        base_chip.range(),
        ctx,
        &u1.truncation,
        &n.truncation,
        base_chip.limb_bits,
        base_chip.limb_bases[1],
    );
    let u2_small = big_less_than::assign::<F>(
        base_chip.range(),
        ctx,
        &u2.truncation,
        &n.truncation,
        base_chip.limb_bits,
        base_chip.limb_bases[1],
    );

    // check
    // - (r in [0, n - 1])
    // - (s in [0, n - 1])
    // - (u1_mul != - u2_mul)
    // - (r == x1 mod n)
    // - pk != (0, 0)
    let res = base_chip.range().gate().and_many(
        ctx,
        vec![
            Existing(r_is_valid),
            Existing(s_is_valid),
            Existing(u1_small),
            Existing(u2_small),
            Existing(u1_u2_not_eq),
            Existing(equal_check),
            Existing(is_pubkey_not_zero),
        ],
    );

    let y_is_zero = scalar_chip.is_soft_zero(ctx, &sum.y);
    (res, is_pubkey_zero, sum.y, y_is_zero)
}
