//! This module implements the ECDSA circuit. Modified from
//! <https://github.com/scroll-tech/halo2-lib/blob/530e744232860641f9533c9b9f8c1fee57f54cab/halo2-ecc/src/ecc/ecdsa.rs#L16>

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{modulus, CurveAffineExt},
    AssignedValue, Context,
    QuantumCell::Existing,
};
use halo2_ecc::{
    bigint::{big_less_than, CRTInteger},
    ecc::{ec_add_unequal, fixed_base, scalar_multiply, EcPoint},
    fields::{fp::FpConfig, FieldChip, PrimeField},
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
) -> (AssignedValue<F>, CRTInteger<F>)
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let scalar_chip = FpConfig::<F, SF>::construct(
        base_chip.range.clone(),
        base_chip.limb_bits,
        base_chip.num_limbs,
        modulus::<SF>(),
    );
    let n = scalar_chip.load_constant(ctx, scalar_chip.p.to_biguint().unwrap());

    // check r,s are in [1, n - 1]
    let r_valid = scalar_chip.is_soft_nonzero(ctx, r);
    let s_valid = scalar_chip.is_soft_nonzero(ctx, s);

    // compute u1 = m s^{-1} mod n and u2 = r s^{-1} mod n
    let u1 = scalar_chip.divide(ctx, msghash, s);
    let u2 = scalar_chip.divide(ctx, r, s);

    //let r_crt = scalar_chip.to_crt(ctx, r)?;

    // compute u1 * G and u2 * pubkey
    let u1_mul = fixed_base::scalar_multiply::<F, _, _>(
        base_chip,
        ctx,
        &GA::generator(),
        &u1.truncation.limbs,
        base_chip.limb_bits,
        fixed_window_bits,
    );
    let u2_mul = scalar_multiply::<F, _>(
        base_chip,
        ctx,
        pubkey,
        &u2.truncation.limbs,
        base_chip.limb_bits,
        var_window_bits,
    );

    // check u1 * G and u2 * pubkey are not negatives and not equal
    //     TODO: Technically they could be equal for a valid signature, but this happens with
    // vanishing probability           for an ECDSA signature constructed in a standard way
    // coordinates of u1_mul and u2_mul are in proper bigint form, and lie in but are not
    // constrained to [0, n) we therefore need hard inequality here
    let u1_u2_x_eq = base_chip.is_equal(ctx, &u1_mul.x, &u2_mul.x);
    let u1_u2_not_neg = base_chip.range.gate().not(ctx, Existing(u1_u2_x_eq));

    // compute (x1, y1) = u1 * G + u2 * pubkey and check (r mod n) == x1 as integers
    // WARNING: For optimization reasons, does not reduce x1 mod n, which is
    //          invalid unless p is very close to n in size.
    base_chip.enforce_less_than_p(ctx, u1_mul.x());
    base_chip.enforce_less_than_p(ctx, u2_mul.x());
    let sum = ec_add_unequal(base_chip, ctx, &u1_mul, &u2_mul, false);
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

    // check (r in [1, n - 1]) and (s in [1, n - 1]) and (u1_mul != - u2_mul) and (r == x1 mod n)
    let res1 = base_chip
        .range
        .gate()
        .and(ctx, Existing(r_valid), Existing(s_valid));
    let res2 = base_chip
        .range
        .gate()
        .and(ctx, Existing(res1), Existing(u1_small));
    let res3 = base_chip
        .range
        .gate()
        .and(ctx, Existing(res2), Existing(u2_small));
    let res4 = base_chip
        .range
        .gate()
        .and(ctx, Existing(res3), Existing(u1_u2_not_neg));
    let res5 = base_chip
        .range
        .gate()
        .and(ctx, Existing(res4), Existing(equal_check));
    (res5, sum.y)
}
