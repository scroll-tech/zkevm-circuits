//! This module implements the ECDSA circuit. Modified from
//! <https://github.com/scroll-tech/halo2-lib/blob/530e744232860641f9533c9b9f8c1fee57f54cab/halo2-ecc/src/ecc/ecdsa.rs#L16>

use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::{BigPrimeField, CurveAffineExt},
    AssignedValue, Context,
    QuantumCell::{self, Existing},
};
use halo2_ecc::{
    bigint::{big_less_than, FixedOverflowInteger, ProperCrtUint},
    ecc::{fixed_base, scalar_multiply, EcPoint, EccChip},
    fields::{fp::FpChip, FieldChip, Selectable},
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
pub(crate) fn ecdsa_verify_no_pubkey_check<
    F: BigPrimeField,
    CF: BigPrimeField,
    SF: BigPrimeField,
    GA,
>(
    chip: &EccChip<F, FpChip<F, CF>>,
    ctx: &mut Context<F>,
    pubkey: &EcPoint<F, <FpChip<F, CF> as FieldChip<F>>::FieldPoint>,
    r: &ProperCrtUint<F>,
    s: &ProperCrtUint<F>,
    msghash: &ProperCrtUint<F>,
    var_window_bits: usize,
    fixed_window_bits: usize,
) -> (AssignedValue<F>, AssignedValue<F>, ProperCrtUint<F>)
where
    GA: CurveAffineExt<Base = CF, ScalarExt = SF>,
{
    let base_chip = chip.field_chip;
    let scalar_chip =
        FpChip::<F, SF>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);
    let n = scalar_chip.p.to_biguint().unwrap();
    let n = FixedOverflowInteger::from_native(&n, scalar_chip.num_limbs, scalar_chip.limb_bits);
    let n = n.assign(ctx);

    // check whether the pubkey is (0, 0), i.e. in the case of ecrecover, no pubkey could be
    // recovered.
    let (is_pubkey_zero, is_pubkey_not_zero) = {
        let is_pubkey_x_zero = base_chip.is_zero(ctx, &pubkey.x);
        let is_pubkey_y_zero = base_chip.is_zero(ctx, &pubkey.y);
        let is_pubkey_zero = base_chip.range().gate().and(
            ctx,
            Existing(is_pubkey_x_zero),
            Existing(is_pubkey_y_zero),
        );
        (
            is_pubkey_zero,
            base_chip.range().gate().not(ctx, Existing(is_pubkey_zero)),
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
    let zero = scalar_chip.load_constant(ctx, SF::ZERO);
    let one = scalar_chip.load_constant(ctx, SF::ONE);
    let base_zero = base_chip.load_constant(ctx, CF::ONE);
    let point_at_infinity = EcPoint::new(base_zero.clone(), base_zero);

    // compute u1 = m * s^{-1} mod n
    let s_prime = scalar_chip.select(ctx, one.clone(), s.clone(), s_is_zero);
    let u1 = scalar_chip.divide(ctx, msghash, &s_prime);
    let u1 = scalar_chip.select(ctx, zero.clone(), u1, s_is_zero);

    // compute u2 = r * s^{-1} mod n
    let u2 = scalar_chip.divide(ctx, r, &s_prime);
    let u2 = scalar_chip.select(ctx, zero.clone(), u2, s_is_zero);

    // we want to compute u1*G + u2*PK, there are two edge cases
    // 1. either u1 or u2 is 0; we use binary selections to handle the this case
    // 2. or u1*G + u2*PK is an infinity point; this is computed with paddings

    // =================================
    // case 1:
    // =================================
    let u1_is_zero = scalar_chip.is_zero(ctx, &u1);
    let u1_prime = scalar_chip.select(ctx, one.clone(), u1.clone(), u1_is_zero);
    let u1_mul = fixed_base::scalar_multiply::<F, _, GA>(
        base_chip,
        ctx,
        &GA::generator(),
        u1_prime.limbs().to_vec(),
        base_chip.limb_bits,
        fixed_window_bits,
    );
    let u1_mul = chip.select(ctx, point_at_infinity.clone(), u1_mul, u1_is_zero);

    // compute u2 * pubkey
    let u2_prime = scalar_chip.select(ctx, one.clone(), u2.clone(), s_is_zero);
    let pubkey_prime = chip.load_random_point::<GA>(ctx);
    let pubkey_prime = chip.select(ctx, pubkey_prime, pubkey.clone(), is_pubkey_zero);
    let u2_mul = scalar_multiply::<F, _, GA>(
        base_chip,
        ctx,
        pubkey_prime,
        u2_prime.limbs().to_vec(),
        base_chip.limb_bits,
        var_window_bits,
    );
    let u2_is_zero =
        base_chip
            .range()
            .gate()
            .or(ctx, Existing(s_is_zero), Existing(is_pubkey_zero));
    let u2_mul = chip.select(ctx, point_at_infinity, u2_mul, u2_is_zero);

    // =================================
    // case 2:
    // =================================
    // u1.G == (u1_mul_x, u1_mul_y) and u2.Pk == (u2_mul_x, u2_mul_y)
    //
    // u1.G + u2.Pk == point_at_infinity iff:
    // - (u1_is_zero AND u2_is_zero) OR
    // - (u1_mul_x == u2_mul_x) AND (u1_mul_y == neg(u2_mul_y))
    let u1_u2_are_zero =
        base_chip
            .range()
            .gate()
            .and(ctx, Existing(u1_is_zero), Existing(u2_is_zero));
    let u1_u2_x_eq = base_chip.is_equal(ctx, u1_mul.x(), u2_mul.x());
    let u1_u2_y_neg = {
        let u2_y_neg = base_chip.negate(ctx, u2_mul.y().clone());
        base_chip.is_equal(ctx, u1_mul.y(), &u2_y_neg)
    };
    let sum_is_infinity = base_chip.range().gate().or_and(
        ctx,
        Existing(u1_u2_are_zero),
        Existing(u1_u2_x_eq),
        Existing(u1_u2_y_neg),
    );
    let sum_is_not_infinity = base_chip
        .gate()
        .not(ctx, QuantumCell::Existing(sum_is_infinity));

    // For a valid ECDSA signature, the x co-ordinate of u1.G + u2.Pk, i.e. x_3, MUST EQUAL r
    //
    // For ec_add:
    // P:(x_1, y_1) + Q:(x_2, y_2) == (x_3, y_3) we have:
    // - lambda == (y_2 - y_1) / (x_2 - x_1) (mod n)
    // - x_3 == (lambda * lambda) - x_1 - x_2 (mod n)
    // - y_3 == lambda * (x_1 - x_3) - y_1 (mod n)
    let (x_3, y_3) = {
        // we implement divide_unsafe in a non-panicking way, lambda = dy/dx (mod n)
        let dx = base_chip.sub_no_carry(ctx, u2_mul.x(), u1_mul.x());
        let dy = base_chip.sub_no_carry(ctx, u2_mul.y(), u1_mul.y());
        let lambda = {
            let a_val = base_chip.get_assigned_value(&dy);
            let b_val = base_chip.get_assigned_value(&dx);
            let b_inv = b_val.invert().unwrap_or(CF::ZERO);
            let quot_val = a_val * b_inv;
            let quot = base_chip.load_private(ctx, quot_val);
            // constrain quot * b - a = 0 mod p
            let quot_b = base_chip.mul_no_carry(ctx, &quot, &dx);
            let quot_constraint = base_chip.sub_no_carry(ctx, &quot_b, &dy);
            base_chip.check_carry_mod_to_zero(ctx, quot_constraint);
            quot
        };
        let lambda_sq = base_chip.mul_no_carry(ctx, &lambda, &lambda);
        let lambda_sq_minus_px = base_chip.sub_no_carry(ctx, &lambda_sq, u1_mul.x());
        let x_3_no_carry = base_chip.sub_no_carry(ctx, &lambda_sq_minus_px, u2_mul.x());
        let x_3 = base_chip.carry_mod(ctx, x_3_no_carry);
        let dx_13 = base_chip.sub_no_carry(ctx, u1_mul.x(), &x_3);
        let lambda_dx_13 = base_chip.mul_no_carry(ctx, &lambda, &dx_13);
        let y_3_no_carry = base_chip.sub_no_carry(ctx, &lambda_dx_13, u1_mul.y());
        let y_3 = base_chip.carry_mod(ctx, y_3_no_carry);

        // edge cases
        let x_3 = base_chip.select(ctx, u2_mul.x().clone(), x_3, u1_is_zero);
        let x_3 = base_chip.select(ctx, u1_mul.x().clone(), x_3, u2_is_zero);
        let x_3 = base_chip.select(ctx, zero.clone(), x_3, sum_is_infinity);
        let y_3 = base_chip.select(ctx, u2_mul.y().clone(), y_3, u1_is_zero);
        let y_3 = base_chip.select(ctx, u1_mul.y().clone(), y_3, u2_is_zero);
        let y_3 = base_chip.select(ctx, zero, y_3, sum_is_infinity);

        (x_3, y_3)
    };
    let equal_check = base_chip.is_equal(ctx, &x_3, r);

    // TODO: maybe the big_less_than is optional?
    let u1_small = big_less_than::assign::<F>(
        base_chip.range(),
        ctx,
        u1,
        n.clone(),
        base_chip.limb_bits,
        base_chip.limb_bases[1],
    );
    let u2_small = big_less_than::assign::<F>(
        base_chip.range(),
        ctx,
        u2,
        n.clone(),
        base_chip.limb_bits,
        base_chip.limb_bases[1],
    );

    // check
    // - (r in [0, n - 1])
    // - (s in [0, n - 1])
    // - (u1_mul != - u2_mul)
    // - (r == x1 mod n)
    // - pk != (0, 0)
    let res1 = base_chip.gate().and(ctx, r_is_valid, s_is_valid);
    let res2 = base_chip.gate().and(ctx, res1, u1_small);
    let res3 = base_chip.gate().and(ctx, res2, u2_small);
    let res4 = base_chip.gate().and(ctx, res3, sum_is_not_infinity);
    let res5 = base_chip.gate().and(ctx, res4, equal_check);
    let res6 = base_chip.gate().and(ctx, res5, is_pubkey_not_zero);

    (res6, is_pubkey_zero, y_3)
}
