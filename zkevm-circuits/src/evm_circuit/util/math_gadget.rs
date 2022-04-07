use crate::{
    evm_circuit::{
        table::{FixedTableTag, Lookup},
        util::{
            self, constraint_builder::ConstraintBuilder, from_bytes, pow_of_two, pow_of_two_expr,
            select, split_u256, split_u256_limb64, sum, Cell,
        },
    },
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, ToScalar, Word};
use halo2_proofs::{
    circuit::Region,
    plonk::{Error, Expression},
};
use std::convert::TryFrom;

/// Returns `1` when `value == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZeroGadget<F> {
    inverse: Cell<F>,
    is_zero: Expression<F>,
}

impl<F: Field> IsZeroGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, value: Expression<F>) -> Self {
        let inverse = cb.query_cell();

        let is_zero = 1.expr() - (value.clone() * inverse.expr());
        // when `value != 0` check `inverse = a.invert()`: value * (1 - value *
        // inverse)
        cb.add_constraint("value ⋅ (1 - value ⋅ value_inv)", value * is_zero.clone());
        // when `value == 0` check `inverse = 0`: `inverse ⋅ (1 - value *
        // inverse)`
        cb.add_constraint(
            "value_inv ⋅ (1 - value ⋅ value_inv)",
            inverse.expr() * is_zero.clone(),
        );

        Self { inverse, is_zero }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: F,
    ) -> Result<F, Error> {
        let inverse = value.invert().unwrap_or(F::zero());
        self.inverse.assign(region, offset, Some(inverse))?;
        Ok(if value.is_zero().into() {
            F::one()
        } else {
            F::zero()
        })
    }
}

/// Returns `1` when `lhs == rhs`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsEqualGadget<F> {
    is_zero: IsZeroGadget<F>,
}

impl<F: Field> IsEqualGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let is_zero = IsZeroGadget::construct(cb, lhs - rhs);

        Self { is_zero }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<F, Error> {
        self.is_zero.assign(region, offset, lhs - rhs)
    }
}

#[derive(Clone, Debug)]
pub struct BatchedIsZeroGadget<F, const N: usize> {
    is_zero: Cell<F>,
    nonempty_witness: Cell<F>,
}

impl<F: Field, const N: usize> BatchedIsZeroGadget<F, N> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, values: [Expression<F>; N]) -> Self {
        let is_zero = cb.query_bool();
        let nonempty_witness = cb.query_cell();

        for value in values.iter() {
            cb.require_zero(
                "is_zero is 0 if there is any non-zero value",
                is_zero.expr() * value.clone(),
            );
        }

        cb.require_zero(
            "is_zero is 1 if values are all zero",
            values.iter().fold(1.expr() - is_zero.expr(), |acc, value| {
                acc * (1.expr() - value.expr() * nonempty_witness.clone().expr())
            }),
        );

        Self {
            is_zero,
            nonempty_witness,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        values: [F; N],
    ) -> Result<F, Error> {
        let is_zero =
            if let Some(inverse) = values.iter().find_map(|value| Option::from(value.invert())) {
                self.nonempty_witness
                    .assign(region, offset, Some(inverse))?;
                F::zero()
            } else {
                F::one()
            };
        self.is_zero.assign(region, offset, Some(is_zero))?;

        Ok(is_zero)
    }
}

/// Construction of 2 256-bit words addition and result, which is useful for
/// opcode ADD, SUB and balance operation
#[derive(Clone, Debug)]
pub(crate) struct AddWordsGadget<F, const N_ADDENDS: usize, const CHECK_OVREFLOW: bool> {
    addends: [util::Word<F>; N_ADDENDS],
    sum: util::Word<F>,
    carry_lo: Cell<F>,
    carry_hi: Option<Cell<F>>,
}

impl<F: Field, const N_ADDENDS: usize, const CHECK_OVREFLOW: bool>
    AddWordsGadget<F, N_ADDENDS, CHECK_OVREFLOW>
{
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        addends: [util::Word<F>; N_ADDENDS],
        sum: util::Word<F>,
    ) -> Self {
        let carry_lo = cb.query_cell();
        let carry_hi = if CHECK_OVREFLOW {
            None
        } else {
            Some(cb.query_cell())
        };

        let addends_lo = &addends
            .iter()
            .map(|addend| from_bytes::expr(&addend.cells[..16]))
            .collect::<Vec<_>>();
        let addends_hi = &addends
            .iter()
            .map(|addend| from_bytes::expr(&addend.cells[16..]))
            .collect::<Vec<_>>();
        let sum_lo = from_bytes::expr(&sum.cells[..16]);
        let sum_hi = from_bytes::expr(&sum.cells[16..]);

        cb.require_equal(
            "sum(addends_lo) == sum_lo + carry_lo ⋅ 2^128",
            sum::expr(addends_lo),
            sum_lo + carry_lo.expr() * pow_of_two_expr(128),
        );
        cb.require_equal(
            if CHECK_OVREFLOW {
                "sum(addends_hi) + carry_lo == sum_hi"
            } else {
                "sum(addends_hi) + carry_lo == sum_hi + carry_hi ⋅ 2^128"
            },
            sum::expr(addends_hi) + carry_lo.expr(),
            if CHECK_OVREFLOW {
                sum_hi
            } else {
                sum_hi + carry_hi.as_ref().unwrap().expr() * pow_of_two_expr(128)
            },
        );

        for carry in if CHECK_OVREFLOW {
            vec![&carry_lo]
        } else {
            vec![&carry_lo, carry_hi.as_ref().unwrap()]
        } {
            cb.require_in_set(
                "carry_lo in 0..N_ADDENDS",
                carry.expr(),
                (0..N_ADDENDS).map(|idx| idx.expr()).collect(),
            );
        }

        Self {
            addends,
            sum,
            carry_lo,
            carry_hi,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        addends: [Word; N_ADDENDS],
        sum: Word,
    ) -> Result<(), Error> {
        for (word, value) in self.addends.iter().zip(addends.iter()) {
            word.assign(region, offset, Some(value.to_le_bytes()))?;
        }
        self.sum.assign(region, offset, Some(sum.to_le_bytes()))?;

        let (addends_lo, addends_hi): (Vec<_>, Vec<_>) = addends.iter().map(split_u256).unzip();
        let (sum_lo, sum_hi) = split_u256(&sum);

        let sum_of_addends_lo = addends_lo
            .into_iter()
            .fold(Word::zero(), |acc, addend_lo| acc + addend_lo);
        let sum_of_addends_hi = addends_hi
            .into_iter()
            .fold(Word::zero(), |acc, addend_hi| acc + addend_hi);

        let carry_lo = (sum_of_addends_lo - sum_lo) >> 128;
        self.carry_lo.assign(region, offset, carry_lo.to_scalar())?;

        if !CHECK_OVREFLOW {
            let carry_hi = (sum_of_addends_hi + carry_lo - sum_hi) >> 128;
            self.carry_hi
                .as_ref()
                .unwrap()
                .assign(region, offset, carry_hi.to_scalar())?;
        }

        Ok(())
    }

    pub(crate) fn addends(&self) -> &[util::Word<F>] {
        &self.addends
    }

    pub(crate) fn sum(&self) -> &util::Word<F> {
        &self.sum
    }

    pub(crate) fn carry(&self) -> &Option<util::Cell<F>> {
        &self.carry_hi
    }
}

/// Construction of 256-bit product by 256-bit multiplicand * 64-bit multiplier,
/// which disallows overflow.
#[derive(Clone, Debug)]
pub(crate) struct MulWordByU64Gadget<F> {
    multiplicand: util::Word<F>,
    product: util::Word<F>,
    carry_lo: [util::Cell<F>; 8],
}

impl<F: Field> MulWordByU64Gadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        multiplicand: util::Word<F>,
        multiplier: Expression<F>,
    ) -> Self {
        let gadget = Self {
            multiplicand,
            product: cb.query_word(),
            carry_lo: cb.query_bytes(),
        };

        let multiplicand_lo = from_bytes::expr(&gadget.multiplicand.cells[..16]);
        let multiplicand_hi = from_bytes::expr(&gadget.multiplicand.cells[16..]);

        let product_lo = from_bytes::expr(&gadget.product.cells[..16]);
        let product_hi = from_bytes::expr(&gadget.product.cells[16..]);

        let carry_lo = from_bytes::expr(&gadget.carry_lo[..8]);

        cb.require_equal(
            "multiplicand_lo ⋅ multiplier == carry_lo ⋅ 2^128 + product_lo",
            multiplicand_lo * multiplier.expr(),
            carry_lo.clone() * pow_of_two_expr(128) + product_lo,
        );

        cb.require_equal(
            "multiplicand_hi ⋅ multiplier + carry_lo == product_hi",
            multiplicand_hi * multiplier.expr() + carry_lo,
            product_hi,
        );

        gadget
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        multiplicand: Word,
        multiplier: u64,
        product: Word,
    ) -> Result<(), Error> {
        self.multiplicand
            .assign(region, offset, Some(multiplicand.to_le_bytes()))?;
        self.product
            .assign(region, offset, Some(product.to_le_bytes()))?;

        let (multiplicand_lo, _) = split_u256(&multiplicand);
        let (product_lo, _) = split_u256(&product);

        let carry_lo = (multiplicand_lo * multiplier - product_lo) >> 128;
        for (cell, byte) in self.carry_lo.iter().zip(
            u64::try_from(carry_lo)
                .map_err(|_| Error::Synthesis)?
                .to_le_bytes()
                .iter(),
        ) {
            cell.assign(region, offset, Some(F::from(*byte as u64)))?;
        }

        Ok(())
    }

    pub(crate) fn product(&self) -> &util::Word<F> {
        &self.product
    }
}

/// Requires that the passed in value is within the specified range.
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER`.
#[derive(Clone, Debug)]
pub struct RangeCheckGadget<F, const N_BYTES: usize> {
    parts: [Cell<F>; N_BYTES],
}

impl<F: Field, const N_BYTES: usize> RangeCheckGadget<F, N_BYTES> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, value: Expression<F>) -> Self {
        let parts = cb.query_bytes();

        // Require that the reconstructed value from the parts equals the
        // original value
        cb.require_equal(
            "Constrain bytes recomposited to value",
            value,
            from_bytes::expr(&parts),
        );

        Self { parts }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: F,
    ) -> Result<(), Error> {
        let bytes = value.to_repr();
        for (idx, part) in self.parts.iter().enumerate() {
            part.assign(region, offset, Some(F::from(bytes[idx] as u64)))?;
        }
        Ok(())
    }
}

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs `< 256**N_BYTES`
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER` to prevent overflow:
/// values are stored in a single field element and two of these are added
/// together.
/// The equation that is enforced is `lhs - rhs == diff - (lt * range)`.
/// Because all values are `<= 256**N_BYTES` and `lt` is boolean, `lt` can only
/// be `1` when `lhs < rhs`.
#[derive(Clone, Debug)]
pub struct LtGadget<F, const N_BYTES: usize> {
    lt: Cell<F>, // `1` when `lhs < rhs`, `0` otherwise.
    diff: [Cell<F>; N_BYTES], /* The byte values of `diff`.
                  * `diff` equals `lhs - rhs` if `lhs >= rhs`,
                  * `lhs - rhs + range` otherwise. */
    range: F, // The range of the inputs, `256**N_BYTES`
}

impl<F: Field, const N_BYTES: usize> LtGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let lt = cb.query_bool();
        let diff = cb.query_bytes();
        let range = pow_of_two(N_BYTES * 8);

        // The equation we require to hold: `lhs - rhs == diff - (lt * range)`.
        cb.require_equal(
            "lhs - rhs == diff - (lt ⋅ range)",
            lhs - rhs,
            from_bytes::expr(&diff) - (lt.expr() * range),
        );

        Self { lt, diff, range }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.lt.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(F, Vec<u8>), Error> {
        // Set `lt`
        let lt = lhs < rhs;
        self.lt
            .assign(region, offset, Some(if lt { F::one() } else { F::zero() }))?;

        // Set the bytes of diff
        let diff = (lhs - rhs) + (if lt { self.range } else { F::zero() });
        let diff_bytes = diff.to_repr();
        for (idx, diff) in self.diff.iter().enumerate() {
            diff.assign(region, offset, Some(F::from(diff_bytes[idx] as u64)))?;
        }

        Ok((if lt { F::one() } else { F::zero() }, diff_bytes.to_vec()))
    }

    pub(crate) fn diff_bytes(&self) -> Vec<Cell<F>> {
        self.diff.to_vec()
    }
}

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs are both 256-bit word.
#[derive(Clone, Debug)]
pub struct LtWordGadget<F> {
    comparison_hi: ComparisonGadget<F, 16>,
    lt_lo: LtGadget<F, 16>,
}

impl<F: Field> LtWordGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: &util::Word<F>,
        rhs: &util::Word<F>,
    ) -> Self {
        let comparison_hi = ComparisonGadget::construct(
            cb,
            from_bytes::expr(&lhs.cells[16..]),
            from_bytes::expr(&rhs.cells[16..]),
        );
        let lt_lo = LtGadget::construct(
            cb,
            from_bytes::expr(&lhs.cells[..16]),
            from_bytes::expr(&rhs.cells[..16]),
        );
        Self {
            comparison_hi,
            lt_lo,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        let (hi_lt, hi_eq) = self.comparison_hi.expr();
        hi_lt + hi_eq * self.lt_lo.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: Word,
        rhs: Word,
    ) -> Result<(), Error> {
        let (lhs_lo, lhs_hi) = split_u256(&lhs);
        let (rhs_lo, rhs_hi) = split_u256(&rhs);
        self.comparison_hi.assign(
            region,
            offset,
            F::from_u128(lhs_hi.as_u128()),
            F::from_u128(rhs_hi.as_u128()),
        )?;
        self.lt_lo.assign(
            region,
            offset,
            F::from_u128(lhs_lo.as_u128()),
            F::from_u128(rhs_lo.as_u128()),
        )?;
        Ok(())
    }
}

/// Returns (lt, eq):
/// - `lt` is `1` when `lhs < rhs`, `0` otherwise.
/// - `eq` is `1` when `lhs == rhs`, `0` otherwise.
/// lhs and rhs `< 256**N_BYTES`
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER`.
#[derive(Clone, Debug)]
pub struct ComparisonGadget<F, const N_BYTES: usize> {
    lt: LtGadget<F, N_BYTES>,
    eq: IsZeroGadget<F>,
}

impl<F: Field, const N_BYTES: usize> ComparisonGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let lt = LtGadget::<F, N_BYTES>::construct(cb, lhs, rhs);
        let eq = IsZeroGadget::<F>::construct(cb, sum::expr(&lt.diff_bytes()));

        Self { lt, eq }
    }

    pub(crate) fn expr(&self) -> (Expression<F>, Expression<F>) {
        (self.lt.expr(), self.eq.expr())
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(F, F), Error> {
        // lt
        let (lt, diff) = self.lt.assign(region, offset, lhs, rhs)?;

        // eq
        let eq = self.eq.assign(region, offset, sum::value(&diff))?;

        Ok((lt, eq))
    }
}

/// Returns (is_a, is_b):
/// - `is_a` is `1` when `value == a`, else `0`
/// - `is_b` is `1` when `value == b`, else `0`
/// `value` is required to be either `a` or `b`.
/// The benefit of this gadget over `IsEqualGadget` is that the
/// expression returned is a single value which will make
/// future expressions depending on this result more efficient.
#[derive(Clone, Debug)]
pub struct PairSelectGadget<F> {
    is_a: Cell<F>,
    is_b: Expression<F>,
}

impl<F: Field> PairSelectGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        value: Expression<F>,
        a: Expression<F>,
        b: Expression<F>,
    ) -> Self {
        let is_a = cb.query_bool();
        let is_b = 1.expr() - is_a.expr();

        // Force `is_a` to be `0` when `value != a`
        cb.add_constraint("is_a ⋅ (value - a)", is_a.expr() * (value.clone() - a));
        // Force `1 - is_a` to be `0` when `value != b`
        cb.add_constraint("(1 - is_a) ⋅ (value - b)", is_b.clone() * (value - b));

        Self { is_a, is_b }
    }

    pub(crate) fn expr(&self) -> (Expression<F>, Expression<F>) {
        (self.is_a.expr(), self.is_b.clone())
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: F,
        a: F,
        _b: F,
    ) -> Result<(F, F), Error> {
        let is_a = if value == a { F::one() } else { F::zero() };
        self.is_a.assign(region, offset, Some(is_a))?;

        Ok((is_a, F::one() - is_a))
    }
}

/// Returns (quotient: numerator/denominator, remainder: numerator%denominator),
/// with `numerator` an expression and `denominator` a constant.
/// Input requirements:
/// - `quotient < 256**N_BYTES`
/// - `quotient * denominator < field size`
/// - `remainder < denominator` requires a range lookup table for `denominator`
#[derive(Clone, Debug)]
pub struct ConstantDivisionGadget<F, const N_BYTES: usize> {
    quotient: Cell<F>,
    remainder: Cell<F>,
    denominator: u64,
    quotient_range_check: RangeCheckGadget<F, N_BYTES>,
}

impl<F: Field, const N_BYTES: usize> ConstantDivisionGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        numerator: Expression<F>,
        denominator: u64,
    ) -> Self {
        let quotient = cb.query_cell();
        let remainder = cb.query_cell();

        // Require that remainder < denominator
        cb.range_lookup(remainder.expr(), denominator);

        // Require that quotient < 2**N_BYTES
        // so we can't have any overflow when doing `quotient * denominator`.
        let quotient_range_check = RangeCheckGadget::construct(cb, quotient.expr());

        // Check if the division was done correctly
        cb.require_equal(
            "numerator - remainder == quotient ⋅ denominator",
            numerator - remainder.expr(),
            quotient.expr() * denominator.expr(),
        );

        Self {
            quotient,
            remainder,
            denominator,
            quotient_range_check,
        }
    }

    pub(crate) fn quotient(&self) -> Expression<F> {
        self.quotient.expr()
    }

    pub(crate) fn remainder(&self) -> Expression<F> {
        self.remainder.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        numerator: u128,
    ) -> Result<(u128, u128), Error> {
        let denominator = self.denominator as u128;
        let quotient = numerator / denominator;
        let remainder = numerator % denominator;

        self.quotient
            .assign(region, offset, Some(F::from_u128(quotient)))?;
        self.remainder
            .assign(region, offset, Some(F::from_u128(remainder)))?;

        self.quotient_range_check
            .assign(region, offset, F::from_u128(quotient))?;

        Ok((quotient, remainder))
    }
}

/// Returns `rhs` when `lhs < rhs`, and returns `lhs` otherwise.
/// lhs and rhs `< 256**N_BYTES`
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER`.
#[derive(Clone, Debug)]
pub struct MinMaxGadget<F, const N_BYTES: usize> {
    lt: LtGadget<F, N_BYTES>,
    min: Expression<F>,
    max: Expression<F>,
}

impl<F: Field, const N_BYTES: usize> MinMaxGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let lt = LtGadget::construct(cb, lhs.clone(), rhs.clone());
        let max = select::expr(lt.expr(), rhs.clone(), lhs.clone());
        let min = select::expr(lt.expr(), lhs, rhs);

        Self { lt, min, max }
    }

    pub(crate) fn min(&self) -> Expression<F> {
        self.min.clone()
    }

    pub(crate) fn max(&self) -> Expression<F> {
        self.max.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(F, F), Error> {
        let (lt, _) = self.lt.assign(region, offset, lhs, rhs)?;
        Ok(if lt.is_zero_vartime() {
            (rhs, lhs)
        } else {
            (lhs, rhs)
        })
    }
}

// This function generates a Lagrange polynomial in the range [start, end) which
// will be evaluated to 1 when `exp == value`, otherwise 0
pub(crate) fn generate_lagrange_base_polynomial<
    F: Field,
    Exp: Expr<F>,
    I: Iterator<Item = usize>,
>(
    exp: Exp,
    val: usize,
    range: I,
) -> Expression<F> {
    let mut numerator = 1u64.expr();
    let mut denominator = F::from(1);
    for x in range {
        if x != val {
            numerator = numerator * (exp.expr() - x.expr());
            denominator *= F::from(val as u64) - F::from(x as u64);
        }
    }
    numerator * denominator.invert().unwrap()
}

/// Construct the gadget that checks a * b + c == d (modulo 2**256),
/// where a, b, c, d are 256-bit words. This can be used by opcode MUL, DIV,
/// and MOD. For opcode MUL, set c to 0. For opcode DIV and MOD, treat c as
/// residue and d as dividend.
///
/// We execute a multi-limb multiplication as follows:
/// a and b is divided into 4 64-bit limbs, denoted as a0~a3 and b0~b3
/// defined t0, t1, t2, t3
///   t0 = a0 * b0, contribute to 0 ~ 128 bit
///   t1 = a0 * b1 + a1 * b0, contribute to 64 ~ 193 bit (include the carry)
///   t2 = a0 * b2 + a2 * b0 + a1 * b1, contribute to above 128 bit
///   t3 = a0 * b3 + a3 * b0 + a2 * b1 + a1 * b2, contribute to above 192 bit
///
/// so t0 ~ t1 include all contributions to the low 256-bit of product, with
/// a maximum 68-bit radix (the part higher than 256-bit), denoted as carry_hi
/// Similarly, we define carry_lo as the radix of contributions to the low
/// 128-bit of the product.
/// We can slightly relax the constraint of carry_lo/carry_hi to 72-bit and
/// allocate 9 bytes for them each
///
/// Finally we just prove:
///   t0 + t1 * 2^64 = <low 128 bit of product> + carry_lo
///   t2 + t3 * 2^64 + carry_lo = <high 128 bit of product> + carry_hi
///
/// Last, we sum the parts that are higher than 256-bit in the multiplication
/// into overflow
///   overflow = carry_hi + a1 * b3 + a2 * b2 + a3 * b1 + a2 * b3 + a3 * b2
///              + a3 * b3
/// In the cases of DIV and MOD, we need to constrain overflow == 0 outside the
/// MulAddWordsGadget.
#[derive(Clone, Debug)]
pub(crate) struct MulAddWordsGadget<F> {
    pub a: util::Word<F>,
    pub b: util::Word<F>,
    pub c: util::Word<F>,
    pub d: util::Word<F>,
    carry_lo: [Cell<F>; 9],
    carry_hi: [Cell<F>; 9],
    overflow: Expression<F>,
}

impl<F: Field> MulAddWordsGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let a = cb.query_word();
        let b = cb.query_word();
        let c = cb.query_word();
        let d = cb.query_word();
        let carry_lo = cb.query_bytes();
        let carry_hi = cb.query_bytes();
        let carry_lo_expr = from_bytes::expr(&carry_lo);
        let carry_hi_expr = from_bytes::expr(&carry_hi);

        let mut a_limbs = vec![];
        let mut b_limbs = vec![];
        for trunk in 0..4 {
            let idx = (trunk * 8) as usize;
            a_limbs.push(from_bytes::expr(&a.cells[idx..idx + 8]));
            b_limbs.push(from_bytes::expr(&b.cells[idx..idx + 8]));
        }
        let c_lo = from_bytes::expr(&c.cells[0..16]);
        let c_hi = from_bytes::expr(&c.cells[16..32]);
        let d_lo = from_bytes::expr(&d.cells[0..16]);
        let d_hi = from_bytes::expr(&d.cells[16..32]);

        let t0 = a_limbs[0].clone() * b_limbs[0].clone();
        let t1 = a_limbs[0].clone() * b_limbs[1].clone() + a_limbs[1].clone() * b_limbs[0].clone();
        let t2 = a_limbs[0].clone() * b_limbs[2].clone()
            + a_limbs[1].clone() * b_limbs[1].clone()
            + a_limbs[2].clone() * b_limbs[0].clone();
        let t3 = a_limbs[0].clone() * b_limbs[3].clone()
            + a_limbs[1].clone() * b_limbs[2].clone()
            + a_limbs[2].clone() * b_limbs[1].clone()
            + a_limbs[3].clone() * b_limbs[0].clone();
        let overflow = carry_hi_expr.clone()
            + a_limbs[1].clone() * b_limbs[3].clone()
            + a_limbs[2].clone() * b_limbs[2].clone()
            + a_limbs[3].clone() * b_limbs[2].clone()
            + a_limbs[2].clone() * b_limbs[3].clone()
            + a_limbs[3].clone() * b_limbs[2].clone()
            + a_limbs[3].clone() * b_limbs[3].clone();

        cb.require_equal(
            "(a * b)_lo + c_lo == d_lo + carry_lo ⋅ 2^128",
            t0.expr() + t1.expr() * pow_of_two_expr(64) + c_lo,
            d_lo + carry_lo_expr.clone() * pow_of_two_expr(128),
        );
        cb.require_equal(
            "(a * b)_hi + c_hi + carry_lo == d_hi + carry_hi ⋅ 2^128",
            t2.expr() + t3.expr() * pow_of_two_expr(64) + c_hi + carry_lo_expr,
            d_hi + carry_hi_expr * pow_of_two_expr(128),
        );

        Self {
            a,
            b,
            c,
            d,
            carry_lo,
            carry_hi,
            overflow,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        words: [Word; 4],
    ) -> Result<(), Error> {
        let (a, b, c, d) = (words[0], words[1], words[2], words[3]);
        self.a.assign(region, offset, Some(a.to_le_bytes()))?;
        self.b.assign(region, offset, Some(b.to_le_bytes()))?;
        self.c.assign(region, offset, Some(c.to_le_bytes()))?;
        self.d.assign(region, offset, Some(d.to_le_bytes()))?;

        let a_limbs = split_u256_limb64(&a);
        let b_limbs = split_u256_limb64(&b);
        let (c_lo, c_hi) = split_u256(&c);
        let (d_lo, d_hi) = split_u256(&d);

        let t0 = a_limbs[0] * b_limbs[0];
        let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
        let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
        let t3 = a_limbs[0] * b_limbs[3]
            + a_limbs[1] * b_limbs[2]
            + a_limbs[2] * b_limbs[1]
            + a_limbs[3] * b_limbs[0];

        let carry_lo = (t0 + (t1 << 64) + c_lo - d_lo) >> 128;
        let carry_hi = (t2 + (t3 << 64) + c_hi + carry_lo - d_hi) >> 128;

        self.carry_lo
            .iter()
            .zip(carry_lo.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Some(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        self.carry_hi
            .iter()
            .zip(carry_hi.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Some(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    pub(crate) fn overflow(&self) -> Expression<F> {
        self.overflow.clone()
    }
}

#[derive(Clone, Debug)]
pub struct ShrWordsGadget<F> {
    a: util::Word<F>,
    shift: util::Word<F>,
    b: util::Word<F>,
    // slice_hi means the higher part of split digit
    // slice_lo means the lower part of the split digit
    a_slice_hi: [Cell<F>; 32],
    a_slice_lo: [Cell<F>; 32],
    // shift_div64, shift_mod64_div8, shift_mod8
    // is used to seperate shift[0]
    shift_div64: Cell<F>,
    shift_mod64_div8: Cell<F>,
    shift_mod64_decpow: Cell<F>, // means 2^(8-shift_mod64)
    shift_mod64_pow: Cell<F>,    // means 2^shift_mod64
    shift_mod8: Cell<F>,
    // is_zero will check combination of shift[1..32] == 0
    is_zero: IsZeroGadget<F>,
}

impl<F: Field> ShrWordsGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        a: util::Word<F>,
        shift: util::Word<F>,
    ) -> Self {
        let b = cb.query_word();
        let a_slice_hi = cb.query_bytes();
        let a_slice_lo = cb.query_bytes();
        let shift_div64 = cb.query_cell();
        let shift_mod64_div8 = cb.query_cell();
        let shift_mod64_decpow = cb.query_cell();
        let shift_mod64_pow = cb.query_cell();
        let shift_mod8 = cb.query_cell();

        // check (combination of shift[1..32] == 0) == 1 - shift_overflow
        let mut sum = 0.expr();
        (1..32).for_each(|idx| sum = sum.clone() + shift.cells[idx].expr());
        let is_zero = IsZeroGadget::construct(cb, sum);
        // if combination of shift[1..32] == 0
        // shift_overflow will be equal to 0, otherwise 1.
        let shift_overflow = 1.expr() - is_zero.expr();
        cb.require_equal(
            "shift_overflow == shift > 256 ",
            shift_overflow.clone(),
            1.expr() - is_zero.expr(),
        );

        // rename variable:
        // shift_div64 :a
        // shift_mod64_div8:b
        // shift_mod8:c
        // we split shift[0] to the equation:
        // shift[0] == a * 64 + b * 8 + c
        let shift_mod64 = 8.expr() * shift_mod64_div8.expr() + shift_mod8.expr();
        cb.require_equal(
            "shift[0] == shift_div64 * 64 + shift_mod64_div8 * 8 + shift_mod8",
            shift.cells[0].expr(),
            shift_div64.expr() * 64.expr() + shift_mod64.clone(),
        );

        // merge 8 8-bit cell for a 64-bit expression
        // for a, a_slice_hi, a_slice_lo, b
        let mut a_digits = vec![];
        let mut a_slice_hi_digits = vec![];
        let mut a_slice_lo_digits = vec![];
        let mut b_digits = vec![];
        for virtual_idx in 0..4 {
            let now_idx = (virtual_idx * 8) as usize;
            a_digits.push(from_bytes::expr(&a.cells[now_idx..now_idx + 8]));
            a_slice_lo_digits.push(from_bytes::expr(&a_slice_lo[now_idx..now_idx + 8]));
            a_slice_hi_digits.push(from_bytes::expr(&a_slice_hi[now_idx..now_idx + 8]));
            b_digits.push(from_bytes::expr(&b.cells[now_idx..now_idx + 8]));
        }

        // check combination of a_slice_back_digits and a_slice_front_digits
        // == b_digits
        let mut shr_constraints = (0..4).map(|_| 0.expr()).collect::<Vec<Expression<F>>>();
        for transplacement in (0_usize)..(4_usize) {
            // generate the polynomial depends on the shift_div64
            let select_transplacement_polynomial =
                generate_lagrange_base_polynomial(shift_div64.expr(), transplacement, 0..4);
            for idx in 0..(4 - transplacement) {
                let tmpidx = idx + transplacement;
                let merge_a = if idx + transplacement == (3_usize) {
                    a_slice_hi_digits[tmpidx].clone()
                } else {
                    a_slice_hi_digits[tmpidx].clone()
                        + a_slice_lo_digits[tmpidx + 1].clone() * shift_mod64_decpow.expr()
                };
                shr_constraints[idx] = shr_constraints[idx].clone()
                    + select_transplacement_polynomial.clone()
                        * select::expr(
                            shift_overflow.clone(),
                            b_digits[idx].clone(),
                            merge_a - b_digits[idx].clone(),
                        );
            }
            for idx in (4 - transplacement)..4 {
                shr_constraints[idx] = shr_constraints[idx].clone()
                    + select_transplacement_polynomial.clone() * b_digits[idx].clone();
            }
        }
        (0..4).for_each(|idx| {
            cb.require_zero(
                "merge a_slice_lo_digits and a_slice_hi_digits == b_digits",
                shr_constraints[idx].clone(),
            )
        });

        // for i in 0..4
        // a_slice_lo_digits[i] + a_slice_hi_digits * shift_mod64_pow
        // == a_digits[i]
        for idx in 0..4 {
            cb.require_equal(
                "a[idx] == a_slice_lo[idx] + a_slice_hi[idx] * shift_mod64_pow",
                a_slice_lo_digits[idx].clone()
                    + a_slice_hi_digits[idx].clone() * shift_mod64_pow.expr(),
                a_digits[idx].clone(),
            );
        }

        // check serveral higher cells == 0 for slice_back and slice_front
        let mut equal_to_zero = 0.expr();
        for digit_transplacement in 0..8 {
            let select_transplacement_polynomial = generate_lagrange_base_polynomial(
                shift_mod64_div8.expr(),
                digit_transplacement,
                0..8,
            );
            for virtual_idx in 0..4 {
                for idx in (digit_transplacement + 1)..8 {
                    let nowidx = (virtual_idx * 8 + idx) as usize;
                    equal_to_zero = equal_to_zero
                        + (select_transplacement_polynomial.clone() * a_slice_lo[nowidx].expr());
                }
                for idx in (8 - digit_transplacement)..8 {
                    let nowidx = (virtual_idx * 8 + idx) as usize;
                    equal_to_zero = equal_to_zero
                        + (select_transplacement_polynomial.clone() * a_slice_hi[nowidx].expr());
                }
            }
        }

        //check the specific 4 cells in 0..(1 << shift_mod8).
        //check another specific 4 cells in 0..(1 << (8 - shift_mod8)).
        for virtual_idx in 0..4 {
            let mut slice_bits_polynomial = vec![0.expr(), 0.expr()];
            for digit_transplacement in 0..8 {
                let select_transplacement_polynomial = generate_lagrange_base_polynomial(
                    shift_mod64_div8.expr(),
                    digit_transplacement,
                    0..8,
                );
                let nowidx = (virtual_idx * 8 + digit_transplacement) as usize;
                slice_bits_polynomial[0] = slice_bits_polynomial[0].clone()
                    + select_transplacement_polynomial.clone() * a_slice_lo[nowidx].expr();
                let nowidx = (virtual_idx * 8 + 7 - digit_transplacement) as usize;
                slice_bits_polynomial[1] = slice_bits_polynomial[1].clone()
                    + select_transplacement_polynomial.clone() * a_slice_hi[nowidx].expr();
            }
            cb.add_lookup(
                "slice_bits range lookup",
                Lookup::Fixed {
                    tag: FixedTableTag::Bitslevel.expr(),
                    values: [
                        shift_mod8.expr(),
                        slice_bits_polynomial[0].clone(),
                        0.expr(),
                    ],
                },
            );
            cb.add_lookup(
                "slice_bits range lookup",
                Lookup::Fixed {
                    tag: FixedTableTag::Bitslevel.expr(),
                    values: [
                        8.expr() - shift_mod8.expr(),
                        slice_bits_polynomial[1].clone(),
                        0.expr(),
                    ],
                },
            );
        }

        // check:
        // 2^shift_mod64 == shift_mod64_pow
        // 2^(8-shift_mod64) == shift_mod64_decpow
        cb.add_lookup(
            "pow_of_two lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Pow64.expr(),
                values: [
                    shift_mod64,
                    shift_mod64_pow.expr(),
                    shift_mod64_decpow.expr(),
                ],
            },
        );

        cb.add_lookup(
            "shift_div64 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [2.expr(), shift_div64.expr(), 0.expr()],
            },
        );
        cb.add_lookup(
            "shift_mod64_div8 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [3.expr(), shift_mod64_div8.expr(), 0.expr()],
            },
        );
        cb.add_lookup(
            "shift_mod8 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [3.expr(), shift_mod8.expr(), 0.expr()],
            },
        );

        Self {
            a,
            shift,
            b,
            a_slice_hi,
            a_slice_lo,
            shift_div64,
            shift_mod64_div8,
            shift_mod64_decpow,
            shift_mod64_pow,
            shift_mod8,
            is_zero,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        a: Word,
        shift: Word,
        b: Word,
    ) -> Result<(), Error> {
        self.assign_witness(region, offset, &a, &shift)?;
        self.a.assign(region, offset, Some(a.to_le_bytes()))?;
        self.shift
            .assign(region, offset, Some(shift.to_le_bytes()))?;
        self.b.assign(region, offset, Some(b.to_le_bytes()))?;
        Ok(())
    }

    pub(crate) fn b(&self) -> &util::Word<F> {
        &self.b
    }

    fn assign_witness(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        wa: &Word,
        wshift: &Word,
    ) -> Result<(), Error> {
        let a8s = wa.to_le_bytes();
        let shift = wshift.to_le_bytes()[0] as u128;
        let shift_div64 = shift / 64;
        let shift_mod64_div8 = shift % 64 / 8;
        let shift_mod64 = shift % 64;
        let shift_mod64_pow = 1u128 << shift_mod64;
        let shift_mod64_decpow = (1u128 << 64) / (shift_mod64_pow as u128);
        let shift_mod8 = shift % 8;
        let mut a_slice_hi = [0u8; 32];
        let mut a_slice_lo = [0u8; 32];
        for virtual_idx in 0..4 {
            let mut tmp_a: u64 = 0;
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                tmp_a += (1u64 << (8 * idx)) * (a8s[now_idx] as u64);
            }
            let mut slice_back = if shift_mod64 == 0 {
                0
            } else {
                tmp_a % (1u64 << shift_mod64)
            };
            let mut slice_front = if shift_mod64 == 0 {
                tmp_a
            } else {
                tmp_a / (1u64 << shift_mod64)
            };
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                a_slice_lo[now_idx] = (slice_back % (1 << 8)) as u8;
                a_slice_hi[now_idx] = (slice_front % (1 << 8)) as u8;
                slice_back >>= 8;
                slice_front >>= 8;
            }
        }
        a_slice_hi.iter().zip(self.a_slice_hi.iter()).try_for_each(
            |(bt, assignee)| -> Result<(), Error> {
                assignee.assign(region, offset, Some(F::from(*bt as u64)))?;
                Ok(())
            },
        )?;
        a_slice_lo.iter().zip(self.a_slice_lo.iter()).try_for_each(
            |(bt, assignee)| -> Result<(), Error> {
                assignee.assign(region, offset, Some(F::from(*bt as u64)))?;
                Ok(())
            },
        )?;
        self.shift_div64
            .assign(region, offset, Some(F::from_u128(shift_div64)))?;
        self.shift_mod64_div8
            .assign(region, offset, Some(F::from_u128(shift_mod64_div8)))?;
        self.shift_mod64_decpow
            .assign(region, offset, Some(F::from_u128(shift_mod64_decpow)))?;
        self.shift_mod64_pow
            .assign(region, offset, Some(F::from_u128(shift_mod64_pow)))?;
        self.shift_mod8
            .assign(region, offset, Some(F::from_u128(shift_mod8)))?;

        let mut sum: u128 = 0;
        wshift.to_le_bytes().iter().for_each(|v| sum += *v as u128);
        sum -= shift as u128;
        self.is_zero.assign(region, offset, F::from_u128(sum))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ShlWordsGadget<F> {
    a: util::Word<F>,
    shift: util::Word<F>,
    b: util::Word<F>,
    // slice_front means the higher part of split digit
    // slice_back means the lower part of the split digit
    a_slice_front: [Cell<F>; 32],
    a_slice_back: [Cell<F>; 32],
    // shift_div64, shift_mod64_div8, shift_mod8
    // is used to seperate shift[0]
    shift_div64: Cell<F>,
    shift_mod64_div8: Cell<F>,
    shift_mod64_decpow: Cell<F>, // means 2^(8-shift_mod64)
    shift_mod64_pow: Cell<F>,    // means 2^shift_mod64
    shift_mod8: Cell<F>,
    // if combination of shift[1..32] == 0
    // shift_overflow will be equal to 0, otherwise 1.
    shift_overflow: Cell<F>,
    // is_zero will check combination of shift[1..32] == 0
    is_zero: IsZeroGadget<F>,
}
impl<F: Field> ShlWordsGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        a: util::Word<F>,
        shift: util::Word<F>,
    ) -> Self {
        let b = cb.query_word();
        let a_slice_front = array_init::array_init(|_| cb.query_byte());
        let a_slice_back = array_init::array_init(|_| cb.query_byte());
        let shift_div64 = cb.query_cell();
        let shift_mod64_div8 = cb.query_cell();
        let shift_mod64_decpow = cb.query_cell();
        let shift_mod64_pow = cb.query_cell();
        let shift_mod8 = cb.query_cell();
        let shift_overflow = cb.query_bool();

        // check (combination of shift[1..32] == 0) == 1 - shift_overflow
        let mut sum = 0.expr();
        (1..32).for_each(|idx| sum = sum.clone() + shift.cells[idx].expr());
        let is_zero = IsZeroGadget::construct(cb, sum);
        cb.require_equal(
            "shift_overflow == shift > 256 ",
            shift_overflow.expr(),
            1.expr() - is_zero.expr(),
        );

        // rename variable:
        // shift_div64 :a
        // shift_mod64_div8:b
        // shift_mod8:c
        // we split shift[0] to the equation:
        // shift[0] == a * 64 + b * 8 + c
        let shift_mod64 = 8.expr() * shift_mod64_div8.expr() + shift_mod8.expr();
        cb.require_equal(
            "shift[0] == shift_div64 * 64 + shift_mod64_div8 * 8 + shift_mod8",
            shift.cells[0].expr(),
            shift_div64.expr() * 64.expr() + shift_mod64.clone(),
        );

        // merge 8 8-bit cell for a 64-bit expression
        // for a, a_slice_front, a_slice_back, b
        let mut a_digits = vec![];
        let mut a_slice_front_digits = vec![];
        let mut a_slice_back_digits = vec![];
        let mut b_digits = vec![];
        for virtual_idx in 0..4 {
            let now_idx = (virtual_idx * 8) as usize;
            a_digits.push(from_bytes::expr(&a.cells[now_idx..now_idx + 8]));
            a_slice_back_digits.push(from_bytes::expr(&a_slice_back[now_idx..now_idx + 8]));
            a_slice_front_digits.push(from_bytes::expr(&a_slice_front[now_idx..now_idx + 8]));
            b_digits.push(from_bytes::expr(&b.cells[now_idx..now_idx + 8]));
        }

        // check combination of a_slice_back_digits and a_slice_front_digits
        // == b_digits
        let mut shl_constraints = (0..4).map(|_| 0.expr()).collect::<Vec<Expression<F>>>();
        for transplacement in (0_usize)..(4_usize) {
            // generate the polynomial depends on the shift_div64
            let select_transplacement_polynomial =
                generate_lagrange_base_polynomial(shift_div64.expr(), transplacement, 0..4);
            for idx in 0..(4 - transplacement) {
                let tmpidx = idx + transplacement;
                let merge_a = if idx == (0_usize) {
                    a_slice_back_digits[idx].clone() * shift_mod64_pow.expr()
                } else {
                    a_slice_back_digits[idx].clone() * shift_mod64_pow.expr()
                        + a_slice_front_digits[idx - 1].clone()
                };
                shl_constraints[tmpidx] = shl_constraints[tmpidx].clone()
                    + select_transplacement_polynomial.clone()
                        * select::expr(
                            shift_overflow.expr(),
                            b_digits[tmpidx].clone(),
                            merge_a - b_digits[tmpidx].clone(),
                        );
            }
            for idx in 0..transplacement {
                shl_constraints[idx] = shl_constraints[idx].clone()
                    + select_transplacement_polynomial.clone() * b_digits[idx].clone();
            }
        }
        (0..4).for_each(|idx| {
            cb.require_zero(
                "merge a_slice_back_digits and a_slice_front_digits == b_digits",
                shl_constraints[idx].clone(),
            )
        });

        // for i in 0..4
        // a_slice_back_digits[i] + a_slice_front_digits * shift_mod64_decpow
        // == a_digits[i]
        for idx in 0..4 {
            cb.require_equal(
                "a[idx] == a_slice_back[idx] + a_slice_front[idx] * shift_mod64_decpow",
                a_slice_back_digits[idx].clone()
                    + a_slice_front_digits[idx].clone() * shift_mod64_decpow.expr(),
                a_digits[idx].clone(),
            );
        }

        // check serveral higher cells == 0 for slice_back and slice_front
        let mut equal_to_zero = 0.expr();
        for digit_transplacement in 0..8 {
            let select_transplacement_polynomial = generate_lagrange_base_polynomial(
                shift_mod64_div8.clone(),
                digit_transplacement,
                0..8,
            );
            for virtual_idx in 0..4 {
                for idx in (digit_transplacement + 1)..8 {
                    let nowidx = (virtual_idx * 8 + idx) as usize;
                    equal_to_zero = equal_to_zero
                        + (select_transplacement_polynomial.clone() * a_slice_front[nowidx].expr());
                }
                for idx in (8 - digit_transplacement)..8 {
                    let nowidx = (virtual_idx * 8 + idx) as usize;
                    equal_to_zero = equal_to_zero
                        + (select_transplacement_polynomial.clone() * a_slice_back[nowidx].expr());
                }
            }
        }

        //check the specific 4 cells in 0..(1 << shift_mod8).
        //check another specific 4 cells in 0..(1 << (8 - shift_mod8)).
        for virtual_idx in 0..4 {
            let mut slice_bits_polynomial = vec![0.expr(), 0.expr()];
            for digit_transplacement in 0..8 {
                let select_transplacement_polynomial = generate_lagrange_base_polynomial(
                    shift_mod64_div8.clone(),
                    digit_transplacement,
                    0..8,
                );
                let nowidx = (virtual_idx * 8 + digit_transplacement) as usize;
                slice_bits_polynomial[0] = slice_bits_polynomial[0].clone()
                    + select_transplacement_polynomial.clone() * a_slice_front[nowidx].expr();
                let nowidx = (virtual_idx * 8 + 7 - digit_transplacement) as usize;
                slice_bits_polynomial[1] = slice_bits_polynomial[1].clone()
                    + select_transplacement_polynomial.clone() * a_slice_back[nowidx].expr();
            }
            cb.add_lookup(
                "slice_bits range lookup",
                Lookup::Fixed {
                    tag: FixedTableTag::Bitslevel.expr(),
                    values: [
                        shift_mod8.expr(),
                        slice_bits_polynomial[0].clone(),
                        0.expr(),
                    ],
                },
            );
            cb.add_lookup(
                "slice_bits range lookup",
                Lookup::Fixed {
                    tag: FixedTableTag::Bitslevel.expr(),
                    values: [
                        8.expr() - shift_mod8.expr(),
                        slice_bits_polynomial[1].clone(),
                        0.expr(),
                    ],
                },
            );
        }

        // check:
        // 2^shift_mod64 == shift_mod64_pow
        // 2^(8-shift_mod64) == shift_mod64_decpow
        cb.add_lookup(
            "pow_of_two lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Pow64.expr(),
                values: [
                    shift_mod64,
                    shift_mod64_pow.expr(),
                    shift_mod64_decpow.expr(),
                ],
            },
        );

        cb.add_lookup(
            "shift_div64 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [2.expr(), shift_div64.expr(), 0.expr()],
            },
        );
        cb.add_lookup(
            "shift_mod64_div8 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [3.expr(), shift_mod64_div8.expr(), 0.expr()],
            },
        );
        cb.add_lookup(
            "shift_mod8 range lookup",
            Lookup::Fixed {
                tag: FixedTableTag::Bitslevel.expr(),
                values: [3.expr(), shift_mod8.expr(), 0.expr()],
            },
        );

        Self {
            a,
            shift,
            b,
            a_slice_front,
            a_slice_back,
            shift_div64,
            shift_mod64_div8,
            shift_mod64_decpow,
            shift_mod64_pow,
            shift_mod8,
            shift_overflow,
            is_zero,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        a: Word,
        shift: Word,
        b: Word,
    ) -> Result<(), Error> {
        self.assign_witness(region, offset, &a, &shift)?;
        self.a.assign(region, offset, Some(a.to_le_bytes()))?;
        self.shift
            .assign(region, offset, Some(shift.to_le_bytes()))?;
        self.b.assign(region, offset, Some(b.to_le_bytes()))?;
        Ok(())
    }

    pub(crate) fn b(&self) -> &util::Word<F> {
        &self.b
    }

    fn assign_witness(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        wa: &Word,
        wshift: &Word,
    ) -> Result<(), Error> {
        let a8s = wa.to_le_bytes();
        let shift = wshift.to_le_bytes()[0] as u128;
        let shift_div64 = shift / 64;
        let shift_mod64_div8 = shift % 64 / 8;
        let shift_mod64 = shift % 64;
        let shift_mod64_pow = 1u128 << shift_mod64;
        let shift_mod64_decpow = (1u128 << 64) / (shift_mod64_pow as u128);
        let shift_mod8 = shift % 8;
        let mut a_slice_front = [0u8; 32];
        let mut a_slice_back = [0u8; 32];
        for virtual_idx in 0..4 {
            let mut tmp_a: u64 = 0;
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                tmp_a += (1u64 << (8 * idx)) * (a8s[now_idx] as u64);
            }
            let mut slice_back = if shift_mod64 == 0 {
                tmp_a
            } else {
                tmp_a % (1u64 << (64 - shift_mod64))
            };
            let mut slice_front = if shift_mod64 == 0 {
                0
            } else {
                tmp_a / (1u64 << (64 - shift_mod64))
            };
            for idx in 0..8 {
                let now_idx = virtual_idx * 8 + idx;
                a_slice_back[now_idx] = (slice_back % (1 << 8)) as u8;
                a_slice_front[now_idx] = (slice_front % (1 << 8)) as u8;
                slice_back >>= 8;
                slice_front >>= 8;
            }
        }
        a_slice_front
            .iter()
            .zip(self.a_slice_front.iter())
            .try_for_each(|(bt, assignee)| -> Result<(), Error> {
                assignee.assign(region, offset, Some(F::from(*bt as u64)))?;
                Ok(())
            })?;
        a_slice_back
            .iter()
            .zip(self.a_slice_back.iter())
            .try_for_each(|(bt, assignee)| -> Result<(), Error> {
                assignee.assign(region, offset, Some(F::from(*bt as u64)))?;
                Ok(())
            })?;
        self.shift_div64
            .assign(region, offset, Some(F::from_u128(shift_div64)))?;
        self.shift_mod64_div8
            .assign(region, offset, Some(F::from_u128(shift_mod64_div8)))?;
        self.shift_mod64_decpow
            .assign(region, offset, Some(F::from_u128(shift_mod64_decpow)))?;
        self.shift_mod64_pow
            .assign(region, offset, Some(F::from_u128(shift_mod64_pow)))?;
        self.shift_mod8
            .assign(region, offset, Some(F::from_u128(shift_mod8)))?;

        let mut sum: u128 = 0;
        wshift.to_le_bytes().iter().for_each(|v| sum += *v as u128);
        sum -= shift as u128;
        let shift_overflow = sum != 0;
        self.is_zero.assign(region, offset, F::from_u128(sum))?;
        self.shift_overflow
            .assign(region, offset, Some(F::from_u128(shift_overflow as u128)))?;
        Ok(())
    }
}
