use crate::{
    evm_circuit::{
        param::MAX_BYTES_FIELD,
        util::{
            self, constraint_builder::ConstraintBuilder, from_bytes, get_range,
            select, sum, Cell,
        },
    },
    util::Expr,
};
use bus_mapping::eth_types::{ToLittleEndian, Word};
use halo2::plonk::Error;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Expression};

/// Returns `1` when `value == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZeroGadget<F> {
    inverse: Cell<F>,
    is_zero: Expression<F>,
}

impl<F: FieldExt> IsZeroGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        value: Expression<F>,
    ) -> Self {
        let inverse = cb.query_cell();

        let is_zero = 1.expr() - (value.clone() * inverse.expr());
        // when `value != 0` check `inverse = a.invert()`: value * (1 - value * inverse)
        cb.add_constraint(
            "value ⋅ (1 - value ⋅ value_inv)",
            value * is_zero.clone(),
        );
        // when `value == 0` check `inverse = 0`: `inverse ⋅ (1 - value * inverse)`
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
        Ok(if value.is_zero() { F::one() } else { F::zero() })
    }
}

/// Returns `1` when `lhs == rhs`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsEqualGadget<F> {
    is_zero: IsZeroGadget<F>,
}

impl<F: FieldExt> IsEqualGadget<F> {
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
pub(crate) struct WordAdditionGadget<F> {
    pub(crate) a: util::Word<F>,
    pub(crate) b: util::Word<F>,
    pub(crate) c: util::Word<F>,
    pub(crate) carry_lo: Cell<F>,
    pub(crate) carry_hi: Cell<F>,
}

impl<F: FieldExt> WordAdditionGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>) -> Self {
        let a = cb.query_word();
        let b = cb.query_word();
        let c = cb.query_word();
        let carry_lo = cb.query_bool();
        let carry_hi = cb.query_bool();

        let a_lo = from_bytes::expr(a.cells[..16].to_vec());
        let a_hi = from_bytes::expr(a.cells[16..].to_vec());
        let b_lo = from_bytes::expr(b.cells[..16].to_vec());
        let b_hi = from_bytes::expr(b.cells[16..].to_vec());
        let c_lo = from_bytes::expr(c.cells[..16].to_vec());
        let c_hi = from_bytes::expr(c.cells[16..].to_vec());

        cb.require_equal(
            "a_lo + b_lo == c_lo + carry_lo ⋅ 2^128",
            a_lo + b_lo,
            c_lo + carry_lo.expr() * Expression::Constant(get_range(128)),
        );
        cb.require_equal(
            "a_hi + b_hi + carry_lo == c_hi + carry_hi ⋅ 2^128",
            a_hi + b_hi + carry_lo.expr(),
            c_hi + carry_hi.expr() * Expression::Constant(get_range(128)),
        );

        Self {
            a,
            b,
            c,
            carry_lo,
            carry_hi,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        a: Word,
        b: Word,
        c: Word,
    ) -> Result<(), Error> {
        let mut assign_and_split = |word: &util::Word<F>, value: &Word| {
            let bytes = value.to_le_bytes();
            word.assign(region, offset, Some(bytes))?;
            let (lo, hi) = bytes.split_at(16);
            let (lo, hi) =
                (Word::from_little_endian(lo), Word::from_little_endian(hi));
            Ok((lo, hi))
        };
        let (a_lo, a_hi) = assign_and_split(&self.a, &a)?;
        let (b_lo, b_hi) = assign_and_split(&self.b, &b)?;
        let (c_lo, c_hi) = assign_and_split(&self.c, &c)?;
        let carry_lo = c_lo != a_lo + b_lo;
        let carry_hi = c_hi != a_hi + b_hi + Word::from(carry_lo as usize);
        self.carry_lo.assign(
            region,
            offset,
            Some(F::from_u64(carry_lo as u64)),
        )?;
        self.carry_hi.assign(
            region,
            offset,
            Some(F::from_u64(carry_hi as u64)),
        )?;
        Ok(())
    }
}

/// Requires that the passed in value is within the specified range.
/// `NUM_BYTES` is required to be `<= 31`.
#[derive(Clone, Debug)]
pub struct RangeCheckGadget<F, const NUM_BYTES: usize> {
    parts: [Cell<F>; NUM_BYTES],
}

impl<F: FieldExt, const NUM_BYTES: usize> RangeCheckGadget<F, NUM_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        value: Expression<F>,
    ) -> Self {
        assert!(NUM_BYTES <= 31, "number of bytes too large");

        let parts = cb.query_bytes();
        // Require that the reconstructed value from the parts equals the original value
        cb.require_equal(
            "Constrain bytes recomposited to value",
            value,
            from_bytes::expr(parts.to_vec()),
        );

        Self { parts }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: F,
    ) -> Result<(), Error> {
        let bytes = value.to_bytes();
        for (idx, part) in self.parts.iter().enumerate() {
            part.assign(region, offset, Some(F::from_u64(bytes[idx] as u64)))?;
        }
        Ok(())
    }
}

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs `< 256**NUM_BYTES`
/// `NUM_BYTES` is required to be `<= MAX_BYTES_FIELD` to prevent overflow:
/// values are stored in a single field element and two of these
/// are added together.
/// The equation that is enforced is `lhs - rhs == diff - (lt * range)`.
/// Because all values are `<= 256**NUM_BYTES` and `lt` is boolean,
///  `lt` can only be `1` when `lhs < rhs`.
#[derive(Clone, Debug)]
pub struct LtGadget<F, const NUM_BYTES: usize> {
    lt: Cell<F>, // `1` when `lhs < rhs`, `0` otherwise.
    diff: [Cell<F>; NUM_BYTES], /* The byte values of `diff`.
                  * `diff` equals `lhs - rhs` if `lhs >= rhs`,
                  * `lhs - rhs + range` otherwise. */
    range: F, // The range of the inputs, `256**NUM_BYTES`
}

impl<F: FieldExt, const NUM_BYTES: usize> LtGadget<F, NUM_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        assert!(NUM_BYTES <= MAX_BYTES_FIELD, "unsupported number of bytes");

        let lt = cb.query_bool();
        let diff = cb.query_bytes();
        let range = get_range(NUM_BYTES * 8);

        // The equation we require to hold: `lhs - rhs == diff - (lt * range)`.
        cb.require_equal(
            "lhs - rhs == diff - (lt ⋅ range)",
            lhs - rhs,
            from_bytes::expr(diff.to_vec()) - (lt.expr() * range),
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
        self.lt.assign(
            region,
            offset,
            Some(F::from_u64(if lt { 1 } else { 0 })),
        )?;

        // Set the bytes of diff
        let diff = (lhs - rhs) + (if lt { self.range } else { F::zero() });
        let diff_bytes = diff.to_bytes();
        for (idx, diff) in self.diff.iter().enumerate() {
            diff.assign(
                region,
                offset,
                Some(F::from_u64(diff_bytes[idx] as u64)),
            )?;
        }

        Ok((if lt { F::one() } else { F::zero() }, diff_bytes.to_vec()))
    }

    pub(crate) fn diff_bytes(&self) -> Vec<Cell<F>> {
        self.diff.to_vec()
    }
}

/// Returns (lt, eq):
/// - `lt` is `1` when `lhs < rhs`, `0` otherwise.
/// - `eq` is `1` when `lhs == rhs`, `0` otherwise.
/// lhs and rhs `< 256**NUM_BYTES`
/// `NUM_BYTES` is required to be `<= MAX_BYTES_FIELD`.
#[derive(Clone, Debug)]
pub struct ComparisonGadget<F, const NUM_BYTES: usize> {
    lt: LtGadget<F, NUM_BYTES>,
    eq: IsZeroGadget<F>,
}

impl<F: FieldExt, const NUM_BYTES: usize> ComparisonGadget<F, NUM_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let lt = LtGadget::<F, NUM_BYTES>::construct(cb, lhs, rhs);
        let eq =
            IsZeroGadget::<F>::construct(cb, sum::expr(&lt.diff_bytes()[..]));

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
        let eq = self.eq.assign(region, offset, sum::value(&diff[..]))?;

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

impl<F: FieldExt> PairSelectGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        value: Expression<F>,
        a: Expression<F>,
        b: Expression<F>,
    ) -> Self {
        let is_a = cb.query_bool();
        let is_b = 1.expr() - is_a.expr();

        // Force `is_a` to be `0` when `value != a`
        cb.add_constraint(
            "is_a ⋅ (value - a)",
            is_a.expr() * (value.clone() - a),
        );
        // Force `1 - is_a` to be `0` when `value != b`
        cb.add_constraint(
            "(1 - is_a) ⋅ (value - b)",
            is_b.clone() * (value - b),
        );

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

/// Returns (quotient: numerator/divisor, remainder: numerator%divisor),
/// with `numerator` an expression and `divisor` a constant.
/// Input requirements:
/// - `quotient < 256**NUM_BYTES`
/// - `quotient * divisor < field size`
/// - `remainder < divisor` currently requires a lookup table for `divisor`
#[derive(Clone, Debug)]
pub struct ConstantDivisionGadget<F, const NUM_BYTES: usize> {
    quotient: Cell<F>,
    remainder: Cell<F>,
    divisor: u64,
    quotient_range_check: RangeCheckGadget<F, NUM_BYTES>,
}

impl<F: FieldExt, const NUM_BYTES: usize> ConstantDivisionGadget<F, NUM_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        numerator: Expression<F>,
        divisor: u64,
    ) -> Self {
        let quotient = cb.query_cell();
        let remainder = cb.query_cell();

        // Require that remainder < divisor
        cb.require_in_range(remainder.expr(), divisor);

        // Require that quotient < 2**NUM_BYTES
        // so we can't have any overflow when doing `quotient * divisor`.
        let quotient_range_check =
            RangeCheckGadget::construct(cb, quotient.expr());

        // Check if the division was done correctly
        cb.require_equal(
            "lhnumerator - remainder == quotient ⋅ divisor",
            numerator - remainder.expr(),
            quotient.expr() * divisor.expr(),
        );

        Self {
            quotient,
            remainder,
            divisor,
            quotient_range_check,
        }
    }

    pub(crate) fn expr(&self) -> (Expression<F>, Expression<F>) {
        // Return the quotient and the remainder
        (self.quotient.expr(), self.remainder.expr())
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        numerator: u128,
    ) -> Result<(u128, u128), Error> {
        let divisor = self.divisor as u128;
        let quotient = numerator / divisor;
        let remainder = numerator % divisor;
        self.quotient
            .assign(region, offset, Some(F::from_u128(quotient)))?;
        self.remainder
            .assign(region, offset, Some(F::from_u128(remainder)))?;

        self.quotient_range_check.assign(
            region,
            offset,
            F::from_u128(quotient),
        )?;

        Ok((quotient, remainder))
    }
}

/// Returns `rhs` when `lhs < rhs`, and returns `lhs` otherwise.
/// lhs and rhs `< 256**NUM_BYTES`
/// `NUM_BYTES` is required to be `<= 31`.
#[derive(Clone, Debug)]
pub struct MaxGadget<F, const NUM_BYTES: usize> {
    lt: LtGadget<F, NUM_BYTES>,
    max: Expression<F>,
}

impl<F: FieldExt, const NUM_BYTES: usize> MaxGadget<F, NUM_BYTES> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let lt = LtGadget::construct(cb, lhs.clone(), rhs.clone());
        let max = select::expr(lt.expr(), rhs, lhs);

        Self { lt, max }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.max.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<F, Error> {
        let (lt, _) = self.lt.assign(region, offset, lhs, rhs)?;
        Ok(select::value(lt, rhs, lhs))
    }
}
