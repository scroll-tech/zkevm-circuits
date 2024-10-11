//! Utility traits, functions used in the crate.
use crate::Field;
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    H256, U256,
};
use halo2_proofs::plonk::Expression;

/// Returns the sum of the passed in cells
pub mod sum {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression for the sum of the list of expressions.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(0.expr(), |acc, input| acc + input.expr())
    }

    /// Returns the sum of the given list of values within the field.
    pub fn value<F: Field>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::ZERO, |acc, value| acc + F::from(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod and {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression that evaluates to 1 only if all the expressions in
    /// the given list are 1, else returns 0.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        inputs
            .into_iter()
            .fold(1.expr(), |acc, input| acc * input.expr())
    }

    /// Returns the product of all given values.
    pub fn value<F: Field>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::ONE, |acc, input| acc * input)
    }
}

/// Returns `1` when `expr[0] || expr[1] || ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub mod or {
    use super::{and, not};
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression that evaluates to 1 if any expression in the given
    /// list is 1. Returns 0 if all the expressions were 0.
    pub fn expr<F: Field, E: Expr<F>, I: IntoIterator<Item = E>>(inputs: I) -> Expression<F> {
        not::expr(and::expr(inputs.into_iter().map(not::expr)))
    }

    /// Returns the value after passing all given values through the OR gate.
    pub fn value<F: Field>(inputs: Vec<F>) -> F {
        not::value(and::value(inputs.into_iter().map(not::value).collect()))
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub mod not {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression that represents the NOT of the given expression.
    pub fn expr<F: Field, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    /// Returns a value that represents the NOT of the given value.
    pub fn value<F: Field>(b: F) -> F {
        F::ONE - b
    }
}

/// Returns `a ^ b`.
/// `a` and `b` needs to be boolean
pub mod xor {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns an expression that represents the XOR of the given expression.
    pub fn expr<F: Field, E: Expr<F>>(a: E, b: E) -> Expression<F> {
        a.expr() + b.expr() - 2.expr() * a.expr() * b.expr()
    }

    /// Returns a value that represents the XOR of the given value.
    pub fn value<F: Field>(a: F, b: F) -> F {
        a + b - F::from(2u64) * a * b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub mod select {
    use crate::util::Expr;
    use crate::Field;
    use halo2_proofs::plonk::Expression;

    /// Returns the `when_true` expression when the selector is true, else
    /// returns the `when_false` expression.
    pub fn expr<F: Field>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    /// Returns the `when_true` value when the selector is true, else returns
    /// the `when_false` value.
    pub fn value<F: Field>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::ONE - selector) * when_false
    }

    /// Returns the `when_true` word when selector is true, else returns the
    /// `when_false` word.
    pub fn value_word<F: Field>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::ONE {
            when_true
        } else {
            when_false
        }
    }
}

/// Trait that implements functionality to get a constant expression from
/// commonly used types.
pub trait Expr<F: Field> {
    /// Returns an expression for the type.
    fn expr(&self) -> Expression<F>;
}

/// Implementation trait `Expr` for type able to be casted to u64
#[macro_export]
macro_rules! impl_expr {
    ($type:ty) => {
        impl<F: Field> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from(*self as u64))
            }
        }
    };
    ($type:ty, $method:path) => {
        impl<F: $crate::Field> $crate::util::Expr<F> for $type {
            #[inline]
            fn expr(&self) -> Expression<F> {
                Expression::Constant(F::from($method(self) as u64))
            }
        }
    };
}

impl_expr!(bool);
impl_expr!(u8);
impl_expr!(u64);
impl_expr!(usize);
impl_expr!(OpcodeId, OpcodeId::as_u8);
impl_expr!(GasCost, GasCost::as_u64);

impl<F: Field> Expr<F> for Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        self.clone()
    }
}

impl<F: Field> Expr<F> for &Expression<F> {
    #[inline]
    fn expr(&self) -> Expression<F> {
        (*self).clone()
    }
}

impl<F: Field> Expr<F> for i32 {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(
            F::from(self.unsigned_abs() as u64) * if self.is_negative() { -F::ONE } else { F::ONE },
        )
    }
}

/// Given a bytes-representation of an expression, it computes and returns the
/// single expression.
pub fn expr_from_bytes<F: Field, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
    let mut value = 0.expr();
    let mut multiplier = F::ONE;
    for byte in bytes.iter() {
        value = value + byte.expr() * multiplier;
        multiplier *= F::from(256);
    }
    value
}

/// Given a u16-array-representation of an expression, it computes and returns
/// the single expression.
pub fn expr_from_u16<F: Field, E: Expr<F>>(u16s: &[E]) -> Expression<F> {
    let mut value = 0.expr();
    let mut multiplier = F::ONE;
    for u16 in u16s.iter() {
        value = value + u16.expr() * multiplier;
        multiplier *= F::from(2u64.pow(16));
    }
    value
}

/// Returns 2**by as Field
pub fn pow_of_two<F: Field>(by: usize) -> F {
    F::from(2).pow([by as u64, 0, 0, 0])
}

/// Returns tuple consists of low and high part of U256
pub fn split_u256(value: &U256) -> (U256, U256) {
    (
        U256([value.0[0], value.0[1], 0, 0]),
        U256([value.0[2], value.0[3], 0, 0]),
    )
}

/// Split a U256 value into 4 64-bit limbs stored in U256 values.
pub fn split_u256_limb64(value: &U256) -> [U256; 4] {
    [
        U256([value.0[0], 0, 0, 0]),
        U256([value.0[1], 0, 0, 0]),
        U256([value.0[2], 0, 0, 0]),
        U256([value.0[3], 0, 0, 0]),
    ]
}

/// Split a 32-bytes hash into (hi, lo) Field elements.
pub fn split_h256<F: Field>(value: H256) -> (F, F) {
    let be_bytes = value.to_fixed_bytes();
    let mut hi_le_bytes = [0u8; 32];
    let mut lo_le_bytes = [0u8; 32];
    hi_le_bytes[0x10..0x20].copy_from_slice(&be_bytes[0x00..0x10]);
    lo_le_bytes[0x10..0x20].copy_from_slice(&be_bytes[0x10..0x20]);
    hi_le_bytes.reverse();
    lo_le_bytes.reverse();
    (
        F::from_repr(hi_le_bytes).expect("try F from 128-bits should not fail"),
        F::from_repr(lo_le_bytes).expect("try F from 128-bits should not fail"),
    )
}

#[cfg(test)]
mod tests {
    use eth_types::H256;
    use halo2_proofs::halo2curves::bn256::Fr;

    use super::split_h256;

    #[test]
    fn test_split_h256() {
        let zero = Fr::zero();
        let in_outs = [
            // all zeroes
            (H256::zero(), zero, zero),
            (
                H256([
                    0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0x01,
                ]),
                Fr::from_raw([0, 1 << 56 /* 256 ^ 7 */, 0, 0]),
                Fr::from_raw([0x01, 0, 0, 0]),
            ),
            // 0xFB, 0xFC, 0, 0, 0, 0, 0, 0,
            // 0, 0, 0, 0, 0, 0, 0xFD, 0xFE,
            // 0x01, 0x02, 0, 0, 0, 0, 0, 0,
            // 0, 0, 0, 0, 0, 0, 0x03, 0x04
            (
                H256([
                    0xfb, 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd, 0xfe, 0x01, 0x02, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0x04,
                ]),
                Fr::from_raw([0xfd * 256 + 0xfe, 0xfb * (1 << 56) + 0xfc * (1 << 48), 0, 0]),
                Fr::from_raw([0x03 * 256 + 0x04, (1 << 56) + 0x02 * (1 << 48), 0, 0]),
            ),
        ];
        for (hash_in, expected_hi, expected_lo) in in_outs {
            let (hi, lo) = split_h256::<Fr>(hash_in);
            assert_eq!(hi, expected_hi);
            assert_eq!(lo, expected_lo);
        }
    }
}
