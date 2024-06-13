//! # ZKEVM-Gadgets
//!
//! A collection of reusable gadgets for the zk_evm circuits.

#![cfg_attr(docsrs, feature(doc_cfg))]
// We want to have UPPERCASE idents sometimes.
#![allow(clippy::upper_case_acronyms)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(clippy::debug_assert_with_mut_call)]

pub mod batched_is_zero;
pub mod binary_number;
pub mod comparator;
pub mod evm_word;
pub mod is_equal;
pub mod is_zero;
pub mod less_than;
pub mod monotone;
pub mod mul_add;
pub mod range;
pub mod util;

use eth_types::Address;
use eth_types::DebugU256;
use eth_types::ToWord;
use eth_types::U256;
use halo2_proofs::{
    circuit::{AssignedCell, Value},
    halo2curves::{bn256::Fr, ff::PrimeField},
    plonk::Expression,
};

/// Trait used to reduce verbosity with the declaration of the [`Field`]
/// trait and its repr.
pub trait Field:
    PrimeField<Repr = [u8; 32]> + poseidon_base::hash::Hashable + std::convert::From<Fr>
{
    /// Re-expose zero element as a function
    fn zero() -> Self {
        Self::ZERO
    }

    /// Re-expose one element as a function
    fn one() -> Self {
        Self::ONE
    }

    /// Expose the lower 128 bits
    fn get_lower_128(&self) -> u128 {
        u128::from_le_bytes(self.to_repr().as_ref()[..16].try_into().unwrap())
    }
}

// Impl custom `Field` trait for BN256 Fr to be used and consistent with the
// rest of the workspace.
impl Field for Fr {}

/// Trait used to define types that can be converted to a 256 bit scalar value.
pub trait ToScalar<F> {
    /// Convert the type to a scalar value.
    fn to_scalar(&self) -> Option<F>;
}

impl<F: Field> ToScalar<F> for DebugU256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for U256 {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        self.to_little_endian(&mut bytes);
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for Address {
    fn to_scalar(&self) -> Option<F> {
        let mut bytes = [0u8; 32];
        bytes[32 - Self::len_bytes()..].copy_from_slice(self.as_bytes());
        bytes.reverse();
        F::from_repr(bytes).into()
    }
}

impl<F: Field> ToScalar<F> for bool {
    fn to_scalar(&self) -> Option<F> {
        self.to_word().to_scalar()
    }
}

impl<F: Field> ToScalar<F> for u64 {
    fn to_scalar(&self) -> Option<F> {
        Some(F::from(*self))
    }
}

impl<F: Field> ToScalar<F> for usize {
    fn to_scalar(&self) -> Option<F> {
        u64::try_from(*self).ok().map(F::from)
    }
}

#[allow(dead_code)]
/// An assigned cell in the circuit.
#[derive(Clone, Debug)]
pub struct Variable<T, F: Field> {
    assig_cell: AssignedCell<F, F>,
    value: Value<T>,
}

impl<T, F: Field> Variable<T, F> {
    pub(crate) fn new(assig_cell: AssignedCell<F, F>, value: Value<T>) -> Self {
        Self { assig_cell, value }
    }
}

/// Restrict an expression to be a boolean.
pub fn bool_check<F: Field>(value: Expression<F>) -> Expression<F> {
    range_check(value, 2)
}

/// Restrict an expression such that 0 <= word < range.
pub fn range_check<F: Field>(word: Expression<F>, range: usize) -> Expression<F> {
    (1..range).fold(word.clone(), |acc, i| {
        acc * (Expression::Constant(F::from(i as u64)) - word.clone())
    })
}
