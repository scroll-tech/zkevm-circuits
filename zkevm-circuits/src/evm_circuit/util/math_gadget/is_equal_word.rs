use std::marker::PhantomData;

use eth_types::Field;
use gadgets::util::and;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::util::{
        constraint_builder::EVMConstraintBuilder, transpose_val_ret, CachedRegion,
    },
    util::word::{Word, WordExpr},
};

use super::IsZeroGadget;

/// Returns `1` when `lhs == rhs`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsEqualWordGadget<F, T1, T2> {
    is_zero_lo: IsZeroGadget<F>,
    is_zero_hi: IsZeroGadget<F>,
    _marker: PhantomData<(T1, T2)>,
}

impl<F: Field, T1: WordExpr<F>, T2: WordExpr<F>> IsEqualWordGadget<F, T1, T2> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, lhs: &T1, rhs: &T2) -> Self {
        let (lhs_lo, lhs_hi) = lhs.to_word().to_lo_hi();
        let (rhs_lo, rhs_hi) = rhs.to_word().to_lo_hi();
        let is_zero_lo = IsZeroGadget::construct(cb, lhs_lo - rhs_lo);
        let is_zero_hi = IsZeroGadget::construct(cb, lhs_hi - rhs_hi);

        Self {
            is_zero_lo,
            is_zero_hi,
            _marker: Default::default(),
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        and::expr([self.is_zero_lo.expr(), self.is_zero_hi.expr()])
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: Word<F>,
        rhs: Word<F>,
    ) -> Result<F, Error> {
        let (lhs_lo, lhs_hi) = lhs.to_lo_hi();
        let (rhs_lo, rhs_hi) = rhs.to_lo_hi();
        self.is_zero_lo.assign(region, offset, lhs_lo - rhs_lo)?;
        self.is_zero_hi.assign(region, offset, lhs_hi - rhs_hi)?;
        Ok(F::from(2))
    }

    pub(crate) fn assign_value(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: Value<Word<F>>,
        rhs: Value<Word<F>>,
    ) -> Result<Value<F>, Error> {
        transpose_val_ret(
            lhs.zip(rhs)
                .map(|(lhs, rhs)| self.assign(region, offset, lhs, rhs)),
        )
    }

    pub(crate) fn assign_u256(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: eth_types::Word,
        rhs: eth_types::Word,
    ) -> Result<F, Error> {
        self.assign(region, offset, Word::from(lhs), Word::from(rhs))
    }
}

// TODO add unittest
