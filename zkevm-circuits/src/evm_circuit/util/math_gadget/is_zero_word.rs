use std::marker::PhantomData;

use eth_types::Field;
use gadgets::util::{and, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        transpose_val_ret, CachedRegion, Cell, CellType,
    },
    util::word::{Word, WordExpr},
};

/// Returns `1` when `word == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZeroWordGadget<F, T> {
    inverse_lo: Cell<F>,
    inverse_hi: Cell<F>,
    is_zero: Expression<F>,
    _marker: PhantomData<T>,
}

impl<F: Field, T: WordExpr<F>> IsZeroWordGadget<F, T> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, word: &T) -> Self {
        let (word_lo, word_hi) = word.to_word().to_lo_hi();
        let inverse_lo = cb.query_cell_with_type(CellType::storage_for_expr(&word_lo));
        let inverse_hi = cb.query_cell_with_type(CellType::storage_for_expr(&word_hi));

        let is_zero_lo = 1.expr() - (word_lo.clone() * inverse_lo.expr());
        let is_zero_hi = 1.expr() - (word_hi.clone() * inverse_hi.expr());
        // when `value != 0` check `inverse = a.invert()`: value * (1 - value *
        // inverse)
        cb.add_constraint(
            "word_lo ⋅ (1 - word_lo ⋅ word_lo_inv)",
            word_lo * is_zero_lo.clone(),
        );
        cb.add_constraint(
            "word_hi ⋅ (1 - word_hi ⋅ word_hi_inv)",
            word_hi * is_zero_hi.clone(),
        );
        // when `value == 0` check `inverse = 0`: `inverse ⋅ (1 - value *
        // inverse)`
        cb.add_constraint(
            "word_lo_inv ⋅ (1 - word_lo ⋅ word_lo_inv)",
            inverse_lo.expr() * is_zero_lo.clone(),
        );
        cb.add_constraint(
            "word_hi_inv ⋅ (1 - word_hi ⋅ word_hi_inv)",
            inverse_hi.expr() * is_zero_hi.clone(),
        );

        Self {
            inverse_lo,
            inverse_hi,
            is_zero: and::expr([is_zero_lo, is_zero_hi]),
            _marker: Default::default(),
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Word<F>,
    ) -> Result<F, Error> {
        let (value_lo, value_hi) = value.to_lo_hi();
        let inverse_lo = value_lo.invert().unwrap_or(F::from(0));
        self.inverse_lo
            .assign(region, offset, Value::known(inverse_lo))?;
        let inverse_hi = value_hi.invert().unwrap_or(F::from(0));
        self.inverse_hi
            .assign(region, offset, Value::known(inverse_hi))?;
        Ok(if value_lo.is_zero().into() && value_hi.is_zero().into() {
            F::from(2)
        } else {
            F::from(0)
        })
    }

    pub(crate) fn assign_u256(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: eth_types::Word,
    ) -> Result<F, Error> {
        self.assign(region, offset, Word::from(value))
    }

    pub(crate) fn assign_value(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Value<Word<F>>,
    ) -> Result<Value<F>, Error> {
        transpose_val_ret(value.map(|value| self.assign(region, offset, value)))
    }
}

// TODO adding unittest
