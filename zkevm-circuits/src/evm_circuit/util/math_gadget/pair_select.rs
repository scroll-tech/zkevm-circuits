use crate::{
    evm_circuit::util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        CachedRegion, Cell,
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
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
        cb: &mut EVMConstraintBuilder<F>,
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
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
        a: F,
        _b: F,
    ) -> Result<(F, F), Error> {
        let is_a = if value == a { F::one() } else { F::zero() };
        self.is_a.assign(region, offset, Value::known(is_a))?;

        Ok((is_a, F::one() - is_a))
    }
}

#[cfg(test)]
mod tests {
    use crate::evm_circuit::util::constraint_builder::ConstrainBuilderCommon;

    use super::{super::test_util::*, *};
    use eth_types::*;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// PairSelectionTestContainer: require(v == a if SELECT_A else b)
    struct PairSelectionTestContainer<F, const SELECT_A: bool> {
        select_gadget: PairSelectGadget<F>,
        a: Cell<F>,
        b: Cell<F>,
        v: Cell<F>,
    }

    impl<F: Field, const SELECT_A: bool> MathGadgetContainer<F>
        for PairSelectionTestContainer<F, SELECT_A>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let v = cb.query_cell();
            let a = cb.query_cell();
            let b = cb.query_cell();
            let select_gadget = PairSelectGadget::<F>::construct(cb, v.expr(), a.expr(), b.expr());
            cb.require_equal(
                "is_a * is_b == 0",
                select_gadget.expr().0 * select_gadget.expr().1,
                0.expr(),
            );

            if SELECT_A {
                cb.require_equal("is_a == 1", select_gadget.expr().0, 1.expr());
            } else {
                cb.require_equal("is_b == 1", select_gadget.expr().1, 1.expr());
            }

            PairSelectionTestContainer {
                select_gadget,
                v,
                a,
                b,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let v = witnesses[0].to_scalar().unwrap();
            let a = witnesses[1].to_scalar().unwrap();
            let b = witnesses[2].to_scalar().unwrap();
            let offset = 0;

            self.v.assign(region, offset, Value::known(v))?;
            self.a.assign(region, offset, Value::known(a))?;
            self.b.assign(region, offset, Value::known(b))?;
            self.select_gadget.assign(region, offset, v, a, b)?;

            Ok(())
        }
    }

    #[test]
    fn test_pairselect_eq() {
        try_test!(
            PairSelectionTestContainer<Fr, true>,
            [Word::from(0), Word::from(0), Word::from(0)],
            true,
        );
        try_test!(
            PairSelectionTestContainer<Fr, true>,
            [Word::from(2898), Word::from(2898), Word::from(2898)],
            true,
        );
    }

    #[test]
    fn test_pairselect_expect_a_and_a() {
        try_test!(
            PairSelectionTestContainer<Fr, true>,
            [Word::from(0), Word::from(0), Word::from(1)],
            true,
        );
        try_test!(
            PairSelectionTestContainer<Fr, true>,
            [Word::from(2898), Word::from(2898), Word::from(1)],
            true,
        );
        try_test!(
            PairSelectionTestContainer<Fr, true>,
            [WORD_LOW_MAX, WORD_LOW_MAX, Word::from(1)],
            true,
        );
    }

    #[test]
    fn test_pairselect_expect_a_but_b() {
        try_test!(
            PairSelectionTestContainer<Fr, true>,
            [Word::from(0), Word::from(1), Word::from(0)],
            false,
        );
        try_test!(
            PairSelectionTestContainer<Fr, true>,
            [Word::from(2989), Word::from(1), Word::from(2989)],
            false,
        );
    }

    #[test]
    fn test_pairselect_expect_b_and_b() {
        try_test!(
            PairSelectionTestContainer<Fr, false>,
            [Word::from(0), Word::from(1), Word::from(0)],
            true,
        );
        try_test!(
            PairSelectionTestContainer<Fr, false>,
            [Word::from(2989), Word::from(1), Word::from(2989)],
            true,
        );
    }
}
