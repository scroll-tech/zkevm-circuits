use std::marker::PhantomData;

use crate::{
    evm_circuit::util::{
        constraint_builder::EVMConstraintBuilder, from_bytes, math_gadget::*, split_u256,
        CachedRegion, Cell
    }, 
    util::word::{WordExpr, Word32Cell}
};
use eth_types::{Field, Word};
use halo2_proofs::plonk::{Error, Expression};

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs are both 256-bit word.
#[derive(Clone, Debug)]
pub struct LtWordGadget<F> {
    comparison_hi: ComparisonGadget<F, 16>,
    lt_lo: LtGadget<F, 16>,
}

impl<F: Field> LtWordGadget<F> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, lhs: &Word32Cell<F>, rhs: &Word32Cell<F>) -> Self {
        let comparison_hi = ComparisonGadget::construct(
            cb,
            from_bytes::expr(&lhs.limbs[16..]),
            from_bytes::expr(&rhs.limbs[16..]),
        );
        let lt_lo = LtGadget::construct(
            cb,
            from_bytes::expr(&lhs.limbs[..16]),
            from_bytes::expr(&rhs.limbs[..16]),
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
        region: &mut CachedRegion<'_, '_, F>,
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

#[cfg(test)]
mod tests {
    use crate::evm_circuit::util::constraint_builder::ConstrainBuilderCommon;

    use super::{test_util::*, *};
    use eth_types::*;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};
    use crate::util::word::{Word32Cell, WordExpr};

    #[derive(Clone)]
    /// LtWordTestContainer: require(a < b)
    struct LtWordTestContainer<F> {
        ltword_gadget: LtWordGadget<F>,
        a: Word32Cell<F>,
        b: Word32Cell<F>,
    }

    impl<F: Field> MathGadgetContainer<F> for LtWordTestContainer<F> {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let a = cb.query_word32();
            let b = cb.query_word32();
            let ltword_gadget = LtWordGadget::<F>::construct(cb, &a, &b);
            cb.require_equal("a < b", ltword_gadget.expr(), 1.expr());
            LtWordTestContainer {
                ltword_gadget,
                a,
                b,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let a = witnesses[0];
            let b = witnesses[1];
            let offset = 0;

            self.a.assign_u256(region, offset, a)?;
            self.b.assign_u256(region, offset, b)?;
            self.ltword_gadget.assign(region, 0, a, b)?;

            Ok(())
        }
    }

    #[test]
    fn test_ltword_expect() {
        try_test!(
            LtWordTestContainer<Fr>,
            vec![Word::from(0), Word::from(1)],
            true,
        );
        try_test!(
            LtWordTestContainer<Fr>,
            vec![Word::from(1), Word::MAX],
            true,
        );
        try_test!(
            LtWordTestContainer<Fr>,
            vec![WORD_LOW_MAX, WORD_HIGH_MAX],
            true,
        );
        try_test!(
            LtWordTestContainer<Fr>,
            vec![Word::from(90), WORD_LOW_MAX],
            true,
        );
        try_test!(
            LtWordTestContainer<Fr>,
            vec![Word::from(90), WORD_HIGH_MAX],
            true,
        );
    }

    #[test]
    fn test_ltword_unexpect() {
        try_test!(
            LtWordTestContainer<Fr>,
            vec![Word::from(1), Word::from(0)],
            false,
        );
        try_test!(LtWordTestContainer<Fr>, vec![Word::MAX, Word::MAX], false,);

        try_test!(
            LtWordTestContainer<Fr>,
            vec![WORD_HIGH_MAX, WORD_LOW_MAX],
            false,
        );
    }
}
