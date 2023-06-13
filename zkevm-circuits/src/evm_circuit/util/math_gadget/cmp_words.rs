use crate::{
    evm_circuit::util::{
        self, constraint_builder::EVMConstraintBuilder, from_bytes, math_gadget::*, select,
        CachedRegion,
    },
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::plonk::{Error, Expression};

#[derive(Clone, Debug)]
/// CmpWordsGadget compares two words, exposing `eq`  and `lt`
pub(crate) struct CmpWordsGadget<F> {
    comparison_lo: ComparisonGadget<F, 16>,
    comparison_hi: ComparisonGadget<F, 16>,
    pub eq: Expression<F>,
    pub lt: Expression<F>,
}

impl<F: Field> CmpWordsGadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        a: &util::Word<F>,
        b: &util::Word<F>,
    ) -> Self {
        // `a[0..16] <= b[0..16]`
        let comparison_lo = ComparisonGadget::construct(
            cb,
            from_bytes::expr(&a.cells[0..16]),
            from_bytes::expr(&b.cells[0..16]),
        );

        let (lt_lo, eq_lo) = comparison_lo.expr();

        // `a[16..32] <= b[16..32]`
        let comparison_hi = ComparisonGadget::construct(
            cb,
            from_bytes::expr(&a.cells[16..32]),
            from_bytes::expr(&b.cells[16..32]),
        );
        let (lt_hi, eq_hi) = comparison_hi.expr();

        // `a < b` when:
        // - `a[16..32] < b[16..32]` OR
        // - `a[16..32] == b[16..32]` AND `a[0..16] < b[0..16]`
        let lt = select::expr(lt_hi, 1.expr(), eq_hi.clone() * lt_lo);

        // `a == b` when both parts are equal
        let eq = eq_hi * eq_lo;

        Self {
            comparison_lo,
            comparison_hi,
            lt,
            eq,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        a: Word,
        b: Word,
    ) -> Result<(), Error> {
        // `a[0..1] <= b[0..16]`
        self.comparison_lo.assign(
            region,
            offset,
            from_bytes::value(&a.to_le_bytes()[0..16]),
            from_bytes::value(&b.to_le_bytes()[0..16]),
        )?;

        // `a[16..32] <= b[16..32]`
        self.comparison_hi.assign(
            region,
            offset,
            from_bytes::value(&a.to_le_bytes()[16..32]),
            from_bytes::value(&b.to_le_bytes()[16..32]),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{test_util::*, *};
    use crate::evm_circuit::util::constraint_builder::ConstrainBuilderCommon;
    use eth_types::Word;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// CmpWordGadgetTestContainer: require(a == b if CHECK_EQ else a < b)
    struct CmpWordGadgetTestContainer<F, const CHECK_EQ: bool> {
        cmp_gadget: CmpWordsGadget<F>,
        a: util::Word<F>,
        b: util::Word<F>,
    }

    impl<F: Field, const CHECK_EQ: bool> MathGadgetContainer<F>
        for CmpWordGadgetTestContainer<F, CHECK_EQ>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let a = cb.query_word_rlc();
            let b = cb.query_word_rlc();
            let cmp_gadget = CmpWordsGadget::<F>::construct(cb, &a, &b);
            cb.require_equal(
                "(a < b) * (a == b) == 0",
                cmp_gadget.eq.clone() * cmp_gadget.lt.clone(),
                0.expr(),
            );

            if CHECK_EQ {
                cb.require_equal("a == b", cmp_gadget.eq.clone(), 1.expr());
            } else {
                cb.require_equal("a < b", cmp_gadget.lt.clone(), 1.expr());
            }

            CmpWordGadgetTestContainer { cmp_gadget, a, b }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let a = witnesses[0];
            let b = witnesses[1];
            let offset = 0;

            self.a.assign(region, offset, Some(a.to_le_bytes()))?;
            self.b.assign(region, offset, Some(b.to_le_bytes()))?;
            self.cmp_gadget.assign(region, offset, a, b)?;
            Ok(())
        }
    }

    #[test]
    fn test_cmpword_0_eq() {
        // a == b check
        try_test!(
            CmpWordGadgetTestContainer<Fr, true>,
            vec![Word::from(0), Word::from(0)],
            true,
        );
    }

    #[test]
    fn test_cmpword_1_eq() {
        try_test!(
            CmpWordGadgetTestContainer<Fr, true>,
            vec![Word::from(1), Word::from(1)],
            true,
        );
    }

    #[test]
    fn test_cmpword_wordmax_eq() {
        try_test!(
            CmpWordGadgetTestContainer<Fr, true>,
            vec![Word::MAX, Word::MAX],
            true,
        );
    }

    #[test]
    fn test_cmpword_0_neq_wordmax() {
        try_test!(
            CmpWordGadgetTestContainer<Fr, true>,
            vec![Word::from(0), Word::MAX],
            false,
        );
    }

    // a < b check
    #[test]
    fn test_cmpword_0_lt_1() {
        try_test!(
            CmpWordGadgetTestContainer<Fr, false>,
            vec![Word::from(0), Word::from(1)],
            true,
        );
    }

    #[test]
    fn test_cmpword_1_lt_wordmax() {
        try_test!(
            CmpWordGadgetTestContainer<Fr, false>,
            vec![Word::from(1), Word::MAX],
            true,
        );
    }

    #[test]
    fn test_cmpword_1_lt_0() {
        try_test!(
            CmpWordGadgetTestContainer<Fr, false>,
            vec![Word::from(1), Word::from(0)],
            false,
        );
    }

    #[test]
    fn test_cmpword_lowmax_lt_highmax() {
        try_test!(
            CmpWordGadgetTestContainer<Fr, false>,
            vec![WORD_LOW_MAX, WORD_HIGH_MAX],
            true,
        );
    }

    #[test]
    fn test_cmpword_highmax_lt_lowmax() {
        try_test!(
            CmpWordGadgetTestContainer<Fr, false>,
            vec![WORD_HIGH_MAX, WORD_LOW_MAX],
            false,
        );
    }
}
