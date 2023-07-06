use crate::evm_circuit::util::{
    constraint_builder::EVMConstraintBuilder, math_gadget::*, sum, CachedRegion,
};
use eth_types::Field;
use halo2_proofs::plonk::{Error, Expression};

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
        cb: &mut EVMConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        let lt = LtGadget::<F, N_BYTES>::construct(cb, lhs, rhs);
        let eq = IsZeroGadget::<F>::construct(cb, "", sum::expr(&lt.diff_bytes()));

        Self { lt, eq }
    }

    pub(crate) fn expr(&self) -> (Expression<F>, Expression<F>) {
        (self.lt.expr(), self.eq.expr())
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
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

#[cfg(test)]
mod tests {
    use super::{test_util::*, *};
    use crate::evm_circuit::util::{constraint_builder::ConstrainBuilderCommon, Cell};
    use eth_types::*;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// ComparisonTestContainer: require(a == b if CHECK_EQ else a < b)
    struct ComparisonTestContainer<F, const N: usize, const CHECK_EQ: bool> {
        cmp_gadget: ComparisonGadget<F, N>,
        a: Cell<F>,
        b: Cell<F>,
    }

    impl<F: Field, const N: usize, const CHECK_EQ: bool> MathGadgetContainer<F>
        for ComparisonTestContainer<F, N, CHECK_EQ>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let a = cb.query_cell();
            let b = cb.query_cell();
            let cmp_gadget = ComparisonGadget::<F, N>::construct(cb, a.expr(), b.expr());
            cb.require_equal(
                "(a < b) * (a == b) == 0",
                cmp_gadget.expr().0 * cmp_gadget.expr().1,
                0.expr(),
            );

            if CHECK_EQ {
                cb.require_equal("a == b", cmp_gadget.expr().1, 1.expr());
            } else {
                cb.require_equal("a < b", cmp_gadget.expr().0, 1.expr());
            }

            ComparisonTestContainer { cmp_gadget, a, b }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let a = witnesses[0].to_scalar().unwrap();
            let b = witnesses[1].to_scalar().unwrap();
            let offset = 0;

            self.a.assign(region, offset, Value::known(a))?;
            self.b.assign(region, offset, Value::known(b))?;
            self.cmp_gadget.assign(region, offset, a, b)?;

            Ok(())
        }
    }

    #[test]
    fn test_comparison_0_eq() {
        // a == b check
        try_test!(
            ComparisonTestContainer<Fr, 4, true>,
            vec![Word::from(0), Word::from(0)],
            true,
        );
    }

    #[test]
    fn test_comparison_1_eq() {
        try_test!(
            ComparisonTestContainer<Fr, 4, true>,
            vec![Word::from(1), Word::from(1)],
            true,
        );
    }

    #[test]
    fn test_comparison_max_eq() {
        try_test!(
            ComparisonTestContainer<Fr, 4, true>,
            vec![Word::from(1 << 4), Word::from(1 << 4)],
            true,
        );
    }

    #[test]
    fn test_comparison_0_neq_max() {
        try_test!(
            ComparisonTestContainer<Fr, 4, true>,
            vec![Word::from(0), Word::from(1 << 4)],
            false,
        );
    }

    // a < b check
    #[test]
    fn test_comparison_0_lt_1() {
        try_test!(
            ComparisonTestContainer<Fr, 4, false>,
            vec![Word::from(0), Word::from(1)],
            true,
        );
    }

    #[test]
    fn test_comparison_1_lt_max() {
        try_test!(
            ComparisonTestContainer<Fr, 4, false>,
            vec![Word::from(1), Word::from(1 << 4)],
            true,
        );
    }

    #[test]
    fn test_comparison_1_lt_0() {
        try_test!(
            ComparisonTestContainer<Fr, 4, false>,
            vec![Word::from(1), Word::from(0)],
            false,
        );
    }

    #[test]
    fn test_comparison_8bytes_lowmax_lt_highmax() {
        const N_BYTES: usize = 16;
        let half_max_lo = U256([u64::MAX, 0, 0, 0]);
        let half_max_hi = U256([0, u64::MAX, 0, 0]);
        try_test!(
            ComparisonTestContainer<Fr, N_BYTES, false>,
            vec![half_max_lo, half_max_hi],
            true,
        );

        try_test!(
            ComparisonTestContainer<Fr, N_BYTES, false>,
            vec![half_max_hi, half_max_lo],
            false,
        );
    }

    #[test]
    fn test_comparison_overflow() {
        try_test!(
            ComparisonTestContainer<Fr, 4, false>,
            vec![Word::from(10000), Word::from(1 << (4 + 1))],
            false,
        );
    }
}
