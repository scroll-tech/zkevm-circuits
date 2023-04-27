use crate::evm_circuit::util::{
    constraint_builder::EVMConstraintBuilder, math_gadget::*, select, transpose_val_ret,
    CachedRegion,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
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
        cb: &mut EVMConstraintBuilder<F>,
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
        region: &mut CachedRegion<'_, '_, F>,
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

    pub(crate) fn assign_value(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: Value<F>,
        rhs: Value<F>,
    ) -> Result<Value<(F, F)>, Error> {
        transpose_val_ret(
            lhs.zip(rhs)
                .map(|(lhs, rhs)| self.assign(region, offset, lhs, rhs)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{test_util::*, *};
    use crate::evm_circuit::util::{constraint_builder::ConstrainBuilderCommon, Cell};
    use eth_types::{ToScalar, Word};
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// MinMaxTestContainer: require(min(a, b) == (a if MIN_IS_A else b))
    struct MinMaxTestContainer<F, const N_BYTES: usize, const MIN_IS_A: bool> {
        minmax_gadget: MinMaxGadget<F, N_BYTES>,
        a: Cell<F>,
        b: Cell<F>,
    }

    impl<F: Field, const N_BYTES: usize, const MIN_IS_A: bool> MathGadgetContainer<F>
        for MinMaxTestContainer<F, N_BYTES, MIN_IS_A>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let a = cb.query_cell();
            let b = cb.query_cell();
            let minmax_gadget = MinMaxGadget::<F, N_BYTES>::construct(cb, a.expr(), b.expr());

            if MIN_IS_A {
                cb.require_equal("min == a", minmax_gadget.min(), a.expr());
                cb.require_equal("max == b", minmax_gadget.max(), b.expr());
            } else {
                cb.require_equal("min == b", minmax_gadget.min(), b.expr());
                cb.require_equal("max == a", minmax_gadget.max(), a.expr());
            }

            MinMaxTestContainer {
                minmax_gadget,
                a,
                b,
            }
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
            self.minmax_gadget.assign(region, offset, a, b)?;

            Ok(())
        }
    }

    #[test]
    fn test_minmax_eq() {
        // a == b
        try_test!(
            MinMaxTestContainer<Fr, 4, true>,
            vec![Word::from(0), Word::from(0)],
            true,
        );
        try_test!(
            MinMaxTestContainer<Fr, 4, true>,
            vec![Word::from(5), Word::from(5)],
            true,
        );
        try_test!(
            MinMaxTestContainer<Fr, 16, true>,
            vec![WORD_LOW_MAX, WORD_LOW_MAX],
            true,
        );
    }

    #[test]
    fn test_minmax_expect_min_a() {
        // min == a, max == b
        try_test!(
            MinMaxTestContainer<Fr, 1, true>,
            vec![Word::from(0), Word::from(1)],
            true,
        );
        try_test!(
            MinMaxTestContainer<Fr, 1, true>,
            vec![Word::from(3), Word::from(5)],
            true,
        );
        try_test!(
            MinMaxTestContainer<Fr, 31, true>,
            vec![WORD_LOW_MAX, WORD_LOW_MAX],
            true,
        );
    }

    #[test]
    fn test_minmax_unexpect_min_a() {
        // min == b, max == a
        try_test!(
            MinMaxTestContainer<Fr, 1, true>,
            vec![Word::from(1), Word::from(0)],
            false,
        );
        try_test!(
            MinMaxTestContainer<Fr, 1, true>,
            vec![Word::from(256), Word::from(3)],
            false,
        );
        try_test!(
            MinMaxTestContainer<Fr, 31, true>,
            vec![WORD_LOW_MAX, Word::from(123456)],
            false,
        );
    }

    #[test]
    fn test_minmax_expect_min_b() {
        // min == a, max == b
        try_test!(
            MinMaxTestContainer<Fr, 1, false>,
            vec![Word::from(1), Word::from(0)],
            true,
        );

        try_test!(
            MinMaxTestContainer<Fr, 4, false>,
            vec![Word::from(777), Word::from(44)],
            true,
        );

        try_test!(
            MinMaxTestContainer<Fr, 17, false>,
            vec![WORD_LOW_MAX+1, WORD_LOW_MAX],
            true,
        );
    }
}
