use crate::evm_circuit::{
    param::MAX_N_BYTES_INTEGER,
    util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        from_bytes, CachedRegion, Cell,
    },
};
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Requires that the passed in value is within the specified range.
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER`.
#[derive(Clone, Debug)]
pub struct RangeCheckGadget<F, const N_BYTES: usize> {
    parts: [Cell<F>; N_BYTES],
}

impl<F: Field, const N_BYTES: usize> RangeCheckGadget<F, N_BYTES> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, value: Expression<F>) -> Self {
        assert!(N_BYTES <= MAX_N_BYTES_INTEGER);
        let parts = cb.query_bytes();

        // Require that the reconstructed value from the parts equals the
        // original value
        cb.require_equal(
            "Constrain bytes recomposited to value",
            value,
            from_bytes::expr(&parts),
        );

        Self { parts }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
    ) -> Result<(), Error> {
        let bytes = value.to_repr();
        for (idx, part) in self.parts.iter().enumerate() {
            part.assign(region, offset, Value::known(F::from(bytes[idx] as u64)))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_util::*, *};
    use eth_types::*;
    use gadgets::util::Expr;
    use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// RangeCheckTestContainer: require(a in [0..1<<(8*N_BYTES)])
    struct RangeCheckTestContainer<F, const N_BYTES: usize> {
        range_check_gadget: RangeCheckGadget<F, N_BYTES>,
        a: Cell<F>,
    }

    impl<F: Field, const N_BYTES: usize> MathGadgetContainer<F>
        for RangeCheckTestContainer<F, N_BYTES>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let a = cb.query_cell();
            let range_check_gadget = RangeCheckGadget::<F, N_BYTES>::construct(cb, a.expr());
            RangeCheckTestContainer {
                range_check_gadget,
                a,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let a = witnesses[0].to_scalar().unwrap();
            let offset = 0;

            self.a.assign(region, offset, Value::known(a))?;
            self.range_check_gadget.assign(region, 0, a)?;

            Ok(())
        }
    }

    #[test]
    fn test_rangecheck_just_in_range() {
        try_test!(RangeCheckTestContainer<Fr, 4>, vec![Word::from(0)], true);

        try_test!(RangeCheckTestContainer<Fr, 4>, vec![Word::from(1)], true);
        // max - 1
        try_test!(
            RangeCheckTestContainer<Fr, 4>,
            vec![Word::from((1u64 << 32) - 1)],
            true,
        );
    }

    #[test]
    fn test_rangecheck_out_of_range() {
        try_test!(
            RangeCheckTestContainer<Fr, 4>,
            vec![Word::from(1u64 << 32)],
            false,
        );
    }
}
