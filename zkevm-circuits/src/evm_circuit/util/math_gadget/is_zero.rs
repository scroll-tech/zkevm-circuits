use crate::{
    evm_circuit::util::{
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        transpose_val_ret, CachedRegion, Cell, CellType,
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Returns `1` when `value == 0`, and returns `0` otherwise.
#[derive(Clone, Debug)]
pub struct IsZeroGadget<F> {
    inverse: Cell<F>,
    is_zero: Expression<F>,
}

impl<F: Field> IsZeroGadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        name: &str,
        value: Expression<F>,
    ) -> Self {
        let inverse = cb.query_cell_with_type(CellType::storage_for_expr(&value));

        let is_zero = 1.expr() - (value.clone() * inverse.expr());
        // when `value != 0` check `inverse = a.invert()`: value * (1 - value *
        // inverse)
        cb.add_constraint(
            Box::leak(
                format!("IsZeroGadget(\"{name}\"): value ⋅ (1 - value ⋅ value_inv)")
                    .into_boxed_str(),
            ),
            value * is_zero.clone(),
        );
        // when `value == 0` check `inverse = 0`: `inverse ⋅ (1 - value *
        // inverse)`
        cb.add_constraint(
            Box::leak(
                format!("IsZeroGadget(\"{name}\"): value_inv ⋅ (1 - value ⋅ value_inv)")
                    .into_boxed_str(),
            ),
            inverse.expr() * is_zero.clone(),
        );

        Self { inverse, is_zero }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.clone()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: F,
    ) -> Result<F, Error> {
        let inverse = value.invert().unwrap_or(F::zero());
        self.inverse.assign(region, offset, Value::known(inverse))?;
        Ok(if value.is_zero().into() {
            F::one()
        } else {
            F::zero()
        })
    }

    pub(crate) fn assign_value(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<Value<F>, Error> {
        transpose_val_ret(value.map(|value| self.assign(region, offset, value)))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        evm_circuit::util::{constraint_builder::ConstrainBuilderCommon, Cell},
        util::Expr,
    };

    use super::{super::test_util::*, *};

    use eth_types::{ToScalar, Word};
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// IsZeroGadgetTestContainer: require(n != 0)
    struct IsZeroGadgetTestContainer<F> {
        z_gadget: IsZeroGadget<F>,
        n: Cell<F>,
    }

    impl<F: Field> MathGadgetContainer<F> for IsZeroGadgetTestContainer<F> {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let n = cb.query_cell();
            let z_gadget = IsZeroGadget::<F>::construct(cb, "", n.expr());
            cb.require_equal("Input is zero", z_gadget.expr(), 1.expr());
            IsZeroGadgetTestContainer { z_gadget, n }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let n = witnesses[0].to_scalar().unwrap();
            let offset = 0;

            self.n.assign(region, offset, Value::known(n))?;
            self.z_gadget.assign(region, 0, n)?;

            Ok(())
        }
    }

    #[test]
    fn test_0_is_zero() {
        try_test!(IsZeroGadgetTestContainer<Fr>, vec![Word::from(0)], true);
    }

    #[test]
    fn test_1_is_not_zero() {
        try_test!(IsZeroGadgetTestContainer<Fr>, vec![Word::from(1)], false);
    }

    #[test]
    fn test_large_num_is_not_zero() {
        try_test!(
            IsZeroGadgetTestContainer<Fr>,
            vec![Word::from(10000)],
            false,
        );
    }
}
