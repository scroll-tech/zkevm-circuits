use crate::{
    evm_circuit::util::{
        constraint_builder::ConstraintBuilder, transpose_val_ret, CachedRegion, Cell, CellType,
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub struct BatchedIsZeroGadget<F, const N: usize> {
    is_zero: Cell<F>,
    nonempty_witness: Cell<F>,
}

impl<F: Field, const N: usize> BatchedIsZeroGadget<F, N> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, values: [Expression<F>; N]) -> Self {
        let max_values_phase = values
            .iter()
            .map(CellType::expr_phase)
            .max()
            .expect("BatchedIsZeroGadget needs at least one expression");

        let cell_type = CellType::storage_for_phase::<F>(max_values_phase);
        let is_zero = cb.query_bool_with_type(cell_type);
        let nonempty_witness = cb.query_cell_with_type(cell_type);

        for value in values.iter() {
            cb.require_zero(
                "is_zero is 0 if there is any non-zero value",
                is_zero.expr() * value.clone(),
            );
        }

        cb.require_zero(
            "is_zero is 1 if values are all zero",
            values.iter().fold(1.expr() - is_zero.expr(), |acc, value| {
                acc * (1.expr() - value.expr() * nonempty_witness.clone().expr())
            }),
        );

        Self {
            is_zero,
            nonempty_witness,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.is_zero.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        values: [F; N],
    ) -> Result<F, Error> {
        let is_zero =
            if let Some(inverse) = values.iter().find_map(|value| Option::from(value.invert())) {
                self.nonempty_witness
                    .assign(region, offset, Value::known(inverse))?;
                F::zero()
            } else {
                F::one()
            };
        self.is_zero.assign(region, offset, Value::known(is_zero))?;

        Ok(is_zero)
    }

    pub(crate) fn assign_value(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        values: [Value<F>; N],
    ) -> Result<Value<F>, Error> {
        let values: Value<[F; N]> =
            Value::<Vec<F>>::from_iter(values).map(|vv| vv.try_into().unwrap());
        transpose_val_ret(values.map(|values| self.assign(region, offset, values)))
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_util::*, *};
    use eth_types::*;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// IsZeroGadgetTestContainer: require(all(cells) == 0)
    struct IsZeroGadgetTestContainer<F, const N: usize> {
        z_gadget: BatchedIsZeroGadget<F, N>,
        nums: [Cell<F>; N],
    }

    impl<F: Field, const N: usize> MathGadgetContainer<F> for IsZeroGadgetTestContainer<F, N> {
        fn configure_gadget_container(cb: &mut ConstraintBuilder<F>) -> Self {
            let nums = [(); N].map(|_| cb.query_cell());
            let z_gadget = BatchedIsZeroGadget::<F, N>::construct(
                cb,
                nums.iter()
                    .map(|cell| cell.expr())
                    .collect::<Vec<Expression<F>>>()
                    .try_into()
                    .unwrap(),
            );
            cb.require_equal("Input must be all 0", z_gadget.expr(), 1.expr());
            IsZeroGadgetTestContainer { z_gadget, nums }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let values = witnesses
                .iter()
                .map(|num| num.to_scalar().unwrap())
                .collect::<Vec<F>>();
            let offset = 0;

            for (i, num) in self.nums.iter().enumerate() {
                num.assign(region, offset, Value::known(values[i]))?;
            }
            self.z_gadget
                .assign(region, offset, values.try_into().unwrap())?;

            Ok(())
        }
    }

    #[test]
    fn test_batched_iszero() {
        try_test!(IsZeroGadgetTestContainer<Fr, 5>, [Word::from(0); 5], true);
    }

    #[test]
    fn test_batched_1_in_array_not_iszero() {
        try_test!(
            IsZeroGadgetTestContainer<Fr, 5>,
            vec![
                Word::from(0),
                Word::from(1),
                Word::from(0),
                Word::from(0),
                Word::from(0),
            ],
            false
        );
    }

    #[test]
    fn test_batched_big_array_not_iszero() {
        let mut test_nums = vec![Word::from(1)];
        test_nums.extend(vec![Word::from(0); 31]);
        try_test!(IsZeroGadgetTestContainer<Fr, 32>, test_nums, false);
    }

    #[test]
    fn test_batched_single_cell_iszero() {
        try_test!(IsZeroGadgetTestContainer<Fr, 1>, [Word::from(0)], true);
    }

    #[test]
    fn test_batched_single_cell_not_iszero() {
        try_test!(IsZeroGadgetTestContainer<Fr, 1>, vec![WORD_LOW_MAX], false);
    }

    #[test]
    fn test_batched_wordmax_bytes_not_iszero() {
        try_test!(
            IsZeroGadgetTestContainer<Fr, 5>,
            vec![
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                WORD_LOW_MAX,
            ],
            false
        );
    }
}
