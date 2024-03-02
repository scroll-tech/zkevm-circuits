use crate::{
    evm_circuit::{
        param::MAX_N_BYTES_INTEGER,
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::*,
            transpose_val_ret, CachedRegion, Cell, CellType,
        },
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
/// Returns (quotient: numerator/denominator, remainder: numerator%denominator),
/// with `numerator` an expression and `denominator` a constant.
/// Input requirements:
/// - `quotient < 256**N_BYTES`
/// - `quotient * denominator < field size`
/// - `remainder < denominator` requires a range lookup table for `denominator`
#[derive(Clone, Debug)]
pub struct ConstantDivisionGadget<F, const N_BYTES: usize> {
    quotient: Cell<F>,
    remainder: Cell<F>,
    denominator: u64,
    quotient_range_check: RangeCheckGadget<F, N_BYTES>,
}

impl<F: Field, const N_BYTES: usize> ConstantDivisionGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        numerator: Expression<F>,
        denominator: u64,
    ) -> Self {
        assert!(N_BYTES * 8 + 64 - denominator.leading_zeros() as usize <= MAX_N_BYTES_INTEGER * 8);
        let quotient = cb.query_cell_with_type(CellType::storage_for_expr(&numerator));
        let remainder = cb.query_cell_with_type(CellType::storage_for_expr(&numerator));

        // Require that remainder < denominator
        cb.range_lookup(remainder.expr(), denominator);

        // Require that quotient < 256**N_BYTES
        // so we can't have any overflow when doing `quotient * denominator`.
        let quotient_range_check = RangeCheckGadget::construct(cb, quotient.expr());

        // Check if the division was done correctly
        cb.require_equal(
            "numerator - remainder == quotient ⋅ denominator",
            numerator - remainder.expr(),
            quotient.expr() * denominator.expr(),
        );

        Self {
            quotient,
            remainder,
            denominator,
            quotient_range_check,
        }
    }

    pub(crate) fn quotient(&self) -> Expression<F> {
        self.quotient.expr()
    }

    pub(crate) fn remainder(&self) -> Expression<F> {
        self.remainder.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        numerator: u128,
    ) -> Result<(u128, u128), Error> {
        let denominator = self.denominator as u128;
        let quotient = numerator / denominator;
        let remainder = numerator % denominator;

        self.quotient
            .assign(region, offset, Value::known(F::from_u128(quotient)))?;
        self.remainder
            .assign(region, offset, Value::known(F::from_u128(remainder)))?;

        self.quotient_range_check
            .assign(region, offset, F::from_u128(quotient))?;

        Ok((quotient, remainder))
    }

    pub(crate) fn assign_value(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        numerator: Value<F>,
    ) -> Result<Value<(u128, u128)>, Error> {
        transpose_val_ret(
            numerator.map(|numerator| self.assign(region, offset, numerator.get_lower_128())),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{test_util::*, *};
    use eth_types::*;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// ConstantDivisionTestContainer:
    /// require(a(N_BYTES) == DENOMINATOR * QUOTIENT + REMAINDER)
    struct ConstantDivisionTestContainer<
        F,
        const N_BYTES: usize,
        const DENOMINATOR: u64,
        const QUOTIENT: u64,
        const REMINDER: u64,
    > {
        constdiv_gadget: ConstantDivisionGadget<F, N_BYTES>,
        a: Cell<F>,
    }

    impl<
            F: Field,
            const N_BYTES: usize,
            const DENOMINATOR: u64,
            const QUOTIENT: u64,
            const REMAINDER: u64,
        > MathGadgetContainer<F>
        for ConstantDivisionTestContainer<F, N_BYTES, DENOMINATOR, QUOTIENT, REMAINDER>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let a = cb.query_cell();
            let constdiv_gadget =
                ConstantDivisionGadget::<F, N_BYTES>::construct(cb, a.expr(), DENOMINATOR);

            cb.require_equal(
                "correct reminder",
                constdiv_gadget.remainder(),
                REMAINDER.expr(),
            );

            cb.require_equal(
                "correct quotient",
                constdiv_gadget.quotient(),
                QUOTIENT.expr(),
            );

            ConstantDivisionTestContainer { constdiv_gadget, a }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let a = u64::from_le_bytes(witnesses[0].to_le_bytes()[..8].try_into().unwrap());
            let offset = 0;

            self.a.assign(region, offset, Value::known(F::from(a)))?;
            self.constdiv_gadget.assign(region, offset, a as u128)?;

            Ok(())
        }
    }

    #[test]
    fn test_constantdivisiongadget_0div5_rem0() {
        try_test!(
            ConstantDivisionTestContainer<Fr, 4, 5, 0, 0>,
            [Word::from(0)],
            true,
        );
    }

    #[test]
    fn test_constantdivisiongadget_5div5_rem0() {
        try_test!(
            ConstantDivisionTestContainer<Fr, 4, 5, 1, 0>,
            [Word::from(5)],
            true,
        );
    }

    #[test]
    fn test_constantdivisiongadget_1div5_rem1() {
        try_test!(
            ConstantDivisionTestContainer<Fr, 4, 5, 0, 1>,
            [Word::from(1)],
            true,
        );
    }

    #[test]
    fn test_constantdivisiongadget_1div5_rem4() {
        try_test!(
            ConstantDivisionTestContainer<Fr, 4, 5, 1, 4>,
            [Word::from(1)],
            false,
        );
    }

    #[test]
    fn test_constantdivisiongadget_quotient_overflow() {
        try_test!(
            ConstantDivisionTestContainer<Fr, 4, 5, 4294967296u64, 1>,
            [Word::from(1u64 << (4 * 8)) * 5 + 1],
            false,
        );
    }

    #[test]
    fn test_constantdivisiongadget_33_div16_rem17() {
        try_test!(
            ConstantDivisionTestContainer<Fr, 4, 16, 1, 17>,
            [Word::from(33)],
            false,
        );
    }
}
