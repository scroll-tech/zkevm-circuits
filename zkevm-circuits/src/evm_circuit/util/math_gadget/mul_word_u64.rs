use crate::{
    evm_circuit::util::{
        self,
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        from_bytes, pow_of_two_expr, split_u256, CachedRegion,
    },
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Construction of 256-bit product by 256-bit multiplicand * 64-bit multiplier,
/// which disallows overflow.
#[derive(Clone, Debug)]
pub(crate) struct MulWordByU64Gadget<F> {
    multiplicand: util::Word<F>,
    product: util::Word<F>,
    carry_lo: [util::Cell<F>; 8],
}

impl<F: Field> MulWordByU64Gadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        multiplicand: util::Word<F>,
        multiplier: Expression<F>,
    ) -> Self {
        let gadget = Self {
            multiplicand,
            product: cb.query_word_rlc(),
            carry_lo: cb.query_bytes(),
        };

        let multiplicand_lo = from_bytes::expr(&gadget.multiplicand.cells[..16]);
        let multiplicand_hi = from_bytes::expr(&gadget.multiplicand.cells[16..]);

        let product_lo = from_bytes::expr(&gadget.product.cells[..16]);
        let product_hi = from_bytes::expr(&gadget.product.cells[16..]);

        let carry_lo = from_bytes::expr(&gadget.carry_lo[..8]);

        cb.require_equal(
            "multiplicand_lo ⋅ multiplier == carry_lo ⋅ 2^128 + product_lo",
            multiplicand_lo * multiplier.expr(),
            carry_lo.clone() * pow_of_two_expr(128) + product_lo,
        );

        cb.require_equal(
            "multiplicand_hi ⋅ multiplier + carry_lo == product_hi",
            multiplicand_hi * multiplier.expr() + carry_lo,
            product_hi,
        );

        gadget
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        multiplicand: Word,
        multiplier: u64,
        product: Word,
    ) -> Result<(), Error> {
        self.multiplicand
            .assign(region, offset, Some(multiplicand.to_le_bytes()))?;
        self.product
            .assign(region, offset, Some(product.to_le_bytes()))?;

        let (multiplicand_lo, _) = split_u256(&multiplicand);
        let (product_lo, _) = split_u256(&product);

        let carry_lo = (multiplicand_lo * multiplier - product_lo) >> 128;
        for (cell, byte) in self.carry_lo.iter().zip(
            u64::try_from(carry_lo)
                .map_err(|_| Error::Synthesis)?
                .to_le_bytes()
                .iter(),
        ) {
            cell.assign(region, offset, Value::known(F::from(*byte as u64)))?;
        }

        Ok(())
    }

    pub(crate) fn product(&self) -> &util::Word<F> {
        &self.product
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_util::*, *};
    use crate::evm_circuit::util::Cell;
    use eth_types::Word;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// MulWordByU64TestContainer: require(product = a*(b as u64))
    struct MulWordByU64TestContainer<F> {
        mulwords_u64_gadget: MulWordByU64Gadget<F>,
        a: util::Word<F>,
        b: Cell<F>,
        product: util::Word<F>,
    }

    impl<F: Field> MathGadgetContainer<F> for MulWordByU64TestContainer<F> {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let a = cb.query_word_rlc();
            let b = cb.query_cell();
            let product = cb.query_word_rlc();
            let mulwords_u64_gadget = MulWordByU64Gadget::<F>::construct(cb, a.clone(), b.expr());
            MulWordByU64TestContainer {
                mulwords_u64_gadget,
                a,
                b,
                product,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let a = witnesses[0];
            let b = u64::from_le_bytes(witnesses[1].to_le_bytes()[..8].try_into().unwrap());
            let product = witnesses[2];
            let offset = 0;

            self.a.assign(region, offset, Some(a.to_le_bytes()))?;
            self.b.assign(region, offset, Value::known(F::from(b)))?;
            self.product
                .assign(region, offset, Some(product.to_le_bytes()))?;
            self.mulwords_u64_gadget.assign(region, 0, a, b, product)?;

            Ok(())
        }
    }

    #[test]
    fn test_mulwordu64_expect() {
        // 0 * 0 = 0
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [Word::from(0), Word::from(0), Word::from(0)],
            true,
        );
        // max * 0 = 0
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [Word::MAX, Word::from(0), Word::from(0)],
            true,
        );
        // 1 * 1 = 1
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [Word::from(1), Word::from(1), Word::from(1)],
            true,
        );
        // max * 1 = max
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [Word::MAX, Word::from(1), Word::MAX],
            true,
        );
        // 2 * 2 = 4
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [Word::from(2), Word::from(2), Word::from(4)],
            true,
        );
        // 22222 * 500 = 11111000
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [Word::from(22222), Word::from(500), Word::from(11111000)],
            true,
        );
        // low_max * 2 = low_max << 1
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [WORD_LOW_MAX, Word::from(2), WORD_LOW_MAX << 1],
            true,
        );
    }

    #[test]
    fn test_mulwordu64_unexpect() {
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [Word::MAX, Word::from(1), Word::from(1)],
            false,
        );
        // high_max * 2 = overflow
        try_test!(
            MulWordByU64TestContainer<Fr>,
            [WORD_HIGH_MAX, Word::from(2), WORD_HIGH_MAX << 1],
            false,
        );
    }
}
