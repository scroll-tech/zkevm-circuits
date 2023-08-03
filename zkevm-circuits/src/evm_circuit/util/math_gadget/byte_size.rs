use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            sum, CachedRegion, Cell,
        },
    },
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Gadget to verify the byte-size of a word, i.e. the minimum number of bytes
/// it takes to represent the word.
#[derive(Clone, Debug)]
pub(crate) struct ByteSizeGadgetN<F, const N: usize> {
    /// Array of indices from which only one will be turned on. The turned on
    /// index is the index of the most significant non-zero byte in value.
    most_significant_nonzero_byte_index: [Cell<F>; N],
    is_byte_size_zero: Cell<F>,
    /// The inverse of the most significant non-zero byte in value. The inverse
    /// should exist if the byte-size is non-zero.
    most_significant_nonzero_byte_inverse: Cell<F>,
    /// The most significant byte in this word.
    pub(crate) most_significant_byte: Expression<F>,
}

impl<F: Field, const N: usize> ByteSizeGadgetN<F, N> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, values: [Expression<F>; N]) -> Self {
        let most_significant_nonzero_byte_index = [(); N].map(|()| cb.query_bool());
        let is_byte_size_zero = cb.query_bool();
        cb.require_equal(
            "exactly one cell in indices is 1",
            sum::expr(&most_significant_nonzero_byte_index) + is_byte_size_zero.expr(),
            1.expr(),
        );

        let most_significant_nonzero_byte_inverse = cb.query_cell();
        for (i, index) in most_significant_nonzero_byte_index.iter().enumerate() {
            cb.condition(index.expr(), |cb| {
                cb.require_zero("more significant bytes are 0", sum::expr(&values[i + 1..N]));
                cb.require_equal(
                    "most significant nonzero byte's inverse exists",
                    values[i].expr() * most_significant_nonzero_byte_inverse.expr(),
                    1.expr(),
                );
            });
        }

        cb.condition(is_byte_size_zero.expr(), |cb| {
            cb.require_zero("all bytes are 0 when byte size is 0", sum::expr(&values));
            cb.require_zero(
                "byte size == 0",
                most_significant_nonzero_byte_inverse.expr(),
            );
        });

        let most_significant_byte = values
            .iter()
            .zip(most_significant_nonzero_byte_index.iter())
            .fold(0.expr(), |acc, (value, index)| {
                acc.expr() + (value.expr() * index.expr())
            });

        Self {
            most_significant_nonzero_byte_index,
            is_byte_size_zero,
            most_significant_nonzero_byte_inverse,
            most_significant_byte,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Word,
    ) -> Result<(), Error> {
        let byte_size = (value.bits() + 7) / 8;
        for (i, byte_index) in self.most_significant_nonzero_byte_index.iter().enumerate() {
            byte_index.assign(
                region,
                offset,
                Value::known(if i + 1 == byte_size {
                    F::one()
                } else {
                    F::zero()
                }),
            )?;
        }
        self.is_byte_size_zero.assign(
            region,
            offset,
            Value::known(if byte_size == 0 { F::one() } else { F::zero() }),
        )?;
        if byte_size > 0 {
            let most_significant_nonzero_byte = value.to_le_bytes()[byte_size - 1];
            self.most_significant_nonzero_byte_inverse.assign(
                region,
                offset,
                Value::known(
                    F::from(u64::try_from(most_significant_nonzero_byte).unwrap())
                        .invert()
                        .unwrap(),
                ),
            )?;
        } else {
            self.most_significant_nonzero_byte_inverse.assign(
                region,
                offset,
                Value::known(F::zero()),
            )?;
        }
        Ok(())
    }

    pub(crate) fn byte_size(&self) -> Expression<F> {
        sum::expr(
            self.most_significant_nonzero_byte_index
                .iter()
                .enumerate()
                .map(|(i, cell)| (i + 1).expr() * cell.expr()),
        )
    }
}

pub(crate) type ByteSizeGadget<F> = ByteSizeGadgetN<F, N_BYTES_WORD>;

#[cfg(test)]
mod tests {
    use super::{super::test_util::*, *};
    use crate::evm_circuit::util;
    use eth_types::Word;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// ByteSizeGadgetContainer: require(N = byte_size(a))
    struct ByteSizeGadgetContainerM<F, const N: u8, const TEST_MSB: bool = false> {
        bytesize_gadget: ByteSizeGadget<F>,
        a: util::Word<F>,
    }

    impl<F: Field, const N: u8, const TEST_MSB: bool> MathGadgetContainer<F>
        for ByteSizeGadgetContainerM<F, N, TEST_MSB>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let value_rlc = cb.query_word_rlc();
            let bytesize_gadget = ByteSizeGadget::<F>::construct(
                cb,
                value_rlc
                    .cells
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            );

            if TEST_MSB {
                cb.require_equal(
                    "check most significant byte",
                    bytesize_gadget.most_significant_byte.expr(),
                    N.expr(),
                );
            } else {
                cb.require_equal(
                    "byte size gadget must equal N",
                    bytesize_gadget.byte_size(),
                    N.expr(),
                );
            }

            Self {
                bytesize_gadget,
                a: value_rlc,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let offset = 0;
            let x = witnesses[0];
            self.a.assign(region, offset, Some(x.to_le_bytes()))?;
            self.bytesize_gadget.assign(region, offset, x)?;

            Ok(())
        }
    }

    type ByteSizeGadgetContainer<F, const N: u8> = ByteSizeGadgetContainerM<F, N>;
    type WordMSBGadgetContainer<F, const N: u8> = ByteSizeGadgetContainerM<F, N, true>;

    #[test]
    fn test_bytesize_0() {
        try_test!(ByteSizeGadgetContainer<Fr, 0>, vec![Word::from(0)], true)
    }

    #[test]
    fn test_bytesize_1() {
        try_test!(ByteSizeGadgetContainer<Fr, 1>, vec![Word::from(1)], true)
    }

    #[test]
    fn test_bytesize_1_neq_0() {
        try_test!(ByteSizeGadgetContainer<Fr, 0>,
            vec![Word::from(1)],
            false
        );
    }

    #[test]
    fn test_bytesize_256_eq_2() {
        try_test!(ByteSizeGadgetContainer<Fr, 2>,
            vec![Word::from(256)],
            true
        );
    }

    #[test]
    fn test_bytesize_wordmax_eq_32() {
        try_test!(ByteSizeGadgetContainer<Fr, 32>, vec![Word::MAX], true)
    }

    #[test]
    fn test_bytesize_msb_0() {
        try_test!(WordMSBGadgetContainer<Fr, 0>, vec![Word::from(0)], true)
    }

    #[test]
    fn test_bytesize_msb_1() {
        try_test!(WordMSBGadgetContainer<Fr, 1>, vec![Word::from(1)], true)
    }

    #[test]
    fn test_bytesize_1_msb_neq_0() {
        try_test!(WordMSBGadgetContainer<Fr, 0>,
            vec![Word::from(1)],
            false
        );
    }

    #[test]
    fn test_bytesize_512_msb_eq_2() {
        try_test!(WordMSBGadgetContainer<Fr, 2>,
            vec![Word::from(512)],
            true
        );
    }

    #[test]
    fn test_bytesize_258_msb_neq_2() {
        try_test!(ByteSizeGadgetContainer<Fr, 2>, vec![Word::from(258)], true)
    }
}
