use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        util::{constraint_builder::ConstraintBuilder, sum, CachedRegion, Cell},
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
pub(crate) struct ByteSizeGadget<F> {
    /// Array of indices from which only one will be turned on. The turned on
    /// index is the index of the most significant non-zero byte in value.
    most_significant_nonzero_byte_index: [Cell<F>; N_BYTES_WORD + 1],
    /// The inverse of the most significant non-zero byte in value. The inverse
    /// should exist if the byte-size is non-zero.
    most_significant_nonzero_byte_inverse: Cell<F>,
}

impl<F: Field> ByteSizeGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        values: [Expression<F>; N_BYTES_WORD],
    ) -> Self {
        let most_significant_nonzero_byte_index = [(); N_BYTES_WORD + 1].map(|()| cb.query_bool());
        cb.require_equal(
            "exactly one cell in indices is 1",
            sum::expr(&most_significant_nonzero_byte_index),
            1.expr(),
        );

        let most_significant_nonzero_byte_inverse = cb.query_cell();
        for (i, index) in most_significant_nonzero_byte_index.iter().enumerate() {
            cb.condition(index.expr(), |cb| {
                cb.require_zero(
                    "more significant bytes are 0",
                    sum::expr(&values[i..N_BYTES_WORD]),
                );
                if i > 0 {
                    cb.require_equal(
                        "most significant nonzero byte's inverse exists",
                        values[i - 1].expr() * most_significant_nonzero_byte_inverse.expr(),
                        1.expr(),
                    )
                } else {
                    cb.require_zero(
                        "byte size == 0",
                        most_significant_nonzero_byte_inverse.expr(),
                    );
                }
            });
        }

        Self {
            most_significant_nonzero_byte_index,
            most_significant_nonzero_byte_inverse,
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
                Value::known(if i == byte_size { F::one() } else { F::zero() }),
            )?;
        }
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
                .map(|(i, cell)| i.expr() * cell.expr()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::*;
    use super::*;
    use crate::evm_circuit::util;
    use eth_types::Word;
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::Error;

    #[derive(Clone)]
    /// ByteSizeGadgetContainer: require(N = byte_size(a))
    struct ByteSizeGadgetContainer<F, const N: u8> {
        bytesize_gadget: ByteSizeGadget<F>,
        a: util::Word<F>,
    }

    impl<F: Field, const N: u8> MathGadgetContainer<F> for ByteSizeGadgetContainer<F, N> {
        fn configure_gadget_container(cb: &mut ConstraintBuilder<F>) -> Self {
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
            cb.require_equal(
                "byte size gadget must equal N",
                bytesize_gadget.byte_size(),
                N.expr(),
            );
            ByteSizeGadgetContainer {
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
}
