use crate::{
    evm_circuit::{
        param::{N_BITS_U8, N_BYTES_WORD},
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

pub(crate) enum ByteOrWord {
    Byte(u8),
    Word(Word),
}

impl ByteOrWord {
    fn get_byte(&self) -> u8 {
        if let Self::Byte(val) = &self {
            *val
        } else {
            unreachable!("get_byte called on a word");
        }
    }

    fn get_word(&self) -> Word {
        if let Self::Word(val) = &self {
            *val
        } else {
            unreachable!("get_word called on a byte");
        }
    }
}

/// Gadget to verify the byte-size of a word, i.e. the minimum number of bytes
/// it takes to represent the word.
#[derive(Clone, Debug)]
pub(crate) struct ByteOrBitSizeGadget<F, const N: usize, const IS_BYTE: bool> {
    /// Array of indices from which only one will be turned on. The turned on
    /// index is the index of the most significant non-zero byte/bit in value.
    most_significant_nonzero_value_index: [Cell<F>; N],
    /// True if the byte size or bit length of the value is zero, i.e. the value itself is zero.
    is_size_zero: Cell<F>,
    /// The inverse of the most significant non-zero byte/bit in value. The inverse
    /// should exist if the size is non-zero.
    most_significant_nonzero_value_inverse: Cell<F>,
    /// The most significant byte/bit.
    pub(crate) most_significant_value: Expression<F>,
}

impl<F: Field, const N: usize, const IS_BYTE: bool> ByteOrBitSizeGadget<F, N, IS_BYTE> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, values: [Expression<F>; N]) -> Self {
        let most_significant_nonzero_value_index = [(); N].map(|()| cb.query_bool());
        let is_size_zero = cb.query_bool();
        cb.require_equal(
            "There is exactly one msb, or the value itself is zero",
            sum::expr(&most_significant_nonzero_value_index) + is_size_zero.expr(),
            1.expr(),
        );

        let most_significant_nonzero_value_inverse = cb.query_cell();
        for (i, index) in most_significant_nonzero_value_index.iter().enumerate() {
            cb.condition(index.expr(), |cb| {
                if IS_BYTE {
                    cb.require_zero(
                        "more significant bytes/bits are 0 IS_BYTE=true",
                        sum::expr(&values[i + 1..N]),
                    );
                } else {
                    cb.require_zero(
                        "more significant bytes/bits are 0 IS_BYTE=false",
                        sum::expr(&values[i + 1..N]),
                    );
                }
                if IS_BYTE {
                    cb.require_equal(
                        "most significant nonzero byte/bit's inverse exists IS_BYTE=true",
                        values[i].expr() * most_significant_nonzero_value_inverse.expr(),
                        1.expr(),
                    );
                } else {
                    cb.require_equal(
                        "most significant nonzero byte/bit's inverse exists IS_BYTE=false",
                        values[i].expr() * most_significant_nonzero_value_inverse.expr(),
                        1.expr(),
                    );
                }
            });
        }

        cb.condition(is_size_zero.expr(), |cb| {
            cb.require_zero("all bytes are 0 when value itself is 0", sum::expr(&values));
            cb.require_zero(
                "byte size/bit length == 0",
                most_significant_nonzero_value_inverse.expr(),
            );
        });

        let most_significant_value = values
            .iter()
            .zip(most_significant_nonzero_value_index.iter())
            .fold(0.expr(), |acc, (value, index)| {
                acc.expr() + (value.expr() * index.expr())
            });

        Self {
            most_significant_nonzero_value_index,
            is_size_zero,
            most_significant_nonzero_value_inverse,
            most_significant_value,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: ByteOrWord,
    ) -> Result<(), Error> {
        // get the byte size or bit length of the value.
        let size = if IS_BYTE {
            (value.get_word().bits() + 7) / 8
        } else {
            N_BITS_U8 - (value.get_byte().leading_zeros() as usize)
        };

        for (i, byte_index) in self.most_significant_nonzero_value_index.iter().enumerate() {
            byte_index.assign(
                region,
                offset,
                Value::known(if i + 1 == size { F::one() } else { F::zero() }),
            )?;
        }
        self.is_size_zero.assign(
            region,
            offset,
            Value::known(if size == 0 { F::one() } else { F::zero() }),
        )?;
        if size > 0 {
            let most_significant_nonzero_value = if IS_BYTE {
                value.get_word().to_le_bytes()[size - 1]
            } else {
                let byte = value.get_byte();
                let mask = 1 << (size - 1);
                ((mask & byte) > 0) as u8
            };
            self.most_significant_nonzero_value_inverse.assign(
                region,
                offset,
                Value::known(
                    F::from(u64::from(most_significant_nonzero_value))
                        .invert()
                        .unwrap(),
                ),
            )?;
        } else {
            self.most_significant_nonzero_value_inverse.assign(
                region,
                offset,
                Value::known(F::zero()),
            )?;
        }
        Ok(())
    }

    /// Get the byte size or bit length of the value.
    pub(crate) fn size(&self) -> Expression<F> {
        sum::expr(
            self.most_significant_nonzero_value_index
                .iter()
                .enumerate()
                .map(|(i, cell)| (i + 1).expr() * cell.expr()),
        )
    }
}

pub(crate) type ByteSizeGadget<F> = ByteOrBitSizeGadget<F, N_BYTES_WORD, true>;
pub(crate) type BitLengthGadget<F> = ByteOrBitSizeGadget<F, N_BITS_U8, false>;

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
                    bytesize_gadget.most_significant_value.expr(),
                    N.expr(),
                );
            } else {
                cb.require_equal(
                    "byte size gadget must equal N",
                    bytesize_gadget.size(),
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
            self.bytesize_gadget
                .assign(region, offset, ByteOrWord::Word(x))?;

            Ok(())
        }
    }

    type ByteSizeGadgetContainer<F, const N: u8> = ByteSizeGadgetContainerM<F, N>;
    type WordMSBGadgetContainer<F, const N: u8> = ByteSizeGadgetContainerM<F, N, true>;

    #[test]
    fn test_bytesize_0() {
        try_test!(ByteSizeGadgetContainer<Fr, 0>, [Word::from(0)], true)
    }

    #[test]
    fn test_bytesize_1() {
        try_test!(ByteSizeGadgetContainer<Fr, 1>, [Word::from(1)], true)
    }

    #[test]
    fn test_bytesize_1_neq_0() {
        try_test!(ByteSizeGadgetContainer<Fr, 0>,
            [Word::from(1)],
            false
        );
    }

    #[test]
    fn test_bytesize_256_eq_2() {
        try_test!(ByteSizeGadgetContainer<Fr, 2>,
            [Word::from(256)],
            true
        );
    }

    #[test]
    fn test_bytesize_wordmax_eq_32() {
        try_test!(ByteSizeGadgetContainer<Fr, 32>, [Word::MAX], true)
    }

    #[test]
    fn test_bytesize_msb_0() {
        try_test!(WordMSBGadgetContainer<Fr, 0>, [Word::from(0)], true)
    }

    #[test]
    fn test_bytesize_msb_1() {
        try_test!(WordMSBGadgetContainer<Fr, 1>, [Word::from(1)], true)
    }

    #[test]
    fn test_bytesize_1_msb_neq_0() {
        try_test!(WordMSBGadgetContainer<Fr, 0>,
            [Word::from(1)],
            false
        );
    }

    #[test]
    fn test_bytesize_512_msb_eq_2() {
        try_test!(WordMSBGadgetContainer<Fr, 2>,
            [Word::from(512)],
            true
        );
    }

    #[test]
    fn test_bytesize_258_msb_neq_2() {
        try_test!(ByteSizeGadgetContainer<Fr, 2>, [Word::from(258)], true)
    }
}
