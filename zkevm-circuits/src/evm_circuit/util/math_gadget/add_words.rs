use crate::{
    evm_circuit::util::{
        self,
        constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
        from_bytes, pow_of_two_expr, split_u256, sum, CachedRegion, Cell,
    },
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, ToScalar, Word};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Construction of 2 256-bit words addition and result, which is useful for
/// opcode ADD, SUB and balance operation
#[derive(Clone, Debug)]
pub(crate) struct AddWordsGadget<F, const N_ADDENDS: usize, const CHECK_OVERFLOW: bool> {
    addends: [util::Word<F>; N_ADDENDS],
    sum: util::Word<F>,
    carry_lo: Cell<F>,
    carry_hi: Option<Cell<F>>,
}

impl<F: Field, const N_ADDENDS: usize, const CHECK_OVERFLOW: bool>
    AddWordsGadget<F, N_ADDENDS, CHECK_OVERFLOW>
{
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        addends: [util::Word<F>; N_ADDENDS],
        sum: util::Word<F>,
    ) -> Self {
        let carry_lo = cb.query_cell();
        let carry_hi = if CHECK_OVERFLOW {
            None
        } else {
            Some(cb.query_cell())
        };

        let addends_lo = &addends
            .iter()
            .map(|addend| from_bytes::expr(&addend.cells[..16]))
            .collect::<Vec<_>>();
        let addends_hi = &addends
            .iter()
            .map(|addend| from_bytes::expr(&addend.cells[16..]))
            .collect::<Vec<_>>();
        let sum_lo = from_bytes::expr(&sum.cells[..16]);
        let sum_hi = from_bytes::expr(&sum.cells[16..]);

        cb.require_equal(
            "sum(addends_lo) == sum_lo + carry_lo ⋅ 2^128",
            sum::expr(addends_lo),
            sum_lo + carry_lo.expr() * pow_of_two_expr(128),
        );
        cb.require_equal(
            if CHECK_OVERFLOW {
                "sum(addends_hi) + carry_lo == sum_hi"
            } else {
                "sum(addends_hi) + carry_lo == sum_hi + carry_hi ⋅ 2^128"
            },
            sum::expr(addends_hi) + carry_lo.expr(),
            if CHECK_OVERFLOW {
                sum_hi
            } else {
                sum_hi + carry_hi.as_ref().unwrap().expr() * pow_of_two_expr(128)
            },
        );

        for carry in if CHECK_OVERFLOW {
            vec![&carry_lo]
        } else {
            vec![&carry_lo, carry_hi.as_ref().unwrap()]
        } {
            cb.require_in_set(
                "carry_lo in 0..N_ADDENDS",
                carry.expr(),
                (0..N_ADDENDS).map(|idx| idx.expr()).collect(),
            );
        }

        Self {
            addends,
            sum,
            carry_lo,
            carry_hi,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        addends: [Word; N_ADDENDS],
        sum: Word,
    ) -> Result<(), Error> {
        for (word, value) in self.addends.iter().zip(addends.iter()) {
            word.assign(region, offset, Some(value.to_le_bytes()))?;
        }
        self.sum.assign(region, offset, Some(sum.to_le_bytes()))?;

        let (addends_lo, addends_hi): (Vec<_>, Vec<_>) = addends.iter().map(split_u256).unzip();
        let (sum_lo, sum_hi) = split_u256(&sum);

        let sum_of_addends_lo = addends_lo
            .into_iter()
            .fold(Word::zero(), |acc, addend_lo| acc + addend_lo);
        let sum_of_addends_hi = addends_hi
            .into_iter()
            .fold(Word::zero(), |acc, addend_hi| acc + addend_hi);

        let carry_lo = (sum_of_addends_lo - sum_lo) >> 128;
        self.carry_lo.assign(
            region,
            offset,
            Value::known(
                carry_lo
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        if !CHECK_OVERFLOW {
            let carry_hi = (sum_of_addends_hi + carry_lo - sum_hi) >> 128;
            self.carry_hi.as_ref().unwrap().assign(
                region,
                offset,
                Value::known(
                    carry_hi
                        .to_scalar()
                        .expect("unexpected U256 -> Scalar conversion failure"),
                ),
            )?;
        }

        Ok(())
    }

    pub(crate) fn addends(&self) -> &[util::Word<F>] {
        &self.addends
    }

    pub(crate) fn sum(&self) -> &util::Word<F> {
        &self.sum
    }

    pub(crate) fn carry(&self) -> &Option<util::Cell<F>> {
        &self.carry_hi
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_util::*, *};
    use eth_types::{Word, U256};
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    #[derive(Clone)]
    /// AddWordsTestContainer: require(sum = sum(addends))
    struct AddWordsTestContainer<
        F,
        const N_ADDENDS: usize,
        const CARRY_HI: u64,
        const CHECK_OVERFLOW: bool,
    > {
        addwords_gadget: AddWordsGadget<F, N_ADDENDS, CHECK_OVERFLOW>,
        addends: [util::Word<F>; N_ADDENDS],
        sum: util::Word<F>,
    }

    impl<F: Field, const N_ADDENDS: usize, const CARRY_HI: u64, const CHECK_OVERFLOW: bool>
        MathGadgetContainer<F> for AddWordsTestContainer<F, N_ADDENDS, CARRY_HI, CHECK_OVERFLOW>
    {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let addends = [(); N_ADDENDS].map(|_| cb.query_word_rlc());
            let sum = cb.query_word_rlc();
            let addwords_gadget = AddWordsGadget::<F, N_ADDENDS, CHECK_OVERFLOW>::construct(
                cb,
                addends.clone(),
                sum.clone(),
            );

            assert_eq!(addwords_gadget.addends().len(), N_ADDENDS);
            if !CHECK_OVERFLOW {
                let carry_hi = addwords_gadget.carry().as_ref().unwrap();
                cb.require_equal("carry_hi is correct", carry_hi.expr(), CARRY_HI.expr())
            } else {
                assert!(addwords_gadget.carry().is_none());
            }

            AddWordsTestContainer {
                addwords_gadget,
                addends,
                sum,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            assert_eq!(N_ADDENDS, witnesses.len() - 1);
            let offset = 0;
            for (i, addend) in self.addends.iter().enumerate() {
                let a = witnesses[i];
                addend.assign(region, offset, Some(a.to_le_bytes()))?;
            }
            let sum = witnesses[N_ADDENDS];
            self.sum.assign(region, offset, Some(sum.to_le_bytes()))?;

            let addends = witnesses[0..N_ADDENDS].try_into().unwrap();
            self.addwords_gadget.assign(region, 0, addends, sum)?;

            Ok(())
        }
    }

    #[test]
    fn test_addwords_0_0() {
        try_test!(AddWordsTestContainer<Fr, 2, 0u64, true>, [Word::from(0), Word::from(0), Word::from(0)], true);
    }

    #[test]
    fn test_addwords_1_1() {
        try_test!(AddWordsTestContainer<Fr, 2, 0u64, true>, [Word::from(1), Word::from(1), Word::from(2)], true);
    }

    #[test]
    fn test_addwords_1000_1000() {
        try_test!(AddWordsTestContainer<Fr, 2, 0u64, true>, [Word::from(1000), Word::from(1000), Word::from(2000)], true);
    }

    #[test]
    fn test_addwords_to_wordmax() {
        try_test!(AddWordsTestContainer<Fr, 2,0u64, true>, [Word::MAX - 1, Word::from(1), Word::MAX], true);
    }

    #[test]
    fn test_addwords_high_low_max() {
        try_test!(AddWordsTestContainer<Fr, 2, 0u64, true>, [WORD_LOW_MAX, WORD_HIGH_MAX, Word::MAX], true);
    }

    #[test]
    fn test_addwords_overflow() {
        try_test!(AddWordsTestContainer<Fr, 2, 0u64, true>, [Word::MAX, Word::from(1),  Word::from(0)], false);
    }

    #[test]
    fn test_addwords_wrong_sum0() {
        try_test!(AddWordsTestContainer<Fr, 2, 0u64, true>, [Word::from(1), Word::from(0),  Word::from(0)], false);
    }

    #[test]
    fn test_addwords_wrong_sum2() {
        try_test!(AddWordsTestContainer<Fr, 2, 0u64, true>, [Word::from(2), Word::from(1),  Word::from(2)], false);
    }

    #[test]
    fn test_addwords_no_overflow_check() {
        try_test!(AddWordsTestContainer<Fr, 2, 1u64, false,>, [Word::MAX, Word::from(1),  Word::from(0)], true);
    }

    #[test]
    fn test_addwords_incorrect_carry_check() {
        try_test!(AddWordsTestContainer<Fr, 2, 0u64, false,>, [Word::MAX, Word::from(1),  Word::from(0)], false);
    }

    #[test]
    fn test_addwords_3_addends() {
        try_test!(AddWordsTestContainer<Fr, 3, 0u64, false,>, [Word::from(0), Word::from(1), Word::from(0),  Word::from(1)], true);
    }

    #[test]
    fn test_addwords_3_addends_with_overflow_check() {
        try_test!(AddWordsTestContainer<Fr, 3, 0u64, true>, [Word::MAX, Word::from(1), Word::from(0),  Word::from(0)], false);
    }

    #[test]
    fn test_addwords_3_addends_with_carry() {
        const CARRY_HI: u64 = 1u64;
        try_test!(AddWordsTestContainer<Fr, 3, CARRY_HI, false,>, [Word::MAX, Word::from(1), WORD_HIGH_MAX,  WORD_HIGH_MAX], true);
    }

    #[test]
    fn test_addwords_7_addends_with_carry() {
        const CARRY_HI: u64 = 6u64;
        let sum_7_low_max = U256([0xfffffffffffffff9u64, 0xffffffffffffffffu64, CARRY_HI, 0u64]);
        try_test!(
            AddWordsTestContainer<Fr,7, 0u64, true>,
            vec![
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                WORD_LOW_MAX,
                sum_7_low_max],
            true
        );
    }
}
