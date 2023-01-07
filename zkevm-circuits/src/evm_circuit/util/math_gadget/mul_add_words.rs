use crate::{
    evm_circuit::util::{
        self, constraint_builder::ConstraintBuilder, from_bytes, pow_of_two_expr, split_u256,
        split_u256_limb64, CachedRegion, Cell,
    },
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Construct the gadget that checks a * b + c == d (modulo 2**256),
/// where a, b, c, d are 256-bit words. This can be used by opcode MUL, DIV,
/// and MOD. For opcode MUL, set c to 0. For opcode DIV and MOD, treat c as
/// residue and d as dividend.
///
/// We execute a multi-limb multiplication as follows:
/// a and b is divided into 4 64-bit limbs, denoted as a0~a3 and b0~b3
/// defined t0, t1, t2, t3
///   t0 = a0 * b0, contribute to 0 ~ 128 bit
///   t1 = a0 * b1 + a1 * b0, contribute to 64 ~ 193 bit (include the carry)
///   t2 = a0 * b2 + a2 * b0 + a1 * b1, contribute to above 128 bit
///   t3 = a0 * b3 + a3 * b0 + a2 * b1 + a1 * b2, contribute to above 192 bit
///
/// so t0 ~ t1 include all contributions to the low 256-bit of product, with
/// a maximum 68-bit radix (the part higher than 256-bit), denoted as carry_hi
/// Similarly, we define carry_lo as the radix of contributions to the low
/// 128-bit of the product.
/// We can slightly relax the constraint of carry_lo/carry_hi to 72-bit and
/// allocate 9 bytes for them each
///
/// Finally we just prove:
///   t0 + t1 * 2^64 = <low 128 bit of product> + carry_lo
///   t2 + t3 * 2^64 + carry_lo = <high 128 bit of product> + carry_hi
///
/// Last, we sum the parts that are higher than 256-bit in the multiplication
/// into overflow
///   overflow = carry_hi + a1 * b3 + a2 * b2 + a3 * b1 + a2 * b3 + a3 * b2
///              + a3 * b3
/// In the cases of DIV and MOD, we need to constrain overflow == 0 outside the
/// MulAddWordsGadget.
#[derive(Clone, Debug)]
pub(crate) struct MulAddWordsGadget<F> {
    carry_lo: [Cell<F>; 9],
    carry_hi: [Cell<F>; 9],
    overflow: Expression<F>,
}

impl<F: Field> MulAddWordsGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, words: [&util::Word<F>; 4]) -> Self {
        let (a, b, c, d) = (words[0], words[1], words[2], words[3]);
        let carry_lo = cb.query_bytes();
        let carry_hi = cb.query_bytes();
        let carry_lo_expr = from_bytes::expr(&carry_lo);
        let carry_hi_expr = from_bytes::expr(&carry_hi);

        let mut a_limbs = vec![];
        let mut b_limbs = vec![];
        for trunk in 0..4 {
            let idx = (trunk * 8) as usize;
            a_limbs.push(from_bytes::expr(&a.cells[idx..idx + 8]));
            b_limbs.push(from_bytes::expr(&b.cells[idx..idx + 8]));
        }
        let c_lo = from_bytes::expr(&c.cells[0..16]);
        let c_hi = from_bytes::expr(&c.cells[16..32]);
        let d_lo = from_bytes::expr(&d.cells[0..16]);
        let d_hi = from_bytes::expr(&d.cells[16..32]);

        let t0 = a_limbs[0].clone() * b_limbs[0].clone();
        let t1 = a_limbs[0].clone() * b_limbs[1].clone() + a_limbs[1].clone() * b_limbs[0].clone();
        let t2 = a_limbs[0].clone() * b_limbs[2].clone()
            + a_limbs[1].clone() * b_limbs[1].clone()
            + a_limbs[2].clone() * b_limbs[0].clone();
        let t3 = a_limbs[0].clone() * b_limbs[3].clone()
            + a_limbs[1].clone() * b_limbs[2].clone()
            + a_limbs[2].clone() * b_limbs[1].clone()
            + a_limbs[3].clone() * b_limbs[0].clone();
        let overflow = carry_hi_expr.clone()
            + a_limbs[1].clone() * b_limbs[3].clone()
            + a_limbs[2].clone() * b_limbs[2].clone()
            + a_limbs[3].clone() * b_limbs[1].clone()
            + a_limbs[2].clone() * b_limbs[3].clone()
            + a_limbs[3].clone() * b_limbs[2].clone()
            + a_limbs[3].clone() * b_limbs[3].clone();

        cb.require_equal(
            "(a * b)_lo + c_lo == d_lo + carry_lo ⋅ 2^128",
            t0.expr() + t1.expr() * pow_of_two_expr(64) + c_lo,
            d_lo + carry_lo_expr.clone() * pow_of_two_expr(128),
        );
        cb.require_equal(
            "(a * b)_hi + c_hi + carry_lo == d_hi + carry_hi ⋅ 2^128",
            t2.expr() + t3.expr() * pow_of_two_expr(64) + c_hi + carry_lo_expr,
            d_hi + carry_hi_expr * pow_of_two_expr(128),
        );

        Self {
            carry_lo,
            carry_hi,
            overflow,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        words: [Word; 4],
    ) -> Result<(), Error> {
        let (a, b, c, d) = (words[0], words[1], words[2], words[3]);

        let a_limbs = split_u256_limb64(&a);
        let b_limbs = split_u256_limb64(&b);
        let (c_lo, c_hi) = split_u256(&c);
        let (d_lo, d_hi) = split_u256(&d);

        let t0 = a_limbs[0] * b_limbs[0];
        let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
        let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
        let t3 = a_limbs[0] * b_limbs[3]
            + a_limbs[1] * b_limbs[2]
            + a_limbs[2] * b_limbs[1]
            + a_limbs[3] * b_limbs[0];

        let carry_lo = (t0 + (t1 << 64) + c_lo).saturating_sub(d_lo) >> 128;
        let carry_hi = (t2 + (t3 << 64) + c_hi + carry_lo).saturating_sub(d_hi) >> 128;

        self.carry_lo
            .iter()
            .zip(carry_lo.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Value::known(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        self.carry_hi
            .iter()
            .zip(carry_hi.to_le_bytes().iter())
            .map(|(cell, byte)| cell.assign(region, offset, Value::known(F::from(*byte as u64))))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    pub(crate) fn overflow(&self) -> Expression<F> {
        self.overflow.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::*;
    use super::*;
    use eth_types::{ToScalar, Word};
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::plonk::Error;

    #[derive(Clone)]
    /// MulAddGadgetContainer: require(a*b + c == d + carry*(2**256))
    struct MulAddGadgetContainer<F> {
        muladd_words_gadget: MulAddWordsGadget<F>,
        a: util::Word<F>,
        b: util::Word<F>,
        c: util::Word<F>,
        d: util::Word<F>,
        carry: Cell<F>,
    }

    impl<F: Field> MathGadgetContainer<F> for MulAddGadgetContainer<F> {
        fn configure_gadget_container(cb: &mut ConstraintBuilder<F>) -> Self {
            let a = cb.query_word();
            let b = cb.query_word();
            let c = cb.query_word();
            let d = cb.query_word();
            let carry = cb.query_cell();
            let math_gadget = MulAddWordsGadget::<F>::construct(cb, [&a, &b, &c, &d]);
            cb.require_equal("carry is correct", math_gadget.overflow(), carry.expr());
            MulAddGadgetContainer {
                muladd_words_gadget: math_gadget,
                a,
                b,
                c,
                d,
                carry,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let offset = 0;
            self.a
                .assign(region, offset, Some(witnesses[0].to_le_bytes()))?;
            self.b
                .assign(region, offset, Some(witnesses[1].to_le_bytes()))?;
            self.c
                .assign(region, offset, Some(witnesses[2].to_le_bytes()))?;
            self.d
                .assign(region, offset, Some(witnesses[3].to_le_bytes()))?;
            self.carry.assign(
                region,
                offset,
                Value::known(witnesses[4].to_scalar().unwrap()),
            )?;
            self.muladd_words_gadget
                .assign(region, offset, witnesses[..4].try_into().unwrap())
        }
    }

    #[test]
    fn test_muladd_expect() {
        // 0 * 0 + 0 == 0
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(0),
                Word::from(0),
                Word::from(0),
                Word::from(0),
                Word::from(0)
            ],
            true,
        );
        // 1 * 0 + 0 == 0
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(1),
                Word::from(0),
                Word::from(0),
                Word::from(0),
                Word::from(0)
            ],
            true,
        );
        // 1 * 1 + 0 == 1
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(1),
                Word::from(1),
                Word::from(0),
                Word::from(1),
                Word::from(0)
            ],
            true,
        );
        // 1 * 1 + 1 == 2
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(1),
                Word::from(1),
                Word::from(1),
                Word::from(2),
                Word::from(0)
            ],
            true,
        );
        // 100 * 54 + 98 == 5498
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(100),
                Word::from(54),
                Word::from(98),
                Word::from(5498),
                Word::from(0)
            ],
            true,
        );
        // 100 * 54 + low_max == low_max + 5400
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(100),
                Word::from(54),
                WORD_LOW_MAX,
                Word::from(5400) + WORD_LOW_MAX,
                Word::from(0)
            ],
            true,
        );
        // 100 * 54 + high_max == high_max + 5400
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(100),
                Word::from(54),
                WORD_HIGH_MAX,
                Word::from(5400) + WORD_HIGH_MAX,
                Word::from(0)
            ],
            true,
        );
    }

    #[test]
    fn test_overflow_expected() {
        // high_max + low_max + 1 == 0 with overflow 1
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                WORD_LOW_MAX + 1,
                Word::from(1),
                WORD_HIGH_MAX,
                Word::from(0),
                Word::from(1)
            ],
            true,
        );
    }

    #[test]
    #[ignore]
    fn test_max_carry() {
        // max * max + max = max << 256
        // overflow is not really carry value, but kind of a flag.
        // overflow == 73786976294838206460 + ((1<<64)-1)*((1<<64)-1)*6
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::MAX,
                Word::MAX,
                Word::MAX,
                Word::from(0),
                Word::from_dec_str("2041694201525630780632673692000932855810").unwrap(),
            ],
            true,
        );
    }

    #[test]
    fn test_muladd_unexpect() {
        // 10 * 1 + 1 != 3
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(10),
                Word::from(1),
                Word::from(1),
                Word::from(3),
                Word::from(0)
            ],
            false,
        );

        // 1 * 1 + 1 != word_max, no underflow
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(1),
                Word::from(1),
                Word::from(1),
                Word::MAX,
                Word::from(0)
            ],
            false,
        );

        // 100 * 54 + high_max == high_max + 5400, no overflow
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                Word::from(100),
                Word::from(54),
                WORD_HIGH_MAX,
                Word::from(5400) + WORD_HIGH_MAX,
                Word::from(1)
            ],
            false,
        );

        // (low_max + 1) * 1 + high_max == 0 with overflow 1
        try_test!(
            MulAddGadgetContainer<Fr>,
            vec![
                WORD_LOW_MAX + 1,
                Word::from(1),
                WORD_HIGH_MAX,
                Word::from(0),
                Word::from(0)
            ],
            false,
        );
    }
}
