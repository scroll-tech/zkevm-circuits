use crate::{
    evm_circuit::{
        param::MAX_N_BYTES_INTEGER,
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes, pow_of_two, transpose_val_ret, CachedRegion, Cell,
        },
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Returns `1` when `lhs < rhs`, and returns `0` otherwise.
/// lhs and rhs `< 256**N_BYTES`
/// `N_BYTES` is required to be `<= MAX_N_BYTES_INTEGER` to prevent overflow:
/// values are stored in a single field element and two of these are added
/// together.
/// The equation that is enforced is `lhs - rhs == diff - (lt * range)`.
/// Because all values are `<= 256**N_BYTES` and `lt` is boolean, `lt` can only
/// be `1` when `lhs < rhs`.
#[derive(Clone, Debug)]
pub struct LtGadget<F, const N_BYTES: usize> {
    lt: Cell<F>, // `1` when `lhs < rhs`, `0` otherwise.
    diff: [Cell<F>; N_BYTES], /* The byte values of `diff`.
                  * `diff` equals `lhs - rhs` if `lhs >= rhs`,
                  * `lhs - rhs + range` otherwise. */
    range: F, // The range of the inputs, `256**N_BYTES`
}

impl<F: Field, const N_BYTES: usize> LtGadget<F, N_BYTES> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> Self {
        assert!(N_BYTES <= MAX_N_BYTES_INTEGER);
        let lt = cb.query_bool();
        let diff = cb.query_bytes();
        let range = pow_of_two(N_BYTES * 8);

        // The equation we require to hold: `lhs - rhs == diff - (lt * range)`.
        cb.require_equal(
            "lhs - rhs == diff - (lt ⋅ range)",
            lhs - rhs,
            from_bytes::expr(&diff) - (lt.expr() * range),
        );

        Self { lt, diff, range }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        self.lt.expr()
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(F, Vec<u8>), Error> {
        // Set `lt`
        let lt = lhs < rhs;
        self.lt.assign(
            region,
            offset,
            Value::known(if lt { F::one() } else { F::zero() }),
        )?;

        // Set the bytes of diff
        let diff = (lhs - rhs) + (if lt { self.range } else { F::zero() });
        let diff_bytes = diff.to_repr();
        for (idx, diff) in self.diff.iter().enumerate() {
            diff.assign(
                region,
                offset,
                Value::known(F::from(diff_bytes[idx] as u64)),
            )?;
        }

        Ok((if lt { F::one() } else { F::zero() }, diff_bytes.to_vec()))
    }

    pub(crate) fn diff_bytes(&self) -> Vec<Cell<F>> {
        self.diff.to_vec()
    }

    pub(crate) fn assign_value(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        lhs: Value<F>,
        rhs: Value<F>,
    ) -> Result<Value<(F, Vec<u8>)>, Error> {
        transpose_val_ret(
            lhs.zip(rhs)
                .map(|(lhs, rhs)| self.assign(region, offset, lhs, rhs)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_util::*, *};
    use eth_types::*;
    use halo2_proofs::{halo2curves::bn256::Fr, plonk::Error};

    const N: usize = 3;
    #[derive(Clone)]
    /// LtGadgetTestContainer: require(a < b)
    struct LtGadgetTestContainer<F> {
        lt_gadget: LtGadget<F, N>,
        a: Cell<F>,
        b: Cell<F>,
    }

    impl<F: Field> MathGadgetContainer<F> for LtGadgetTestContainer<F> {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let a = cb.query_cell();
            let b = cb.query_cell();
            let lt_gadget = LtGadget::<F, N>::construct(cb, a.expr(), b.expr());
            cb.require_equal("a < b", lt_gadget.expr(), 1.expr());
            LtGadgetTestContainer { lt_gadget, a, b }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[Word],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let a = F::from(u64::from_le_bytes(
                witnesses[0].to_le_bytes()[..8].try_into().unwrap(),
            ));
            let b = F::from(u64::from_le_bytes(
                witnesses[1].to_le_bytes()[..8].try_into().unwrap(),
            ));
            let offset = 0;

            self.a.assign(region, offset, Value::known(a))?;
            self.b.assign(region, offset, Value::known(b))?;
            self.lt_gadget.assign(region, offset, a, b)?;

            Ok(())
        }
    }

    #[test]
    fn test_lt_expect() {
        try_test!(
            LtGadgetTestContainer<Fr>,
            [Word::from(0), Word::from(1)],
            true,
        );
        try_test!(
            LtGadgetTestContainer<Fr>,
            [Word::from(0), Word::from(0)],
            false,
        );
    }

    #[test]
    fn test_lt_just_in_range() {
        try_test!(
            LtGadgetTestContainer<Fr>,
            [Word::from(1), Word::from((1u64 << (N * 8)) - 1)],
            true,
        );
    }

    #[test]
    fn test_lt_out_of_range() {
        try_test!(
            LtGadgetTestContainer<Fr>,
            [Word::from(1), Word::from(2 << (N * 8))],
            false,
        );
    }
}
