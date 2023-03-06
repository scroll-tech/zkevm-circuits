use eth_types::Field;
use gadgets::{binary_number::AsBits, util::Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::evm_circuit::util::{constraint_builder::ConstraintBuilder, CachedRegion, Cell};

#[derive(Clone, Debug)]
pub struct BinaryNumberGadget<F, const N: usize> {
    bits: [Cell<F>; N],
}

impl<F: Field, const N: usize> BinaryNumberGadget<F, N> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, value: Expression<F>) -> Self {
        let bits = array_init::array_init(|_| cb.query_bool());

        // the binary representation of value must be correct.
        cb.require_equal(
            "binary representation of value should be correct",
            value,
            bits.iter()
                .fold(0.expr(), |res, bit| bit.expr() + res * 2.expr()),
        );

        Self { bits }
    }

    pub(crate) fn assign<T>(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: T,
    ) -> Result<(), Error>
    where
        T: AsBits<N>,
    {
        for (c, v) in self.bits.iter().zip(value.as_bits().iter()) {
            c.assign(region, offset, Value::known(F::from(*v as u64)))?;
        }
        Ok(())
    }

    pub(crate) fn value(&self) -> Expression<F> {
        self.bits
            .iter()
            .fold(0.expr(), |res, bit| bit.expr() + res * 2.expr())
    }

    pub(crate) fn value_equals<T>(&self, other: T) -> Expression<F>
    where
        T: AsBits<N>,
    {
        gadgets::util::and::expr(other.as_bits().iter().zip(self.bits.iter()).map(
            |(other_bit, self_bit)| {
                if *other_bit {
                    self_bit.expr()
                } else {
                    gadgets::util::not::expr(self_bit.expr())
                }
            },
        ))
    }
}
