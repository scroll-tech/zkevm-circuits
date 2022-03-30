use std::marker::PhantomData;
use std::convert::TryInto;

use itertools::Itertools;
use eth_types::{Address, ToScalar, Field};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region},
    plonk::{ConstraintSystem, Error, Expression},
};

use crate::util::Expr;

use super::cell::AdviceCell;

// TODO: maybe parameterize over number of limbs?
pub trait ToLimbs {
    fn to_limbs(&self) -> Vec<u16>;
}

impl ToLimbs for Address {
    fn to_limbs(&self) -> Vec<u16> {
        le_bytes_to_limbs(&self.0)
    }
}

impl ToLimbs for u32 {
    fn to_limbs(&self) -> Vec<u16> {
        le_bytes_to_limbs(&self.to_le_bytes())
    }
}

#[derive(Clone)]
pub struct Config<F: Field, T: ToLimbs, const N: usize> {
    value: AdviceCell<F>,
    limbs: [AdviceCell<F>; N],
    _marker: PhantomData<T>,
}

// impl<F: Field, const N: usize> Config<F, Address, N> {
//     pub fn assign(
//         &self,
//         region: &mut Region<'_, F>,
//         offset: usize,
//         value: Address,
//     ) -> Result<AssignedCell<F, F>, Error> {
//         self.value
//             .assign(region, offset, value.to_scalar().unwrap())
//         self.limbs.map(
//             |limb| limb.assign()
//         )
//     }
// }

impl<F: Field, const N: usize> Config<F, u32, N> {
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: u32,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.value
            .assign(region, offset, F::from(value as u64))
    }
}

pub struct Chip<F: Field, T: ToLimbs, const N: usize> {
    config: Config<F, T, N>,
}

impl<F: Field, T: ToLimbs, const N: usize> Chip<F, T, N> {
    pub fn construct(config: Config<F, T, N>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Expression<F>,
        u16_range: Expression<F>,
    ) -> Config<F, T, N> {
        let value = AdviceCell::new(meta);
        let limbs = [0; N].map(|_| AdviceCell::new(meta));

        // Move these into a build function in a hypthetical ConstraintBuilder?
        meta.lookup_any("mpi limbs fit into u16", |_| {
            limbs
                .iter()
                .map(|limb| (limb.cur.clone(), u16_range.clone()))
                .collect()
        });
        meta.create_gate("mpi value matches claimed limbs", |_| {
            vec![selector * (value.cur.clone() - value_from_limbs(&limbs))]
        });

        Config { value, limbs, _marker: PhantomData }
    }

    pub fn load(&self, _layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

fn le_bytes_to_limbs(bytes: &[u8]) -> Vec<u16> {
    bytes
        .iter()
        .tuples()
        .map(|(hi, lo)| u16::from_le_bytes([*lo, *hi]))
        .collect()
}

fn value_from_limbs<F: Field>(limbs: &[AdviceCell<F>]) -> Expression<F> {
    limbs
        .iter()
        .map(|limb| &limb.cur)
        .fold(0u64.expr(), |result, limb| {
            limb.clone() + result * (1u64 << 16).expr()
        })
}
