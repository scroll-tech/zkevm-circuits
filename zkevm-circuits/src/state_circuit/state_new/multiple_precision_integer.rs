use eth_types::{Address, Field, ToScalar};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region},
    plonk::{ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use std::{convert::TryInto, marker::PhantomData};

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

impl<F: Field, const N: usize> Config<F, Address, N> {
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Address,
    ) -> Result<AssignedCell<F, F>, Error> {
        let limbs = value
            .0
            .iter()
            .rev()
            .tuples()
            .map(|(lo, hi)| u16::from_le_bytes([*lo, *hi]));
        for (i, limb) in limbs.enumerate() {
            self.limbs[i].assign(region, offset, F::from(limb as u64))?;
        }
        self.value
            .assign(region, offset, value.to_scalar().unwrap())
    }
}

impl<F: Field, const N: usize> Config<F, u32, N> {
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: u32,
    ) -> Result<AssignedCell<F, F>, Error> {
        for (i, &limb) in le_bytes_to_limbs(&value.to_le_bytes()).iter().enumerate() {
            self.limbs[i].assign(region, offset, F::from(limb as u64))?;
        }
        self.value.assign(region, offset, F::from(value as u64))
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
        for limb in &limbs {
            meta.lookup_any("mpi limb fits into u16", |_| {
                vec![(limb.cur.clone(), u16_range.clone())]
            });
        }

        meta.create_gate("mpi value matches claimed limbs", |_| {
            vec![selector * (value.cur.clone() - value_from_limbs(&limbs))]
        });

        Config {
            value,
            limbs,
            _marker: PhantomData,
        }
    }

    pub fn load(&self, _layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

fn le_bytes_to_limbs(bytes: &[u8]) -> Vec<u16> {
    bytes
        .iter()
        .tuples()
        .map(|(lo, hi)| u16::from_le_bytes([*lo, *hi]))
        .collect()
}

fn value_from_limbs<F: Field>(limbs: &[AdviceCell<F>]) -> Expression<F> {
    limbs
        .iter()
        .rev()
        .map(|limb| &limb.cur)
        .fold(0u64.expr(), |result, limb| {
            limb.clone() + result * (1u64 << 16).expr()
        })
}
