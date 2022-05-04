use super::N_LIMBS_ACCOUNT_ADDRESS;
use super::N_LIMBS_RW_COUNTER;
use crate::util::Expr;
use eth_types::{Address, Field, ToScalar};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::convert::TryInto;
use std::marker::PhantomData;

pub trait ToLimbs<const N: usize> {
    fn to_limbs(&self) -> [u16; N];
}

impl ToLimbs<N_LIMBS_ACCOUNT_ADDRESS> for Address {
    fn to_limbs(&self) -> [u16; 10] {
        // address bytes are be.... maybe just have everything be later?
        // you will need this in the future later because it makes the key ordering more
        // obvious
        let le_bytes: Vec<_> = self.0.iter().rev().cloned().collect();
        le_bytes_to_limbs(&le_bytes).try_into().unwrap()
    }
}

impl ToLimbs<N_LIMBS_RW_COUNTER> for u32 {
    fn to_limbs(&self) -> [u16; 2] {
        le_bytes_to_limbs(&self.to_le_bytes()).try_into().unwrap()
    }
}

#[derive(Clone, Copy)]
pub struct Config<T, const N: usize>
where
    T: ToLimbs<N>,
{
    pub value: Column<Advice>,
    // TODO: we can save a column here by not storing the lsb, and then checking that
    // value - value_from_limbs(limbs.prepend(0)) fits into a limb.
    // Does this apply for RLC's too?
    pub limbs: [Column<Advice>; N],
    _marker: PhantomData<T>,
}

#[derive(Clone)]
pub struct Queries<F: Field, const N: usize> {
    pub value: Expression<F>,
    pub value_prev: Expression<F>, // move this up, as it's not always needed.
    pub limbs: [Expression<F>; N],
}

impl<F: Field, const N: usize> Queries<F, N> {
    pub fn new<T: ToLimbs<N>>(meta: &mut VirtualCells<'_, F>, c: Config<T, N>) -> Self {
        Self {
            value: meta.query_advice(c.value, Rotation::cur()),
            value_prev: meta.query_advice(c.value, Rotation::prev()),
            limbs: c.limbs.map(|limb| meta.query_advice(limb, Rotation::cur())),
        }
    }
}

impl Config<Address, N_LIMBS_ACCOUNT_ADDRESS> {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Address,
    ) -> Result<AssignedCell<F, F>, Error> {
        for (i, &limb) in value.to_limbs().iter().enumerate() {
            region.assign_advice(
                || format!("limb[{}] in address mpi", i),
                self.limbs[i],
                offset,
                || Ok(F::from(limb as u64)),
            )?;
        }
        region.assign_advice(
            || "value in u32 mpi",
            self.value,
            offset,
            || Ok(value.to_scalar().unwrap()), // do this better
        )
    }
}

impl Config<u32, N_LIMBS_RW_COUNTER> {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: u32,
    ) -> Result<AssignedCell<F, F>, Error> {
        for (i, &limb) in value.to_limbs().iter().enumerate() {
            region.assign_advice(
                || format!("limb[{}] in u32 mpi", i),
                self.limbs[i],
                offset,
                || Ok(F::from(limb as u64)),
            )?;
        }
        region.assign_advice(
            || "value in u32 mpi",
            self.value,
            offset,
            || Ok(F::from(value as u64)),
        )
    }
}

pub struct Chip<F: Field, T, const N: usize>
where
    T: ToLimbs<N>,
{
    config: Config<T, N>,
    _marker: PhantomData<F>,
}

impl<F: Field, T, const N: usize> Chip<F, T, N>
where
    T: ToLimbs<N>,
{
    pub fn construct(config: Config<T, N>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Column<Fixed>,
        u16_range: Column<Fixed>,
    ) -> Config<T, N> {
        let value = meta.advice_column();
        let limbs = [0; N].map(|_| meta.advice_column());

        for &limb in &limbs {
            meta.lookup_any("mpi limb fits into u16", |meta| {
                vec![(
                    meta.query_advice(limb, Rotation::cur()),
                    meta.query_fixed(u16_range, Rotation::cur()),
                )]
            });
        }
        meta.create_gate("mpi value matches claimed limbs", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let value = meta.query_advice(value, Rotation::cur());
            let limbs = limbs.map(|limb| meta.query_advice(limb, Rotation::cur()));
            vec![selector * (value - value_from_limbs(&limbs))]
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

fn value_from_limbs<F: Field>(limbs: &[Expression<F>]) -> Expression<F> {
    limbs.iter().rev().fold(0u64.expr(), |result, limb| {
        limb.clone() + result * (1u64 << 16).expr()
    })
}
