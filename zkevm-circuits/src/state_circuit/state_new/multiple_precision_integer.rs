use eth_types::{Address, Field, ToScalar};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::marker::PhantomData;

use crate::util::Expr;

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

#[derive(Clone, Copy)]
pub struct Config<T: ToLimbs, const N: usize> {
    pub value: Column<Advice>,
    pub limbs: [Column<Advice>; N],
    _marker: PhantomData<T>,
}

#[derive(Clone)]
pub struct Queries<F: Field, T: ToLimbs, const N: usize> {
    pub value: Expression<F>,
    pub limbs: [Expression<F>; N],
    _marker: PhantomData<T>,
}

impl<F: Field, T: ToLimbs, const N: usize> Queries<F, T, N> {
    pub fn new(meta: &mut VirtualCells<'_, F>, c: Config<T, N>) -> Self {
        Self {
            value: meta.query_advice(c.value, Rotation::cur()),
            limbs: c.limbs.map(|limb| meta.query_advice(limb, Rotation::cur())),
            _marker: PhantomData,
        }
    }
}

impl<const N: usize> Config<Address, N> {
    pub fn assign<F: Field>(
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

impl<const N: usize> Config<u32, N> {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: u32,
    ) -> Result<AssignedCell<F, F>, Error> {
        for (i, &limb) in le_bytes_to_limbs(&value.to_le_bytes()).iter().enumerate() {
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

pub struct Chip<F: Field, T: ToLimbs, const N: usize> {
    config: Config<T, N>,
    _marker: PhantomData<F>,
}

impl<F: Field, T: ToLimbs, const N: usize> Chip<F, T, N> {
    pub fn construct(config: Config<T, N>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        _selector: Selector,
        _u16_range: Column<Fixed>,
    ) -> Config<T, N> {
        let value = meta.advice_column();
        let limbs = [0; N].map(|_| meta.advice_column());

        // let q_value = meta.query_advice(value, Rotation::cur());
        // for limb in &limbs {
        //     let q_limb =
        //     meta.lookup_any("mpi limb fits into u16", |_| {
        //         vec![(limb.cur.clone(), u16_range.clone())]
        //     });
        // }
        //
        // meta.create_gate("mpi value matches claimed limbs", |_| {
        //     vec![selector * (value.cur.clone() - value_from_limbs(&limbs))]
        // });

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
