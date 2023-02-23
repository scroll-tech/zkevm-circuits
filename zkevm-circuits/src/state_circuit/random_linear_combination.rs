use crate::evm_circuit::util::rlc;
use eth_types::{Field, ToLittleEndian, U256};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;

use super::lookups;

#[derive(Clone, Debug, Copy)]
pub struct Config<const N: usize> {
    // bytes are little endian
    pub bytes: [Column<Advice>; N],
}

#[derive(Clone)]
pub struct Queries<F: Field, const N: usize> {
    pub bytes: [Expression<F>; N],
}

impl<F: Field, const N: usize> Queries<F, N> {
    pub fn new(meta: &mut VirtualCells<'_, F>, c: Config<N>) -> Self {
        Self {
            bytes: c.bytes.map(|byte| meta.query_advice(byte, Rotation::cur())),
        }
    }
}

impl<const N: usize> Config<N> {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        _randomness: Value<F>, // kept for future use
        value: U256,
    ) -> Result<(), Error> {
        let bytes = value.to_le_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            region.assign_advice(
                || format!("byte[{}] in rlc", i),
                self.bytes[i],
                offset,
                || Value::known(F::from(byte as u64)),
            )?;
        }
        Ok(())
    }

    /// Annotates columns of this gadget embedded within a circuit region.
    pub fn annotate_columns_in_region<F: Field>(&self, region: &mut Region<F>, prefix: &str) {
        let mut annotations = Vec::new();
        for (i, _) in self.bytes.iter().enumerate() {
            annotations.push(format!("RLC_byte{}", i));
        }
        self.bytes
            .iter()
            .zip(annotations.iter())
            .for_each(|(col, ann)| region.name_column(|| format!("{}_{}", prefix, ann), *col));
    }
}

pub struct Chip<F: Field, const N: usize> {
    config: Config<N>,
    _marker: PhantomData<F>,
}

impl<F: Field, const N: usize> Chip<F, N> {
    pub fn construct(config: Config<N>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Column<Fixed>,
        encoded: Column<Advice>,
        lookup: lookups::Config,
        randomness: Expression<F>,
    ) -> Config<N> {
        let bytes = [0; N].map(|_| meta.advice_column());

        for &byte in &bytes {
            lookup.range_check_u8(meta, "rlc bytes fit into u8", |meta| {
                meta.query_advice(byte, Rotation::cur())
            });
        }

        meta.create_gate("rlc encoded value matches bytes", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let encoded = meta.query_advice(encoded, Rotation::cur());
            let bytes = bytes.map(|c| meta.query_advice(c, Rotation::cur()));
            vec![selector * (encoded - rlc::expr(&bytes, randomness))]
        });

        Config { bytes }
    }

    pub fn load(&self, _layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}
