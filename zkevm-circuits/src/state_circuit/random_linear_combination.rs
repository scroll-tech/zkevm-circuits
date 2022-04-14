use crate::evm_circuit::util::RandomLinearCombination as RLC;
use eth_types::{Field, ToLittleEndian, U256};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Clone, Debug, Copy)]
pub struct Config<const N: usize> {
    pub encoded: Column<Advice>,
    // bytes are little endian
    pub bytes: [Column<Advice>; N],
}

#[derive(Clone)]
pub struct Queries<F: Field, const N: usize> {
    pub encoded: Expression<F>,
    pub encoded_prev: Expression<F>,
    pub bytes: [Expression<F>; N],
}

impl<F: Field, const N: usize> Queries<F, N> {
    pub fn new(meta: &mut VirtualCells<'_, F>, c: Config<N>) -> Self {
        Self {
            encoded: meta.query_advice(c.encoded, Rotation::cur()),
            encoded_prev: meta.query_advice(c.encoded, Rotation::prev()),
            bytes: c.bytes.map(|byte| meta.query_advice(byte, Rotation::cur())),
        }
    }
}

impl<const N: usize> Config<N> {
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        randomness: F,
        value: U256,
    ) -> Result<AssignedCell<F, F>, Error> {
        let bytes = value.to_le_bytes();
        for (i, &byte) in bytes.iter().enumerate() {
            region.assign_advice(
                || format!("byte[{}] in rlc", i),
                self.bytes[i],
                offset,
                || Ok(F::from(byte as u64)),
            )?;
        }
        region.assign_advice(
            || "encoded value in rlc",
            self.encoded,
            offset,
            || Ok(RLC::random_linear_combine(bytes, randomness)),
        )
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
        u8_lookup: Column<Fixed>,
        power_of_randomness: [Column<Instance>; 31],
    ) -> Config<N> {
        let encoded = meta.advice_column();
        let bytes = [0; N].map(|_| meta.advice_column());

        for &byte in &bytes {
            meta.lookup_any("rlc bytes fit into u8", |meta| {
                let byte = meta.query_advice(byte, Rotation::cur());
                let u8_lookup = meta.query_fixed(u8_lookup, Rotation::cur());
                vec![(byte, u8_lookup)]
            });
        }

        meta.create_gate("rlc encoded value matches bytes", |meta| {
            let selector = meta.query_fixed(selector, Rotation::cur());
            let encoded = meta.query_advice(encoded, Rotation::cur());
            let bytes = bytes.map(|c| meta.query_advice(c, Rotation::cur()));
            let power_of_randomness: Vec<_> = power_of_randomness
                .iter()
                .map(|c| meta.query_instance(*c, Rotation::cur()))
                .collect();
            vec![
                selector * (encoded - RLC::random_linear_combine_expr(bytes, &power_of_randomness)),
            ]
        });

        Config { encoded, bytes }
    }

    pub fn load(&self, _layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}
