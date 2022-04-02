use crate::evm_circuit::{param::N_BYTES_WORD, witness::RwMap};

use eth_types::{Address, Field};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
        VirtualCells,
    },
    poly::Rotation,
};

mod constraint_builder;
mod lookups;
mod multiple_precision_integer;
mod random_linear_combination;
#[cfg(test)]
mod tests;

use constraint_builder::{ConstraintBuilder, Queries};
use lookups::{Chip as LookupsChip, Config as LookupsConfig, Queries as LookupsQueries};
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig, Queries as MpiQueries};
use random_linear_combination::{Chip as RlcChip, Config as RlcConfig, Queries as RlcQueries};

const N_LIMBS_RW_COUNTER: usize = 2;
const N_LIMBS_ACCOUNT_ADDRESS: usize = 10;
const N_LIMBS_ID: usize = 2;

#[derive(Clone, Copy)]
struct StateConfig {
    selector: Selector,
    rw_counter: MpiConfig<u32, N_LIMBS_RW_COUNTER>,
    is_write: Column<Advice>,
    tag: Column<Advice>,
    id: MpiConfig<u32, N_LIMBS_ID>,
    address: MpiConfig<Address, N_LIMBS_ACCOUNT_ADDRESS>,
    field_tag: Column<Advice>,
    storage_key: RlcConfig<N_BYTES_WORD>,
    value: Column<Advice>,
    lookups: LookupsConfig,
    power_of_randomness: [Column<Instance>; N_BYTES_WORD - 1],
    // lexicographic_ordering config, etc.
}

type Lookup<F> = (&'static str, Expression<F>, Expression<F>);

#[derive(Default)]
struct StateCircuit<F: Field> {
    pub randomness: F,
    pub rw_map: RwMap,
}

impl<F: Field> Circuit<F> for StateCircuit<F> {
    type Config = StateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let selector = meta.selector();
        let lookups = LookupsChip::configure(meta);
        let power_of_randomness = [0; N_BYTES_WORD - 1].map(|_| meta.instance_column());

        let config = Self::Config {
            selector,
            rw_counter: MpiChip::configure(meta, selector, lookups.u16),
            is_write: meta.advice_column(),
            tag: meta.advice_column(),
            id: MpiChip::configure(meta, selector, lookups.u16),
            address: MpiChip::configure(meta, selector, lookups.u16),
            field_tag: meta.advice_column(),
            storage_key: RlcChip::configure(meta, selector, lookups.u8, &power_of_randomness),
            value: meta.advice_column(),
            lookups,
            power_of_randomness,
        };

        let mut constraint_builder = ConstraintBuilder::new();
        meta.create_gate("state circuit constraints", |meta| {
            let queries = queries(meta, config);
            constraint_builder.build(&queries);
            constraint_builder.gate(queries.selector)
        });
        for (name, expressions) in constraint_builder.lookups() {
            meta.lookup_any(name, |_| vec![expressions]);
        }

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Is this clone ok?
        // LcChip::construct(config.lookup_columns.clone()).load(&mut layouter)?;

        // TODO: move sorting out of synthesize, so we can check that unsorted witnesses
        // don't verify.
        let mut rows: Vec<_> = self.rw_map.0.values().flatten().collect();
        rows.sort_by_key(|row| {
            (
                row.tag() as u64,
                row.id().unwrap_or_default(),
                row.address().unwrap_or_default(),
                row.field_tag().unwrap_or_default(),
                row.storage_key().unwrap_or_default(),
                row.rw_counter(),
            )
        });

        layouter.assign_region(
            || "assign rw table",
            |mut region| {
                let mut offset = 1;

                for row in &rows {
                    config.selector.enable(&mut region, offset)?;

                    // region.assign_advice(|| "assign advice cell", config.rw_counter, offset, ||
                    // Ok(F::from((row.rw_counter() as u32)))?;
                    config
                        .rw_counter
                        .assign(&mut region, offset, row.rw_counter() as u32)?;
                    // config
                    //     .is_write
                    //     .assign(&mut region, offset, F::from(row.is_write() as u64))?;
                    // config
                    //     .tag
                    //     .assign(&mut region, offset, F::from(row.tag() as u64))?;
                    // if let Some(id) = row.id() {
                    //     config.id.assign(&mut region, offset, F::from(id as u64))?;
                    // }
                    // if let Some(address) = row.address() {
                    //     config.address.assign(&mut region, offset, address)?;
                    // }
                    // if let Some(field_tag) = row.field_tag() {
                    //     config
                    //         .field_tag
                    //         .assign(&mut region, offset, F::from(field_tag))?;
                    // }
                    // if let Some(storage_key) = row.storage_key() {
                    //     config.storage_key.assign(
                    //         &mut region,
                    //         offset,
                    //         self.randomness,
                    //         storage_key,
                    //     )?;
                    // }

                    offset += 1;
                }
                Ok(())
            },
        )
    }
}

fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: StateConfig) -> Queries<F> {
    Queries {
        selector: meta.query_selector(c.selector),
        rw_counter: MpiQueries::new(meta, c.rw_counter),
        is_write: meta.query_advice(c.is_write, Rotation::cur()),
        tag: meta.query_advice(c.tag, Rotation::cur()),
        id: MpiQueries::new(meta, c.rw_counter),
        address: MpiQueries::new(meta, c.address),
        field_tag: meta.query_advice(c.field_tag, Rotation::cur()),
        storage_key: RlcQueries::new(meta, c.storage_key),
        value: meta.query_advice(c.value, Rotation::cur()),
        lookups: LookupsQueries::new(meta, c.lookups),
        power_of_randomness: c
            .power_of_randomness
            .map(|c| meta.query_instance(c, Rotation::cur())),
    }
}
