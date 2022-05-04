//! The state circuit implementation.
mod constraint_builder;
mod lexicographic_ordering;
mod lookups;
mod multiple_precision_integer;
mod random_linear_combination;
#[cfg(test)]
mod state_tests;

use crate::evm_circuit::{
    param::N_BYTES_WORD,
    witness::{Rw, RwMap},
};
use constraint_builder::{ConstraintBuilder, Queries};
use eth_types::{Address, Field};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, VirtualCells,
    },
    poly::Rotation,
};
use lexicographic_ordering::{
    Chip as LexicographicOrderingChip, Config as LexicographicOrderingConfig,
};
use lookups::{Chip as LookupsChip, Config as LookupsConfig, Queries as LookupsQueries};
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig, Queries as MpiQueries};
use random_linear_combination::{Chip as RlcChip, Config as RlcConfig, Queries as RlcQueries};

const N_LIMBS_RW_COUNTER: usize = 2;
const N_LIMBS_ACCOUNT_ADDRESS: usize = 10;
const N_LIMBS_ID: usize = 2;

/// Config for StateCircuit
#[derive(Clone)]
pub struct StateConfig<F: Field> {
    selector: Column<Fixed>, // Figure out why you get errors when this is Selector.
    // https://github.com/appliedzkp/zkevm-circuits/issues/407
    rw_counter: MpiConfig<u32, N_LIMBS_RW_COUNTER>,
    is_write: Column<Advice>,
    tag: Column<Advice>,
    id: MpiConfig<u32, N_LIMBS_ID>,
    address: MpiConfig<Address, N_LIMBS_ACCOUNT_ADDRESS>,
    field_tag: Column<Advice>,
    // Consider using WordConfig instead?
    storage_key: RlcConfig<N_BYTES_WORD>,
    is_storage_key_unchanged: IsZeroConfig<F>,
    value: Column<Advice>,
    lookups: LookupsConfig,
    power_of_randomness: [Column<Instance>; N_BYTES_WORD - 1],
    lexicographic_ordering: LexicographicOrderingConfig<F>,
}

type Lookup<F> = (&'static str, Expression<F>, Expression<F>);

/// State Circuit for proving RwTable is valid
#[derive(Default)]
pub struct StateCircuit<F: Field> {
    pub(crate) randomness: F,
    pub(crate) rows: Vec<Rw>,
}

impl<F: Field> StateCircuit<F> {
    /// make a new state circuit
    pub fn new(randomness: F, rw_map: RwMap) -> Self {
        let mut rows: Vec<_> = rw_map.0.into_values().flatten().collect();
        rows.sort_by_key(|row| {
            (
                row.tag() as u64,
                row.field_tag().unwrap_or_default(),
                row.id().unwrap_or_default(),
                row.address().unwrap_or_default(),
                row.storage_key().unwrap_or_default(),
                row.rw_counter(),
            )
        });
        Self { randomness, rows }
    }

    /// powers of randomness for instance columns
    pub fn instance(&self) -> Vec<Vec<F>> {
        (1..32)
            .map(|exp| vec![self.randomness.pow(&[exp, 0, 0, 0]); self.rows.len()])
            .collect()
    }
}

impl<F: Field> Circuit<F> for StateCircuit<F> {
    type Config = StateConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let selector = meta.fixed_column();
        let lookups = LookupsChip::configure(meta);
        let power_of_randomness = [0; N_BYTES_WORD - 1].map(|_| meta.instance_column());

        let [is_write, tag, field_tag, value, is_zero_chip_advice_column] =
            [0; 5].map(|_| meta.advice_column());

        let id = MpiChip::configure(meta, selector, lookups.u16);
        let address = MpiChip::configure(meta, selector, lookups.u16);
        let storage_key = RlcChip::configure(meta, selector, lookups.u8, power_of_randomness);
        let rw_counter = MpiChip::configure(meta, selector, lookups.u16);

        let is_storage_key_unchanged = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(selector, Rotation::cur()),
            |meta| {
                meta.query_advice(storage_key.encoded, Rotation::cur())
                    - meta.query_advice(storage_key.encoded, Rotation::prev())
            },
            is_zero_chip_advice_column,
        );

        let config = Self::Config {
            selector,
            rw_counter,
            is_write,
            tag,
            id,
            address,
            field_tag,
            storage_key,
            value,
            lexicographic_ordering: LexicographicOrderingChip::configure(
                meta,
                selector,
                tag,
                field_tag,
                id.limbs,
                address.limbs,
                storage_key.bytes,
                rw_counter.limbs,
                lookups.u16,
            ),
            is_storage_key_unchanged,
            lookups,
            power_of_randomness,
        };

        let mut constraint_builder = ConstraintBuilder::new();
        meta.create_gate("state circuit constraints", |meta| {
            let queries = queries(meta, &config);
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
        LookupsChip::construct(config.lookups).load(&mut layouter)?;
        let is_storage_key_unchanged =
            IsZeroChip::construct(config.is_storage_key_unchanged.clone());

        let lexicographic_ordering_chip =
            LexicographicOrderingChip::construct(config.lexicographic_ordering.clone());

        dbg!(self.rows.clone());

        let mut prev_storage_key = F::zero();

        layouter.assign_region(
            || "assign rw table",
            |mut region| {
                for (offset, row) in self.rows.iter().enumerate() {
                    if offset != 0 {
                        region.assign_fixed(
                            || "selector",
                            config.selector,
                            offset,
                            || Ok(F::one()),
                        )?;

                        lexicographic_ordering_chip.assign(
                            &mut region,
                            offset,
                            row,
                            &self.rows[offset - 1],
                        )?;
                    }
                    config
                        .rw_counter
                        .assign(&mut region, offset, row.rw_counter() as u32)?;
                    region.assign_advice(
                        || "is_write",
                        config.is_write,
                        offset,
                        || Ok(if row.is_write() { F::one() } else { F::zero() }),
                    )?;
                    region.assign_advice(
                        || "tag",
                        config.tag,
                        offset,
                        || Ok(F::from(row.tag() as u64)),
                    )?;
                    if let Some(id) = row.id() {
                        config.id.assign(&mut region, offset, id as u32)?;
                    }
                    if let Some(address) = row.address() {
                        config.address.assign(&mut region, offset, address)?;
                    }
                    if let Some(field_tag) = row.field_tag() {
                        region.assign_advice(
                            || "field_tag",
                            config.field_tag,
                            offset,
                            || Ok(F::from(field_tag as u64)),
                        )?;
                    }

                    // TODO: chain assigments idiomatically.
                    let cur_storage_key = *(config
                        .storage_key
                        .assign(
                            &mut region,
                            offset,
                            self.randomness,
                            row.storage_key().unwrap_or_default(),
                        )?
                        .value()
                        .unwrap_or(&F::zero()));

                    is_storage_key_unchanged.assign(
                        &mut region,
                        offset,
                        Some(cur_storage_key - prev_storage_key),
                    )?;

                    prev_storage_key = cur_storage_key;
                }
                Ok(())
            },
        )
    }
}

fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: &StateConfig<F>) -> Queries<F> {
    Queries {
        selector: meta.query_fixed(c.selector, Rotation::cur()),
        rw_counter: MpiQueries::new(meta, c.rw_counter),
        is_write: meta.query_advice(c.is_write, Rotation::cur()),
        tag: meta.query_advice(c.tag, Rotation::cur()),
        prev_tag: meta.query_advice(c.tag, Rotation::prev()),
        id: MpiQueries::new(meta, c.id),
        address: MpiQueries::new(meta, c.address),
        field_tag: meta.query_advice(c.field_tag, Rotation::cur()),
        storage_key: RlcQueries::new(meta, c.storage_key),
        value: meta.query_advice(c.value, Rotation::cur()),
        lookups: LookupsQueries::new(meta, c.lookups),
        power_of_randomness: c
            .power_of_randomness
            .map(|c| meta.query_instance(c, Rotation::cur())),
        is_storage_key_unchanged: c.is_storage_key_unchanged.is_zero_expression.clone(),
        lexicographic_ordering_diff_1_is_zero: c
            .lexicographic_ordering
            .diff_1_is_zero
            .is_zero_expression
            .clone(),
    }
}
