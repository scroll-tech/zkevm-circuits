//! The state circuit implementation.
mod binary_number;
mod constraint_builder;
mod lexicographic_ordering;
mod lookups;
mod multiple_precision_integer;
mod random_linear_combination;
#[cfg(test)]
mod test;

use crate::evm_circuit::{
    param::N_BYTES_WORD,
    table::RwTableTag,
    util::RandomLinearCombination,
    witness::{Rw, RwMap},
};
use binary_number::{Chip as BinaryNumberChip, Config as BinaryNumberConfig};
use constraint_builder::{ConstraintBuilder, Queries};
use eth_types::{Address, Field, ToLittleEndian};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, VirtualCells,
    },
    poly::Rotation,
};
use lexicographic_ordering::Config as LexicographicOrderingConfig;
use lookups::{Chip as LookupsChip, Config as LookupsConfig, Queries as LookupsQueries};
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig, Queries as MpiQueries};
use random_linear_combination::{Chip as RlcChip, Config as RlcConfig, Queries as RlcQueries};
#[cfg(test)]
use std::collections::HashMap;
use std::iter::once;

const N_LIMBS_RW_COUNTER: usize = 2;
const N_LIMBS_ACCOUNT_ADDRESS: usize = 10;
const N_LIMBS_ID: usize = 2;

/// Config for StateCircuit
#[derive(Clone)]
pub struct StateConfig<F: Field> {
    selector: Column<Fixed>, // Figure out why you get errors when this is Selector.
    // https://github.com/appliedzkp/zkevm-circuits/issues/407
    sort_keys: SortKeysConfig,
    is_write: Column<Advice>,
    is_id_unchanged: IsZeroConfig<F>,
    is_storage_key_unchanged: IsZeroConfig<F>, // can be removed
    value: Column<Advice>,
    lookups: LookupsConfig,
    power_of_randomness: [Column<Instance>; N_BYTES_WORD - 1],
    lexicographic_ordering: LexicographicOrderingConfig,
}

/// Keys for sorting the rows of the state circuit
#[derive(Clone, Copy)]
pub struct SortKeysConfig {
    tag: BinaryNumberConfig<RwTableTag, 4>,
    id: MpiConfig<u32, N_LIMBS_ID>,
    field_tag: Column<Advice>,
    address: MpiConfig<Address, N_LIMBS_ACCOUNT_ADDRESS>,
    storage_key: RlcConfig<N_BYTES_WORD>,
    rw_counter: MpiConfig<u32, N_LIMBS_RW_COUNTER>,
}

type Lookup<F> = (&'static str, Expression<F>, Expression<F>);

/// State Circuit for proving RwTable is valid
#[derive(Default)]
pub struct StateCircuit<F: Field> {
    pub(crate) randomness: F,
    pub(crate) rows: Vec<Rw>,
    #[cfg(test)]
    overrides: HashMap<(test::AdviceColumn, usize), F>,
}

impl<F: Field> StateCircuit<F> {
    /// make a new state circuit from an RwMap
    pub fn new(randomness: F, rw_map: RwMap) -> Self {
        let mut rows: Vec<_> = rw_map.0.into_values().flatten().collect();
        rows.sort_by_key(|row| {
            (
                row.tag() as u64,
                row.id().unwrap_or_default(),
                row.field_tag().unwrap_or_default(),
                row.address().unwrap_or_default(),
                // row.field_tag().unwrap_or_default(), // this is the correct place
                row.storage_key().unwrap_or_default(),
                row.rw_counter(),
            )
        });
        Self {
            randomness,
            rows,
            #[cfg(test)]
            overrides: HashMap::new(),
        }
    }

    /// powers of randomness for instance columns
    pub fn instance(&self) -> Vec<Vec<F>> {
        (1..32)
            .map(|exp| vec![self.randomness.pow(&[exp, 0, 0, 0]); self.rows.len() + 1])
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

        let [is_write, field_tag, value, is_id_unchanged_column, is_storage_key_unchanged_column] =
            [0; 5].map(|_| meta.advice_column());

        let tag = BinaryNumberChip::configure(meta, selector);

        let id = MpiChip::configure(meta, selector, lookups.u16);
        let address = MpiChip::configure(meta, selector, lookups.u16);
        let storage_key = RlcChip::configure(meta, selector, lookups.u8, power_of_randomness);
        let rw_counter = MpiChip::configure(meta, selector, lookups.u16);

        let sort_keys = SortKeysConfig {
            tag,
            id,
            field_tag,
            address,
            storage_key,
            rw_counter,
        };

        let lexicographic_ordering =
            LexicographicOrderingConfig::configure(meta, sort_keys, lookups.u16);

        let is_id_unchanged = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(lexicographic_ordering.selector, Rotation::cur()),
            |meta| {
                meta.query_advice(id.value, Rotation::cur())
                    - meta.query_advice(id.value, Rotation::prev())
            },
            is_id_unchanged_column,
        );
        let is_storage_key_unchanged = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(lexicographic_ordering.selector, Rotation::cur()),
            |meta| {
                meta.query_advice(storage_key.encoded, Rotation::cur())
                    - meta.query_advice(storage_key.encoded, Rotation::prev())
            },
            is_storage_key_unchanged_column,
        );

        let config = Self::Config {
            selector,
            sort_keys,
            is_write,
            is_id_unchanged,
            value,
            lexicographic_ordering,
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

        let is_id_unchanged = IsZeroChip::construct(config.is_id_unchanged.clone());
        let is_storage_key_unchanged =
            IsZeroChip::construct(config.is_storage_key_unchanged.clone());

        let tag_chip = BinaryNumberChip::construct(config.sort_keys.tag);

        layouter.assign_region(
            || "rw table",
            |mut region| {
                let rows = once(&Rw::Start).chain(&self.rows);
                let prev_rows = once(&Rw::Start).chain(rows.clone());
                for (offset, (row, prev_row)) in rows.zip(prev_rows).enumerate() {
                    region.assign_fixed(|| "selector", config.selector, offset, || Ok(F::one()))?;
                    config.sort_keys.rw_counter.assign(
                        &mut region,
                        offset,
                        row.rw_counter() as u32,
                    )?;
                    region.assign_advice(
                        || "is_write",
                        config.is_write,
                        offset,
                        || Ok(if row.is_write() { F::one() } else { F::zero() }),
                    )?;
                    tag_chip.assign(&mut region, offset, &row.tag())?;
                    if let Some(id) = row.id() {
                        config.sort_keys.id.assign(&mut region, offset, id as u32)?;
                    }
                    if let Some(address) = row.address() {
                        config
                            .sort_keys
                            .address
                            .assign(&mut region, offset, address)?;
                    }
                    if let Some(field_tag) = row.field_tag() {
                        region.assign_advice(
                            || "field_tag",
                            config.sort_keys.field_tag,
                            offset,
                            || Ok(F::from(field_tag as u64)),
                        )?;
                    }
                    if let Some(storage_key) = row.storage_key() {
                        config.sort_keys.storage_key.assign(
                            &mut region,
                            offset,
                            self.randomness,
                            storage_key,
                        )?;
                    }
                    region.assign_advice(
                        || "value",
                        config.value,
                        offset,
                        || Ok(row.value_assignment(self.randomness)),
                    )?;

                    if offset != 0 {
                        config
                            .lexicographic_ordering
                            .assign(&mut region, offset, row, prev_row)?;

                        let id_change = F::from(row.id().unwrap_or_default() as u64)
                            - F::from(prev_row.id().unwrap_or_default() as u64);
                        is_id_unchanged.assign(&mut region, offset, Some(id_change))?;

                        let storage_key_change = RandomLinearCombination::random_linear_combine(
                            row.storage_key().unwrap_or_default().to_le_bytes(),
                            self.randomness,
                        ) - RandomLinearCombination::random_linear_combine(
                            prev_row.storage_key().unwrap_or_default().to_le_bytes(),
                            self.randomness,
                        );
                        is_storage_key_unchanged.assign(
                            &mut region,
                            offset,
                            Some(storage_key_change),
                        )?;
                    }
                }

                #[cfg(test)]
                for ((column, offset), &f) in &self.overrides {
                    let advice_column = column.value(&config);
                    region.assign_advice(|| "override", advice_column, *offset, || Ok(f))?;
                }

                Ok(())
            },
        )
    }
}

fn queries<F: Field>(meta: &mut VirtualCells<'_, F>, c: &StateConfig<F>) -> Queries<F> {
    Queries {
        selector: meta.query_fixed(c.selector, Rotation::cur()),
        rw_counter: MpiQueries::new(meta, c.sort_keys.rw_counter),
        is_write: meta.query_advice(c.is_write, Rotation::cur()),
        tag: c.sort_keys.tag.value(Rotation::cur())(meta),
        tag_bits: c
            .sort_keys
            .tag
            .bits
            .map(|bit| meta.query_advice(bit, Rotation::cur())),
        id: MpiQueries::new(meta, c.sort_keys.id),
        is_id_unchanged: c.is_id_unchanged.is_zero_expression.clone(),
        address: MpiQueries::new(meta, c.sort_keys.address),
        field_tag: meta.query_advice(c.sort_keys.field_tag, Rotation::cur()),
        storage_key: RlcQueries::new(meta, c.sort_keys.storage_key),
        value: meta.query_advice(c.value, Rotation::cur()),
        lookups: LookupsQueries::new(meta, c.lookups),
        power_of_randomness: c
            .power_of_randomness
            .map(|c| meta.query_instance(c, Rotation::cur())),
        is_storage_key_unchanged: c.is_storage_key_unchanged.is_zero_expression.clone(),
        /* lexicographic_ordering_upper_limb_difference_is_zero: c
         *     .lexicographic_ordering
         *     .upper_limb_difference_is_zero
         *     .is_zero_expression
         *     .clone(), */
    }
}
