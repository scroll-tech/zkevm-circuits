//! The state circuit implementation.
mod constraint_builder;
mod lexicographic_ordering;
mod lookups;
mod multiple_precision_integer;
mod random_linear_combination;
#[cfg(test)]
mod test;

use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        util::RandomLinearCombination,
        witness::{RwMap, RwRow},
    },
    rw_table::RwTable,
    util::DEFAULT_RAND,
};
use constraint_builder::{ConstraintBuilder, Queries};
use eth_types::{Address, Field, ToLittleEndian};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner},
    plonk::{Circuit, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use lexicographic_ordering::{
    Chip as LexicographicOrderingChip, Config as LexicographicOrderingConfig,
};
use lookups::{Chip as LookupsChip, Config as LookupsConfig, Queries as LookupsQueries};
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig, Queries as MpiQueries};
use random_linear_combination::{Chip as RlcChip, Config as RlcConfig, Queries as RlcQueries};
#[cfg(test)]
use std::collections::HashMap;

const N_LIMBS_RW_COUNTER: usize = 2;
const N_LIMBS_ACCOUNT_ADDRESS: usize = 10;
const N_LIMBS_ID: usize = 2;

/// Config for StateCircuit
#[derive(Clone)]
pub struct StateConfig<F, const QUICK_CHECK: bool> {
    // Figure out why you get errors when this is Selector.
    // https://github.com/appliedzkp/zkevm-circuits/issues/407
    selector: Column<Fixed>,
    rw_table: RwTable,
    rw_counter_mpi: MpiConfig<u32, N_LIMBS_RW_COUNTER>,
    id_mpi: MpiConfig<u32, N_LIMBS_ID>,
    address_mpi: MpiConfig<Address, N_LIMBS_ACCOUNT_ADDRESS>,
    storage_key_rlc: RlcConfig<N_BYTES_WORD>,
    is_id_unchanged: IsZeroConfig<F>,
    is_storage_key_unchanged: IsZeroConfig<F>,
    lookups: LookupsConfig<QUICK_CHECK>,
    power_of_randomness: [Expression<F>; 31],
    lexicographic_ordering: LexicographicOrderingConfig<F>,
}

type Lookup<F> = (&'static str, Expression<F>, Expression<F>);

/// State Circuit for proving RwTable is valid
pub type StateCircuit<F> = StateCircuitBase<F, false>;
/// StateCircuit with lexicographic ordering u16 lookup disabled to allow
/// smaller `k`. It is almost impossible to trigger u16 lookup verification
/// error. So StateCircuitLight can be used in opcode gadgets test.
/// Normal opcodes constaints error can still be captured but cost much less
/// time.
pub type StateCircuitLight<F> = StateCircuitBase<F, true>;

/// State Circuit for proving RwTable is valid
#[derive(Default, Clone)]
pub struct StateCircuitBase<F, const QUICK_CHECK: bool> {
    pub(crate) randomness: F,
    pub(crate) rows: Vec<RwRow<F>>,
    #[cfg(test)]
    overrides: HashMap<(test::AdviceColumn, usize), F>,
}

impl<F: Field, const QUICK_CHECK: bool> StateCircuitBase<F, QUICK_CHECK> {
    /// make a new state circuit from an RwMap
    pub fn new(randomness: F, rw_map: RwMap) -> Self {
        let rows = rw_map.table_assignments(randomness);
        Self {
            randomness,
            rows,
            #[cfg(test)]
            overrides: HashMap::new(),
        }
    }
    /// estimate k needed to prover
    pub fn estimate_k(&self) -> u32 {
        let log2_ceil = |n| u32::BITS - (n as u32).leading_zeros() - (n & (n - 1) == 0) as u32;
        let k = if QUICK_CHECK { 12 } else { 18 };
        let k = k.max(log2_ceil(64 + self.rows.len()));
        log::debug!("state circuit uses k = {}", k);
        k
    }

    /// powers of randomness for instance columns
    pub fn instance(&self) -> Vec<Vec<F>> {
        (1..32)
            .map(|exp| vec![self.randomness.pow(&[exp, 0, 0, 0]); self.rows.len() + 1])
            .collect()
    }
    #[allow(clippy::too_many_arguments)]
    fn assign_row(
        &self,
        config: &StateConfig<F, QUICK_CHECK>,
        region: &mut Region<F>,
        is_storage_key_unchanged: &IsZeroChip<F>,
        is_id_unchanged: &IsZeroChip<F>,
        lexicographic_ordering_chip: &LexicographicOrderingChip<F>,
        offset: usize,
        row: RwRow<F>,
        prev_row: Option<RwRow<F>>,
    ) -> Result<(), Error> {
        region.assign_fixed(|| "selector", config.selector, offset, || Ok(F::one()))?;

        config
            .rw_counter_mpi
            .assign(region, offset, row.rw_counter as u32)?;
        config.id_mpi.assign(region, offset, row.id as u32)?;
        config.address_mpi.assign(region, offset, row.address)?;
        config
            .storage_key_rlc
            .assign(region, offset, self.randomness, row.storage_key)?;

        if offset != 0 {
            lexicographic_ordering_chip.assign(region, offset, &row, &prev_row.unwrap())?;

            // assign storage key diff
            let cur_storage_key = RandomLinearCombination::random_linear_combine(
                row.storage_key.to_le_bytes(),
                self.randomness,
            );
            let prev_storage_key = RandomLinearCombination::random_linear_combine(
                prev_row.unwrap_or_default().storage_key.to_le_bytes(),
                self.randomness,
            );
            is_storage_key_unchanged.assign(
                region,
                offset,
                Some(cur_storage_key - prev_storage_key),
            )?;

            // assign id diff
            let id_change =
                F::from(row.id as u64) - F::from(prev_row.unwrap_or_default().id as u64);
            is_id_unchanged.assign(region, offset, Some(id_change))?;
            let _storage_key_change = RandomLinearCombination::random_linear_combine(
                row.storage_key.to_le_bytes(),
                self.randomness,
            ) - RandomLinearCombination::random_linear_combine(
                prev_row.unwrap_or_default().storage_key.to_le_bytes(),
                self.randomness,
            );
        }

        Ok(())
    }
}

impl<F: Field, const QUICK_CHECK: bool> Circuit<F> for StateCircuitBase<F, QUICK_CHECK> {
    type Config = StateConfig<F, QUICK_CHECK>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let selector = meta.fixed_column();
        let lookups = LookupsChip::configure(meta);
        //let power_of_randomness = [0; N_BYTES_WORD - 1].map(|_|
        // meta.instance_column());

        let power_of_randomness: [Expression<F>; 31] = (1..32)
            .map(|exp| Expression::Constant(F::from_u128(DEFAULT_RAND).pow(&[exp, 0, 0, 0])))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let rw_table = RwTable::construct(meta);
        let is_storage_key_unchanged_column = meta.advice_column();
        let is_id_unchanged_column = meta.advice_column();
        let id_mpi = MpiChip::configure(meta, rw_table.id, selector, lookups);
        let address_mpi = MpiChip::configure(meta, rw_table.address, selector, lookups);
        let storage_key_rlc = RlcChip::configure(
            meta,
            selector,
            rw_table.storage_key,
            lookups,
            power_of_randomness.clone(),
        );
        let rw_counter_mpi = MpiChip::configure(meta, rw_table.rw_counter, selector, lookups);

        let lexicographic_ordering = LexicographicOrderingChip::configure(
            meta,
            rw_table.tag,
            rw_table.field_tag,
            id_mpi.limbs,
            address_mpi.limbs,
            storage_key_rlc.bytes,
            rw_counter_mpi.limbs,
            lookups,
        );

        let is_id_unchanged = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(lexicographic_ordering.selector, Rotation::cur()),
            |meta| {
                meta.query_advice(rw_table.id, Rotation::cur())
                    - meta.query_advice(rw_table.id, Rotation::prev())
            },
            is_id_unchanged_column,
        );
        let is_storage_key_unchanged = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(lexicographic_ordering.selector, Rotation::cur()),
            |meta| {
                meta.query_advice(rw_table.storage_key, Rotation::cur())
                    - meta.query_advice(rw_table.storage_key, Rotation::prev())
            },
            is_storage_key_unchanged_column,
        );

        let config = Self::Config {
            selector,
            rw_table,
            lexicographic_ordering,
            address_mpi,
            id_mpi,
            rw_counter_mpi,
            storage_key_rlc,
            is_id_unchanged,
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
        let lexicographic_ordering_chip =
            LexicographicOrderingChip::construct(config.lexicographic_ordering.clone());

        layouter.assign_region(
            || "rw table",
            |mut region| {
                config
                    .rw_table
                    .assign(&mut region, self.randomness, &self.rows)?;

                for (offset, row) in self.rows.iter().enumerate() {
                    log::trace!("state citcuit assign offset:{} row:{:#?}", offset, row);
                    self.assign_row(
                        &config,
                        &mut region,
                        &is_storage_key_unchanged,
                        &is_id_unchanged,
                        &lexicographic_ordering_chip,
                        offset,
                        *row,
                        if offset == 0 {
                            None
                        } else {
                            Some(self.rows[offset - 1])
                        },
                    )?;
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

fn queries<F: Field, const QUICK_CHECK: bool>(
    meta: &mut VirtualCells<'_, F>,
    c: &StateConfig<F, QUICK_CHECK>,
) -> Queries<F> {
    Queries {
        selector: meta.query_fixed(c.selector, Rotation::cur()),
        rw_counter: MpiQueries::new(meta, c.rw_counter_mpi),
        is_write: meta.query_advice(c.rw_table.is_write, Rotation::cur()),
        aux2: meta.query_advice(c.rw_table.aux2, Rotation::cur()),
        tag: meta.query_advice(c.rw_table.tag, Rotation::cur()),
        prev_tag: meta.query_advice(c.rw_table.tag, Rotation::prev()),
        id: MpiQueries::new(meta, c.id_mpi),
        is_id_unchanged: c.is_id_unchanged.is_zero_expression.clone(),
        address: MpiQueries::new(meta, c.address_mpi),
        field_tag: meta.query_advice(c.rw_table.field_tag, Rotation::cur()),
        storage_key: RlcQueries::new(meta, c.storage_key_rlc),
        value: meta.query_advice(c.rw_table.value, Rotation::cur()),
        value_at_prev_rotation: meta.query_advice(c.rw_table.value, Rotation::prev()),
        value_prev: meta.query_advice(c.rw_table.value_prev, Rotation::cur()),
        lookups: LookupsQueries::new(meta, c.lookups),
        power_of_randomness: c.power_of_randomness.clone(),
        is_storage_key_unchanged: c.is_storage_key_unchanged.is_zero_expression.clone(),
        lexicographic_ordering_upper_limb_difference_is_zero: c
            .lexicographic_ordering
            .upper_limb_difference_is_zero
            .is_zero_expression
            .clone(),
        rw_rlc: meta.query_advice(c.rw_table.rlc, Rotation::cur()),
    }
}
