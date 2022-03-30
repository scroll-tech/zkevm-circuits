use crate::evm_circuit::param::N_BYTES_WORD;
use crate::evm_circuit::witness::RwMap;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::plonk::Circuit;
use eth_types::{Address, ToScalar, Field};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, Error, Selector},
};

mod cell;
mod lookup_columns;
mod multiple_precision_integer;
mod random_linear_combination;
#[cfg(test)]
mod tests;

use cell::{AdviceCell, FixedCell, InstanceCell};
use lookup_columns::{Chip as LcChip, Config as LcConfig};
use multiple_precision_integer::{Chip as MpiChip, Config as MpiConfig};
use random_linear_combination::{Chip as RlcChip, Config as RlcConfig};

const N_LIMBS_RW_COUNTER: usize = 2;
const N_LIMBS_ACCOUNT_ADDRESS: usize = 10;

#[derive(Clone)]
struct StateConfig<F: Field> {
    selector: FixedCell<F>,
    rw_counter: MpiConfig<F, u32, N_LIMBS_RW_COUNTER>,
    is_write: AdviceCell<F>,
    tag: AdviceCell<F>,
    id: AdviceCell<F>,
    address: MpiConfig<F, Address, N_LIMBS_ACCOUNT_ADDRESS>,
    field_tag: AdviceCell<F>,
    storage_key: RlcConfig<F, N_BYTES_WORD>,
    value: AdviceCell<F>,
    lookup_columns: LcConfig<F>,
    power_of_randomness: [InstanceCell<F>; N_BYTES_WORD - 1],
    // lexicographic_ordering config, etc.
}

#[derive(Default)]
struct StateCircuit<F: Field> {
    pub randomness: F,
    pub rw_map: RwMap,
}

impl<F: Field> Circuit<F> for StateCircuit<F> {
    type Config = StateConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let lookup_columns = LcChip::configure(meta);
        let power_of_randomness = [0; N_BYTES_WORD - 1].map(|_| InstanceCell::new(meta));
        let selector = FixedCell::new(meta);

        Self::Config {
            rw_counter: MpiChip::configure(meta, selector.cur.clone(), lookup_columns.u8_range()),
            is_write: AdviceCell::new(meta),
            tag: AdviceCell::new(meta),
            id: AdviceCell::new(meta),
            address: MpiChip::configure(meta, selector.cur.clone(), lookup_columns.u8_range()),
            field_tag: AdviceCell::new(meta),
            storage_key: RlcChip::configure(
                meta,
                selector.cur.clone(),
                lookup_columns.u8_range(),
                &power_of_randomness.clone().map(|c| c.cur),
            ),
            value: AdviceCell::new(meta),
            selector,
            lookup_columns,
            power_of_randomness,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        // Is this clone ok?
        LcChip::construct(config.lookup_columns.clone()).load(&mut layouter)?;

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
                    region.assign_fixed(
                        || "assign 1 to selector",
                        config.selector.column,
                        offset,
                        || Ok(F::one()),
                    )?;

                    config.rw_counter.assign(&mut region, offset, row.rw_counter() as u32);
                    config
                        .is_write
                        .assign(&mut region, offset, F::from(row.is_write() as u64));
                    config
                        .tag
                        .assign(&mut region, offset, F::from(row.tag() as u64));
                    config.id.assign(
                        &mut region,
                        offset,
                        F::from(row.id().unwrap_or_default() as u64),
                    );
                    config.field_tag.assign(
                        &mut region,
                        offset,
                        F::from(row.field_tag().unwrap_or_default()),
                    );
                    // self.address.assign(region, offset, rw.key_2);
                    // self.field_tag.assign(region, offset, rw.key_3);
                    // self.storage_key.assign(region, offset, rw.key_4);

                    offset += 1;
                }
                Ok(())
            },
        )
    }
}
