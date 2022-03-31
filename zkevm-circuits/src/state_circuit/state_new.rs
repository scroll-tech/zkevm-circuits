use crate::evm_circuit::{
    param::N_BYTES_WORD, table::RwTableTag, util::constraint_builder::BaseConstraintBuilder,
    util::math_gadget::generate_lagrange_base_polynomial, witness::RwMap,
};
use crate::util::Expr;
use eth_types::{Address, Field};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};
use strum::IntoEnumIterator;

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

impl<F: Field> StateConfig<F> {
    pub fn matches(&self, tag: RwTableTag) -> Expression<F> {
        generate_lagrange_base_polynomial(
            self.tag.cur(),
            tag as usize,
            RwTableTag::iter().map(|x| x as usize),
        )
    }

    fn add_general_constraints(&self, cb: &mut BaseConstraintBuilder<F>) {
        cb.require_in_set(
            "tag in RwTableTag range",
            self.tag.cur.clone(),
            RwTableTag::iter().map(|x| x.expr()).collect(),
        );
    }

    fn configure_start(&self, cb: &mut BaseConstraintBuilder<F>) {
        cb.require_zero("rw_counter starts at 0", self.rw_counter.value.cur());
        cb.require_zero("tag is 0 at start", self.tag.cur())
    }

    fn configure_memory(&self, cb: &mut BaseConstraintBuilder<F>) {
        cb.require_zero("field_tag is 0 for MemoryOp", self.field_tag.cur());
        cb.require_zero(
            "storage_key is 0 for MemoryOp",
            self.storage_key.encoded.cur(),
        );
        // # 1. First access for a set of all keys
        //  #
        //  # When the set of all keys changes (first access of an address in a call)
        //  # - If READ, value must be 0
        for i in 2..N_LIMBS_ACCOUNT_ADDRESS {
            cb.require_zero(
                "memory address is at most 2 limbs",
                self.address.limbs[i].cur(),
            )
        }
        // lookup self.value.cur is in u8 range.
    }

    fn configure_stack(&self, cb: &mut BaseConstraintBuilder<F>) {
        cb.require_zero("field_tag is 0 for StackOp", self.field_tag.cur.clone());
        cb.require_zero(
            "storage_key is 0 for StackOp",
            self.storage_key.encoded.cur.clone(),
        );
        // # 1. First access for a set of all keys
        //  #
        //  # When the set of all keys changes (first access of an address in a call)
        //  # - If READ, value must be 0
        for i in 2..N_LIMBS_ACCOUNT_ADDRESS {
            cb.require_zero(
                "memory address is at most 2 limbs",
                self.address.limbs[i].cur.clone(),
            )
        }
        // lookup self.address.cur is in u10 range.

        cb.require_boolean(
            "stack pointer change is 0 or 1",
            self.address.value.change(),
        );
    }

    fn configure_account_storage(&self, cb: &mut BaseConstraintBuilder<F>) {
        // Unused keys are 0
        for (name, expression) in [
            // Moved tx_id from aux to id column, so this no longer is true.
            // ("0 id for Storage ", self.id.cur()),
            ("0 field_tag for Storage", self.field_tag.cur()),
        ] {
            cb.require_zero(name, expression);
        }
    }

    fn configure_call_context(&self, cb: &mut BaseConstraintBuilder<F>) {
        // Unused keys are 0
        for (name, expression) in [
            ("0 address for Account ", self.address.value.cur()),
            ("0 storage_key for Account", self.storage_key.encoded.cur()),
        ] {
            cb.require_zero(name, expression);
        }
    }

    fn configure_account(&self, cb: &mut BaseConstraintBuilder<F>) {
        // Unused keys are 0
        for (name, expression) in [
            ("0 id for Account ", self.id.cur()),
            ("0 storage_key for Account", self.storage_key.encoded.cur()),
        ] {
            cb.require_zero(name, expression);
        }
    }

    fn configure_tx_refund(&self, cb: &mut BaseConstraintBuilder<F>) {
        // Unused keys are 0
        for (name, expression) in [
            ("0 address for TxRefund ", self.address.value.cur()),
            ("0 field_tag for TxRefund", self.field_tag.cur()),
            ("0 storage_key for TxRefund", self.storage_key.encoded.cur()),
        ] {
            cb.require_zero(name, expression);
        }
        // TODO: add more constraints in state spec.
    }

    fn configure_tx_access_list_account(&self, cb: &mut BaseConstraintBuilder<F>) {
        // Unused keys are 0
        for (name, expression) in [
            ("0 field_tag for TxAccessListAccount", self.field_tag.cur()),
            (
                "0 storage_key for TxAccessListAccount",
                self.storage_key.encoded.cur(),
            ),
        ] {
            cb.require_zero(name, expression);
        }
        // TODO: add more constraints in state spec.
    }

    fn configure_tx_access_list_account_storage(&self, cb: &mut BaseConstraintBuilder<F>) {
        // Unused key is 0
        cb.require_zero(
            "0 field_tag for TxAccessListAccountStorage",
            self.storage_key.encoded.cur(),
        );
        // TODO: add more constraints in state spec.
    }

    fn configure_account_destructed(&self, cb: &mut BaseConstraintBuilder<F>) {
        // Unused keys are 0
        for (name, expression) in [
            ("0 id for AccountDestructed", self.id.cur()),
            ("0 address for AccountDestructed", self.address.value.cur()),
            (
                "0 storage_key for AccountDestructed",
                self.storage_key.encoded.cur(),
            ),
        ] {
            cb.require_zero(name, expression);
        }
        // TODO: add more constraints in state spec.
    }
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

        // maybe this will not be needed with Selector instead of column<fixed>?
        let selector_expression = selector.cur.clone();

        let config = Self::Config {
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
        };

        let mut cb = BaseConstraintBuilder::new(30); // TODO: use correct max degree;
        config.add_general_constraints(&mut cb);
        cb.condition(config.matches(RwTableTag::Start), |cb| {
            config.configure_start(cb)
        });
        cb.condition(config.matches(RwTableTag::Memory), |cb| {
            config.configure_memory(cb)
        });
        cb.condition(config.matches(RwTableTag::Stack), |cb| {
            config.configure_stack(cb)
        });
        cb.condition(config.matches(RwTableTag::AccountStorage), |cb| {
            config.configure_account_storage(cb)
        });
        cb.condition(config.matches(RwTableTag::TxAccessListAccount), |cb| {
            config.configure_tx_access_list_account(cb)
        });
        cb.condition(
            config.matches(RwTableTag::TxAccessListAccountStorage),
            |cb| config.configure_tx_access_list_account_storage(cb),
        );
        cb.condition(config.matches(RwTableTag::TxRefund), |cb| {
            config.configure_tx_refund(cb)
        });
        cb.condition(config.matches(RwTableTag::Account), |cb| {
            config.configure_account(cb)
        });
        cb.condition(config.matches(RwTableTag::AccountDestructed), |cb| {
            config.configure_account_destructed(cb)
        });
        cb.condition(config.matches(RwTableTag::CallContext), |cb| {
            config.configure_call_context(cb)
        });
        meta.create_gate("state circuit constraints", |_| {
            cb.gate(selector_expression)
        });

        config
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

                    config
                        .rw_counter
                        .assign(&mut region, offset, row.rw_counter() as u32)?;
                    config
                        .is_write
                        .assign(&mut region, offset, F::from(row.is_write() as u64))?;
                    config
                        .tag
                        .assign(&mut region, offset, F::from(row.tag() as u64))?;
                    if let Some(id) = row.id() {
                        config.id.assign(&mut region, offset, F::from(id as u64))?;
                    }
                    if let Some(address) = row.address() {
                        config.address.assign(&mut region, offset, address)?;
                    }
                    if let Some(field_tag) = row.field_tag() {
                        config
                            .field_tag
                            .assign(&mut region, offset, F::from(field_tag))?;
                    }
                    if let Some(storage_key) = row.storage_key() {
                        config.storage_key.assign(
                            &mut region,
                            offset,
                            self.randomness,
                            storage_key,
                        )?;
                    }

                    offset += 1;
                }
                Ok(())
            },
        )
    }
}
