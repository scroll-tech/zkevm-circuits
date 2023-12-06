use crate::table::{CallContextFieldTag, LookupTable, UXTable};
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use itertools::Itertools;
use std::marker::PhantomData;
use strum::IntoEnumIterator;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    // Can these be TableColumn's?
    // https://github.com/zcash/halo2/blob/642efc1536d3ea2566b04814bd60a00c4745ae22/halo2_proofs/src/plonk/circuit.rs#L266
    u8_table: UXTable<8>,
    u10_table: UXTable<10>,
    u16_table: UXTable<16>,
    pub call_context_field_tag: Column<Fixed>,
}

impl Config {
    pub fn range_check_u16<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(msg, |meta| {
            let exp = exp_fn(meta);
            vec![exp]
                .into_iter()
                .zip_eq(self.u16_table.table_exprs(meta))
                .collect()
        });
    }
}

#[derive(Clone)]
pub struct Queries<F> {
    pub u8: Expression<F>,
    pub u10: Expression<F>,
    pub u16: Expression<F>,
    pub call_context_field_tag: Expression<F>,
}

impl<F: Field> Queries<F> {
    pub fn new(meta: &mut VirtualCells<'_, F>, c: Config) -> Self {
        Self {
            u8: c.u8_table.table_exprs(meta)[0].clone(),
            u10: c.u10_table.table_exprs(meta)[0].clone(),
            u16: c.u16_table.table_exprs(meta)[0].clone(),
            call_context_field_tag: meta.query_fixed(c.call_context_field_tag, Rotation::cur()),
        }
    }
}

pub struct Chip<F: Field> {
    config: Config,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> {
    pub fn construct(config: Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        u8_table: UXTable<8>,
        u10_table: UXTable<10>,
        u16_table: UXTable<16>,
    ) -> Config {
        let config = Config {
            u8_table,
            u10_table,
            u16_table,
            call_context_field_tag: meta.fixed_column(),
        };
        meta.annotate_lookup_any_column(config.call_context_field_tag, || {
            "LOOKUP_call_context_field_tag"
        });
        config
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.config.u8_table.load(layouter)?;
        self.config.u10_table.load(layouter)?;
        self.config.u16_table.load(layouter)?;
        layouter.assign_region(
            || "assign call_context_field_tags fixed column",
            |mut region| {
                for field_tag in CallContextFieldTag::iter() {
                    region.assign_fixed(
                        || format!("assign {field_tag:?} in call_context_field_tag fixed column"),
                        self.config.call_context_field_tag,
                        field_tag as usize,
                        || Value::known(F::from(field_tag as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}
