use crate::table::CallContextFieldTag;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;
use strum::IntoEnumIterator;

#[derive(Clone, Copy, Debug)]
pub struct Config {
    // Can these be TableColumn's?
    // https://github.com/zcash/halo2/blob/642efc1536d3ea2566b04814bd60a00c4745ae22/halo2_proofs/src/plonk/circuit.rs#L266
    u8: Column<Fixed>,
    u10: Column<Fixed>,
    u16: Column<Fixed>,
    pub call_context_field_tag: Column<Fixed>,
}

impl Config {
    pub fn range_check_u8<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(msg, |meta| {
            let exp = exp_fn(meta);
            vec![(exp, meta.query_fixed(self.u8, Rotation::cur()))]
        });
    }
    pub fn range_check_u10<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(msg, |meta| {
            let exp = exp_fn(meta);
            vec![(exp, meta.query_fixed(self.u10, Rotation::cur()))]
        });
    }
    pub fn range_check_u16<F: Field>(
        &self,
        meta: &mut ConstraintSystem<F>,
        msg: &'static str,
        exp_fn: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(msg, |meta| {
            let exp = exp_fn(meta);
            vec![(exp, meta.query_fixed(self.u16, Rotation::cur()))]
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
            u8: meta.query_fixed(c.u8, Rotation::cur()),
            u10: meta.query_fixed(c.u10, Rotation::cur()),
            u16: meta.query_fixed(c.u16, Rotation::cur()),
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

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        let config = Config {
            u8: meta.fixed_column(),
            u10: meta.fixed_column(),
            u16: meta.fixed_column(),
            call_context_field_tag: meta.fixed_column(),
        };
        meta.annotate_lookup_any_column(config.u8, || "LOOKUP_u8");
        meta.annotate_lookup_any_column(config.u10, || "LOOKUP_u10");
        meta.annotate_lookup_any_column(config.u16, || "LOOKUP_u16");
        meta.annotate_lookup_any_column(config.call_context_field_tag, || {
            "LOOKUP_call_context_field_tag"
        });
        config
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (column, exponent) in [
            (self.config.u8, 8),
            (self.config.u10, 10),
            (self.config.u16, 16),
        ] {
            layouter.assign_region(
                || format!("assign u{exponent} fixed column"),
                |mut region| {
                    for i in 0..(1 << exponent) {
                        region.assign_fixed(
                            || format!("assign {i} in u{exponent} fixed column"),
                            column,
                            i,
                            || Value::known(F::from(i as u64)),
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
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
