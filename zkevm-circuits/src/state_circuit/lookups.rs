use crate::evm_circuit::table::CallContextFieldTag;
use eth_types::Field;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;
use strum::IntoEnumIterator;

#[derive(Clone, Copy)]
pub struct Config<const QUICK_CHECK: bool> {
    // Can these be TableColumn's?
    // https://github.com/zcash/halo2/blob/642efc1536d3ea2566b04814bd60a00c4745ae22/halo2_proofs/src/plonk/circuit.rs#L266
    u8: Column<Fixed>,
    u10: Column<Fixed>,
    u16: Column<Fixed>,
    pub call_context_field_tag: Column<Fixed>,
}

impl<const QUICK_CHECK: bool> Config<QUICK_CHECK> {
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
        if !QUICK_CHECK {
            meta.lookup_any(msg, |meta| {
                let exp = exp_fn(meta);
                vec![(exp, meta.query_fixed(self.u16, Rotation::cur()))]
            });
        } else {
            log::debug!(
                "{} u16 range check is skipped because `QUICK_CHECK` is enabled",
                msg
            );
        }
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
    pub fn new<const QUICK_CHECK: bool>(
        meta: &mut VirtualCells<'_, F>,
        c: Config<QUICK_CHECK>,
    ) -> Self {
        Self {
            u8: meta.query_fixed(c.u8, Rotation::cur()),
            u10: meta.query_fixed(c.u10, Rotation::cur()),
            u16: meta.query_fixed(c.u16, Rotation::cur()),
            call_context_field_tag: meta.query_fixed(c.call_context_field_tag, Rotation::cur()),
        }
    }
}

pub struct Chip<F: Field, const QUICK_CHECK: bool> {
    config: Config<QUICK_CHECK>,
    _marker: PhantomData<F>,
}

impl<F: Field, const QUICK_CHECK: bool> Chip<F, QUICK_CHECK> {
    pub fn construct(config: Config<QUICK_CHECK>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Config<QUICK_CHECK> {
        Config {
            u8: meta.fixed_column(),
            u10: meta.fixed_column(),
            u16: meta.fixed_column(),
            call_context_field_tag: meta.fixed_column(),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let mut columns = vec![(self.config.u8, 8), (self.config.u10, 10)];
        if !QUICK_CHECK {
            columns.push((self.config.u16, 16));
        }
        for (column, exponent) in columns {
            layouter.assign_region(
                || format!("assign u{} fixed column", exponent),
                |mut region| {
                    for i in 0..(1 << exponent) {
                        region.assign_fixed(
                            || format!("assign {} in u{} fixed column", i, exponent),
                            column,
                            i,
                            || Ok(F::from(i as u64)),
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
                        || {
                            format!(
                                "assign {:?} in call_context_field_tag fixed column",
                                field_tag
                            )
                        },
                        self.config.call_context_field_tag,
                        field_tag as usize,
                        || Ok(F::from(field_tag as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
