#![allow(missing_docs)]
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use crate::evm_circuit::{table::LookupTable, witness::RwRow};

#[derive(Clone, Copy)]
pub struct RwTableRlc {
    pub rlc: Column<Advice>,
}

impl<F: FieldExt> LookupTable<F> for RwTableRlc {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![meta.query_advice(self.rlc, Rotation::cur())]
    }
}
impl RwTableRlc {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            rlc: meta.advice_column(),
        }
    }
    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &RwRow<F>,
        randomness: F,
    ) -> Result<(), Error> {
        let values = [
            row.rw_counter,
            row.is_write,
            row.tag,
            row.key1,
            row.key2,
            row.key3,
            row.key4,
            row.value,
            row.value_prev,
            row.aux1,
            row.aux2,
        ];
        let value = values
            .iter()
            .rev()
            .fold(F::zero(), |acc, value| acc * randomness + value);
        region.assign_advice(
            || "assign rw row on rw table",
            self.rlc,
            offset,
            || Ok(value),
        )?;
        Ok(())
    }
}

/// The rw table shared between evm circuit and state circuit
#[derive(Clone, Copy)]
pub struct RwTable {
    pub rw_counter: Column<Advice>,
    pub is_write: Column<Advice>,
    pub tag: Column<Advice>,
    pub key1: Column<Advice>,
    pub key2: Column<Advice>,
    pub key3: Column<Advice>,
    pub key4: Column<Advice>,
    pub value: Column<Advice>,
    pub value_prev: Column<Advice>,
    pub aux1: Column<Advice>,
    pub aux2: Column<Advice>,
}

impl<F: FieldExt> LookupTable<F> for RwTable {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![
            meta.query_advice(self.rw_counter, Rotation::cur()),
            meta.query_advice(self.is_write, Rotation::cur()),
            meta.query_advice(self.tag, Rotation::cur()),
            meta.query_advice(self.key1, Rotation::cur()),
            meta.query_advice(self.key2, Rotation::cur()),
            meta.query_advice(self.key3, Rotation::cur()),
            meta.query_advice(self.key4, Rotation::cur()),
            meta.query_advice(self.value, Rotation::cur()),
            meta.query_advice(self.value_prev, Rotation::cur()),
            meta.query_advice(self.aux1, Rotation::cur()),
            meta.query_advice(self.aux2, Rotation::cur()),
        ]
    }
}
impl RwTable {
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            tag: meta.advice_column(),
            key1: meta.advice_column(),
            key2: meta.advice_column(),
            key3: meta.advice_column(),
            key4: meta.advice_column(),
            value: meta.advice_column(),
            value_prev: meta.advice_column(),
            aux1: meta.advice_column(),
            aux2: meta.advice_column(),
        }
    }
    pub fn assign<F: FieldExt>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &RwRow<F>,
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.rw_counter, row.rw_counter),
            (self.is_write, row.is_write),
            (self.tag, row.tag),
            (self.key1, row.key1),
            (self.key2, row.key2),
            (self.key3, row.key3),
            (self.key4, row.key4),
            (self.value, row.value),
            (self.value_prev, row.value_prev),
            (self.aux1, row.aux1),
            (self.aux2, row.aux2),
        ] {
            region.assign_advice(|| "assign rw row on rw table", column, offset, || Ok(value))?;
        }
        Ok(())
    }
}
