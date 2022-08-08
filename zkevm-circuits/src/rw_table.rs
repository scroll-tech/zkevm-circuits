#![allow(missing_docs)]
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::{
    circuit::{Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use crate::evm_circuit::{
    util::RandomLinearCombination,
    witness::{RwMap, RwRow},
};
use crate::{evm_circuit::util::rlc, table::LookupTable};

#[derive(Clone, Copy)]
pub struct RwTableRlc {
    // TODO: change to instance col?
    pub rlc: Column<Advice>,
}

impl<F: Field> LookupTable<F> for RwTableRlc {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        vec![meta.query_advice(self.rlc, Rotation::cur())]
    }
}
impl RwTableRlc {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            rlc: meta.advice_column(),
        }
    }
    /// Assign the `RwTable` from a `RwMap`, followig the same
    /// table layout that the State Circuit uses.
    pub fn load<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        rws: &RwMap,
        randomness: F,
        n_rows: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "rw table",
            |mut region| self.assign(&mut region, randomness, rws, randomness, n_rows),
        )
    }
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        randomness: F,
        rw_map: &RwMap,
        randomness_next_phase: F,
        n_rows: usize,
    ) -> Result<(), Error> {
        let rows = rw_map.table_assignments();
        let (rows, _) = RwMap::table_assignments_prepad(rows, n_rows);
        for (offset, row) in rows.iter().enumerate() {
            let value = row
                .table_assignment(randomness)
                .rlc(randomness, randomness_next_phase);
            region.assign_advice(
                || "assign rw row on rw table",
                self.rlc,
                offset,
                || Ok(value),
            )?;
        }
        Ok(())
    }
}

/// The rw table shared between evm circuit and state circuit
#[derive(Clone, Copy)]
pub struct RwTable {
    pub rlc: Column<Advice>,
    pub rw_counter: Column<Advice>,
    pub is_write: Column<Advice>,
    pub tag: Column<Advice>,
    pub id: Column<Advice>,
    pub address: Column<Advice>,
    pub field_tag: Column<Advice>,
    pub storage_key: Column<Advice>,
    pub value: Column<Advice>,
    pub value_prev: Column<Advice>,
    pub aux1: Column<Advice>,
    pub aux2: Column<Advice>,
}

impl RwTable {
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            rlc: meta.advice_column(),
            rw_counter: meta.advice_column(),
            is_write: meta.advice_column(),
            tag: meta.advice_column(),
            id: meta.advice_column(),
            address: meta.advice_column(),
            field_tag: meta.advice_column(),
            storage_key: meta.advice_column(),
            value: meta.advice_column(),
            value_prev: meta.advice_column(),
            aux1: meta.advice_column(),
            aux2: meta.advice_column(),
        }
    }

    fn rlc_expr<F: Field>(
        &self,
        meta: &mut VirtualCells<F>,
        power_of_randomness: &[Expression<F>],
    ) -> Expression<F> {
        rlc::expr(
            &[
                meta.query_advice(self.rw_counter, Rotation::cur()),
                meta.query_advice(self.is_write, Rotation::cur()),
                meta.query_advice(self.tag, Rotation::cur()),
                meta.query_advice(self.id, Rotation::cur()),
                meta.query_advice(self.address, Rotation::cur()),
                meta.query_advice(self.field_tag, Rotation::cur()),
                meta.query_advice(self.storage_key, Rotation::cur()),
                meta.query_advice(self.value, Rotation::cur()),
                meta.query_advice(self.value_prev, Rotation::cur()),
                meta.query_advice(self.aux1, Rotation::cur()),
                meta.query_advice(self.aux2, Rotation::cur()),
            ],
            power_of_randomness,
        )
    }
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        randomness: F,
        rows: &[RwRow<F>],
    ) -> Result<(), Error> {
        for (offset, row) in rows.iter().enumerate() {
            self.assign_row(region, offset, randomness, row)?;
        }
        for (offset, row) in rows.iter().enumerate() {
            let value = row.rlc(randomness, randomness);
            region.assign_advice(
                || "assign rw row on rw table",
                self.rlc,
                offset,
                || Ok(value),
            )?;
        }
        Ok(())
    }
    pub fn assign_row<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        randomness: F,
        row: &RwRow<F>,
    ) -> Result<(), Error> {
        for (column, value) in [
            (self.rw_counter, F::from(row.rw_counter)),
            (self.is_write, F::from(row.is_write)),
            (self.tag, F::from(row.tag as u64)),
            (self.id, F::from(row.id)),
            (self.address, (row.address.to_scalar().unwrap())),
            (self.field_tag, F::from(row.field_tag)),
            (
                self.storage_key,
                RandomLinearCombination::random_linear_combine(
                    row.storage_key.to_le_bytes(),
                    randomness,
                ),
            ),
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
