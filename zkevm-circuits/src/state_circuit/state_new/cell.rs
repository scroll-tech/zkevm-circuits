use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Instance},
    poly::Rotation,
};

use crate::util::Expr;

// TODO: maybe a macro for these?
// TODO: it's better to only add the queries as needed.
#[derive(Clone, Debug)]
pub struct AdviceCell<F: Field> {
    pub column: Column<Advice>,
    pub cur: Expression<F>,
    pub prev: Expression<F>,
}

#[derive(Clone, Debug)]
pub struct FixedCell<F: Field> {
    pub column: Column<Fixed>,
    pub cur: Expression<F>,
    pub prev: Expression<F>, // doesn't make sense to have this for fixed and instance cells?
}

#[derive(Clone, Debug)]
pub struct InstanceCell<F: Field> {
    pub column: Column<Instance>,
    pub cur: Expression<F>,
    pub prev: Expression<F>,
}

impl<F: Field> AdviceCell<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let column = meta.advice_column();
        let mut cells = vec![];
        meta.create_gate("new_cell", |meta| {
            cells.push(Self {
                column,
                cur: meta.query_any(column, Rotation::cur()),
                prev: meta.query_any(column, Rotation::prev()),
            });
            vec![0.expr()] // can this be empty?
        });
        cells.pop().unwrap()
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: F,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || format!("assign advice cell"),
            self.column,
            offset,
            || Ok(value),
        )
    }
}

impl<F: Field> FixedCell<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let column = meta.fixed_column();
        let mut cells = vec![];
        meta.create_gate("new_cell", |meta| {
            cells.push(Self {
                column,
                cur: meta.query_any(column, Rotation::cur()),
                prev: meta.query_any(column, Rotation::prev()),
            });
            vec![0.expr()] // can this be empty?
        });
        cells.pop().unwrap()
    }
}

impl<F: Field> InstanceCell<F> {
    pub fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let column = meta.instance_column();
        let mut cells = vec![];
        meta.create_gate("new_cell", |meta| {
            cells.push(Self {
                column,
                cur: meta.query_any(column, Rotation::cur()),
                prev: meta.query_any(column, Rotation::prev()),
            });
            vec![0.expr()] // can this be empty?
        });
        cells.pop().unwrap()
    }
}
