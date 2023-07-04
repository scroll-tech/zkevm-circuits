use crate::keccak_circuit::util::extract_field;
use gadgets::util::Expr;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Value,
    plonk::{Advice, Column, ConstraintSystem, Expression, VirtualCells},
    poly::Rotation,
};

use super::keccak_packed_multi::KeccakRegion;

#[derive(Clone, Debug)]
pub(crate) struct Cell<F> {
    pub(crate) expression: Expression<F>,
    pub(crate) column_expression: Expression<F>,
    pub(crate) column: Option<Column<Advice>>,
    pub(crate) column_idx: usize,
    pub(crate) rotation: i32,
}

impl<F: FieldExt> Cell<F> {
    pub(crate) fn new(
        meta: &mut VirtualCells<F>,
        column: Column<Advice>,
        column_idx: usize,
        rotation: i32,
    ) -> Self {
        Self {
            expression: meta.query_advice(column, Rotation(rotation)),
            column_expression: meta.query_advice(column, Rotation::cur()),
            column: Some(column),
            column_idx,
            rotation,
        }
    }

    pub(crate) fn new_value(column_idx: usize, rotation: i32) -> Self {
        Self {
            expression: 0.expr(),
            column_expression: 0.expr(),
            column: None,
            column_idx,
            rotation,
        }
    }

    pub(crate) fn at_offset(&self, meta: &mut ConstraintSystem<F>, offset: i32) -> Self {
        let mut expression = 0.expr();
        meta.create_gate("Query cell", |meta| {
            expression = meta.query_advice(self.column.unwrap(), Rotation(self.rotation + offset));
            vec![0.expr()]
        });

        Self {
            expression,
            column_expression: self.column_expression.clone(),
            column: self.column,
            column_idx: self.column_idx,
            rotation: self.rotation + offset,
        }
    }

    pub(crate) fn assign(&self, region: &mut KeccakRegion<F>, offset: i32, value: F) {
        region.assign(self.column_idx, (offset + self.rotation) as usize, value);
    }

    pub(crate) fn assign_value(&self, region: &mut KeccakRegion<F>, offset: i32, value: Value<F>) {
        // This is really ugly. But since there's no way to easily adapt the CellManager
        // API customized for this impl specifically, for now I'm opening the
        // value and extracting it. Once https://github.com/privacy-scaling-explorations/zkevm-circuits/issues/933 is resolved,
        // this shouldn't be needed.
        let value_f = extract_field(value);

        region.assign(self.column_idx, (offset + self.rotation) as usize, value_f);
    }
}

impl<F: FieldExt> Expr<F> for Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

impl<F: FieldExt> Expr<F> for &Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

/// CellColumn
#[derive(Clone, Debug)]
pub struct CellColumn<F> {
    pub advice: Column<Advice>,
    pub(crate) expr: Expression<F>,
}

/// CellManager
#[derive(Clone, Debug)]
pub struct CellManager<F> {
    height: usize,
    columns: Vec<CellColumn<F>>,
    rows: Vec<usize>,
    num_unused_cells: usize,
}

impl<F: FieldExt> CellManager<F> {
    pub(crate) fn new(height: usize) -> Self {
        Self {
            height,
            columns: Vec::new(),
            rows: vec![0; height],
            num_unused_cells: 0,
        }
    }

    pub(crate) fn query_cell(&mut self, meta: &mut ConstraintSystem<F>) -> Cell<F> {
        let (row_idx, column_idx) = self.get_position();
        self.query_cell_at_pos(meta, row_idx as i32, column_idx)
    }

    pub(crate) fn query_cell_at_row(
        &mut self,
        meta: &mut ConstraintSystem<F>,
        row_idx: i32,
    ) -> Cell<F> {
        let column_idx = self.rows[row_idx as usize];
        self.rows[row_idx as usize] += 1;
        self.query_cell_at_pos(meta, row_idx, column_idx)
    }

    pub(crate) fn query_cell_value(&mut self) -> Cell<F> {
        let (row_idx, column_idx) = self.get_position();
        self.query_cell_value_at_pos(row_idx as i32, column_idx)
    }

    pub(crate) fn query_cell_value_at_row(&mut self, row_idx: i32) -> Cell<F> {
        let column_idx = self.rows[row_idx as usize];
        self.rows[row_idx as usize] += 1;
        self.query_cell_value_at_pos(row_idx, column_idx)
    }

    pub(crate) fn start_region(&mut self) -> usize {
        // Make sure all rows start at the same column
        let width = self.get_width();
        for row in self.rows.iter_mut() {
            self.num_unused_cells += width - *row;
            *row = width;
        }
        width
    }

    pub(crate) fn get_width(&self) -> usize {
        self.rows.iter().cloned().max().unwrap()
    }

    /// Expose the columns used by the cell manager by reference.
    pub fn columns(&self) -> &[CellColumn<F>] {
        &self.columns
    }

    pub(crate) fn get_num_unused_cells(&self) -> usize {
        self.num_unused_cells
    }

    fn query_cell_at_pos(
        &mut self,
        meta: &mut ConstraintSystem<F>,
        row_idx: i32,
        column_idx: usize,
    ) -> Cell<F> {
        let column = if column_idx < self.columns.len() {
            self.columns[column_idx].advice
        } else {
            let advice = meta.advice_column();
            let mut expr = 0.expr();
            meta.create_gate("Query column", |meta| {
                expr = meta.query_advice(advice, Rotation::cur());
                vec![0.expr()]
            });
            self.columns.push(CellColumn { advice, expr });
            advice
        };

        let mut cells = Vec::new();
        meta.create_gate("Query cell", |meta| {
            cells.push(Cell::new(meta, column, column_idx, row_idx));
            vec![0.expr()]
        });
        cells[0].clone()
    }

    fn query_cell_value_at_pos(&mut self, row_idx: i32, column_idx: usize) -> Cell<F> {
        Cell::new_value(column_idx, row_idx)
    }

    fn get_position(&mut self) -> (usize, usize) {
        let mut best_row_idx = 0usize;
        let mut best_row_pos = 100000usize;
        for (row_idx, row) in self.rows.iter().enumerate() {
            if *row < best_row_pos {
                best_row_pos = *row;
                best_row_idx = row_idx;
            }
        }
        self.rows[best_row_idx] += 1;
        (best_row_idx, best_row_pos)
    }
}
