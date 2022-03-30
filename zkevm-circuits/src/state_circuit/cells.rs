use crate::evm_circuit::util::{not, Cell};
use crate::util::Expr;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

#[derive(Clone, Debug)]
// Use this instead of a Cell when you need access to the expression for the
// previous cell.
pub struct Domino<F: FieldExt> {
    expression: Expression<F>,
    prev_expression: Expression<F>,
    column: Column<Advice>,
}

impl<F: FieldExt> Domino<F> {
    fn new(meta: &mut VirtualCells<F>, column: Column<Advice>) -> Self {
        Self {
            expression: meta.query_advice(column, Rotation::cur()),
            prev_expression: meta.query_advice(column, Rotation::prev()),
            column,
        }
    }

    fn cur(&self) -> Expression<F> {
        self.expression.clone()
    }

    fn prev(&self) -> Expression<F> {
        self.prev_expression.clone()
    }

    fn delta(&self) -> Expression<F> {
        self.cur() - self.prev()
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Option<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || format!("Cell column: {:?}", self.column),
            self.column,
            offset,
            || value.ok_or(Error::Synthesis),
        )
    }
}

#[derive(Clone, Debug)]
pub struct MultiplePrecisionInteger<F: FieldExt, const N: usize> {
    pub value: Domino<F>,
    limbs: [Cell<F>; N],
}

impl<F: FieldExt, const N: usize> MultiplePrecisionInteger<F, N> {
    fn new(meta: &mut ConstraintSystem<F>) -> Self {
        let value = new_domino(meta);
        let limbs = new_cells(meta);
        Self { value, limbs }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Option<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.value.assign(region, offset, value)
        // self.limbs.map(....)
    }
}

#[derive(Clone, Debug)]
pub struct Cells<F: FieldExt> {
    // cb: BaseConstraintBuilder<F>,
    pub rw_counter: MultiplePrecisionInteger<F, 2>,
    pub(super) is_write: Cell<F>,
    // tag: Cell<F>,
    // id: Cell<F>,
    // address: MultiplePrecisionInteger<F, N_LIMBS_ACCOUNT_ADDRESS>,
    // field_tag: Cell<F>,
    // storage_key: RandomLinearCombination<F, N_BYTES_WORD>,
    // value: Cell<F>,
    power_of_randomness: [Expression<F>; 31],
    /* constraints: Vec<(&'static str, Expression<F>)>,
     * lookups: Vec<(&'static str, Lookup<F>)>, */
}

impl<F: FieldExt> Cells<F> {
    pub fn new(meta: &mut ConstraintSystem<F>, power_of_randomness: [Expression<F>; 31]) -> Self {
        Self {
            rw_counter: MultiplePrecisionInteger::new(meta),
            is_write: new_cell(meta),
            // tag: new_cell(meta),
            // id: new_cell(meta),
            // address: MultiplePrecisionInteger::new(meta),
            // field_tag: new_cell(meta),
            // storage_key: RandomLinearCombination::new(new_cells(meta), &power_of_randomness),
            // value: new_cell(meta),
            power_of_randomness,
            /* constraints: vec![],
             * lookups: vec![], */
        }
    }

    pub fn rw_counter(&self) -> Expression<F> {
        self.rw_counter.value.cur()
    }

    pub fn rw_counter_delta(&self) -> Expression<F> {
        self.rw_counter.value.delta()
    }

    pub fn is_write(&self) -> Expression<F> {
        self.is_write.expr()
    }

    pub fn is_read(&self) -> Expression<F> {
        not::expr(self.is_write.expr())
    }
}

fn new_cell<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Cell<F> {
    let advice_column = meta.advice_column();
    let mut cells = vec![];
    meta.create_gate("new_cell", |meta| {
        cells.push(Cell::new(meta, advice_column, 0));
        vec![0.expr()] // can this be empty?
    });
    cells.pop().unwrap()
}

fn new_cells<F: FieldExt, const N: usize>(meta: &mut ConstraintSystem<F>) -> [Cell<F>; N] {
    [0; N].map(|_| new_cell(meta))
}

fn new_domino<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Domino<F> {
    let advice_column = meta.advice_column();
    let mut dominos = vec![];
    meta.create_gate("new_cell", |meta| {
        dominos.push(Domino::new(meta, advice_column));
        vec![0.expr()] // can this be empty?
    });
    dominos.pop().unwrap()
}
