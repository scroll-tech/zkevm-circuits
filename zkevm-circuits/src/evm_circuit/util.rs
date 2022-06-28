use crate::{
    evm_circuit::{
        param::{LOOKUP_CONFIG, N_BYTES_MEMORY_ADDRESS},
        table::Table,
    },
    util::Expr,
};
use eth_types::U256;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Region},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use std::collections::BTreeMap;

pub(crate) mod common_gadget;
pub(crate) mod constraint_builder;
pub(crate) mod math_gadget;
pub(crate) mod memory_gadget;

#[derive(Clone, Debug)]
pub(crate) struct Cell<F> {
    // expression for constraint
    expression: Expression<F>,
    column: Column<Advice>,
    // relative position to selector for synthesis
    rotation: usize,
}

impl<F: FieldExt> Cell<F> {
    pub(crate) fn new(meta: &mut VirtualCells<F>, column: Column<Advice>, rotation: usize) -> Self {
        Self {
            expression: meta.query_advice(column, Rotation(rotation as i32)),
            column,
            rotation,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Option<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        region.assign_advice(
            || {
                format!(
                    "Cell column: {:?} and rotation: {}",
                    self.column, self.rotation
                )
            },
            self.column,
            offset + self.rotation,
            || value.ok_or(Error::Synthesis),
        )
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

pub struct CachedRegion<'r, 'b, F: FieldExt> {
    region: &'r mut Region<'b, F>,
    advice: Vec<Vec<F>>,
    power_of_randomness: [F; 31],
    width_start: usize,
    height_start: usize,
}

impl<'r, 'b, F: FieldExt> CachedRegion<'r, 'b, F> {
    /// New cached region
    pub(crate) fn new(
        region: &'r mut Region<'b, F>,
        power_of_randomness: [F; 31],
        width: usize,
        height: usize,
        width_start: usize,
        height_start: usize,
    ) -> Self {
        Self {
            region,
            advice: vec![vec![F::zero(); height]; width],
            power_of_randomness,
            width_start,
            height_start,
        }
    }

    /// Assign an advice column value (witness).
    pub fn assign_advice<'v, V, VR, A, AR>(
        &'v mut self,
        annotation: A,
        column: Column<Advice>,
        offset: usize,
        to: V,
    ) -> Result<AssignedCell<VR, F>, Error>
    where
        V: FnMut() -> Result<VR, Error> + 'v,
        for<'vr> Assigned<F>: From<&'vr VR>,
        A: Fn() -> AR,
        AR: Into<String>,
    {
        // Actually set the value
        let res = self.region.assign_advice(annotation, column, offset, to);
        // Cache the value
        if let Result::Ok(cell) = &res {
            let call_value = cell.value_field();
            if let Some(value) = call_value {
                self.advice[column.index() - self.width_start][offset - self.height_start] =
                    value.evaluate();
            }
        }
        res
    }

    pub fn get_fixed(&self, _row_index: usize, _column_index: usize, _rotation: Rotation) -> F {
        unimplemented!("fixed column");
    }

    pub fn get_advice(&self, row_index: usize, column_index: usize, rotation: Rotation) -> F {
        self.advice[column_index - self.width_start]
            [(((row_index - self.height_start) as i32) + rotation.0) as usize]
    }

    pub fn get_instance(&self, _row_index: usize, column_index: usize, _rotation: Rotation) -> F {
        self.power_of_randomness[column_index]
    }
}

#[derive(Debug, Clone)]
pub struct StoredExpression<F> {
    pub(crate) name: String,
    cell: Cell<F>,
    cell_type: CellType,
    expr: Expression<F>,
    expr_id: String,
}

impl<F: FieldExt> StoredExpression<F> {
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        let value = self.expr.evaluate(
            &|scalar| scalar,
            &|_| unimplemented!("selector column"),
            &|_, column_index, rotation| region.get_fixed(offset, column_index, rotation),
            &|_, column_index, rotation| region.get_advice(offset, column_index, rotation),
            &|_, column_index, rotation| region.get_instance(offset, column_index, rotation),
            &|a| -a,
            &|a, b| a + b,
            &|a, b| a * b,
            &|a, scalar| a * scalar,
        );
        self.cell.assign(region, offset, Some(value))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CellType {
    Storage,
    Lookup(Table),
}

#[derive(Clone, Debug)]
pub(crate) struct CellColumn<F> {
    pub(crate) index: usize,
    pub(crate) cell_type: CellType,
    pub(crate) height: usize,
    pub(crate) expr: Expression<F>,
}

impl<F: FieldExt> Expr<F> for CellColumn<F> {
    fn expr(&self) -> Expression<F> {
        self.expr.clone()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CellManager<F> {
    width: usize,
    height: usize,
    cells: Vec<Cell<F>>,
    columns: Vec<CellColumn<F>>,
}

impl<F: FieldExt> CellManager<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        height: usize,
        advices: &[Column<Advice>],
        height_offset: usize,
    ) -> Self {
        // Setup the columns and query the cells
        let width = advices.len();
        let mut cells = Vec::with_capacity(height * width);
        let mut columns = Vec::with_capacity(height);
        meta.create_gate("Query rows for step", |meta| {
            for c in 0..width {
                for r in 0..height {
                    cells.push(Cell::new(meta, advices[c], height_offset + r));
                }
                columns.push(CellColumn {
                    index: c,
                    cell_type: CellType::Storage,
                    height: 0,
                    expr: cells[c * height].expr(),
                });
            }
            vec![0.expr()]
        });

        // Mark columns used for lookups
        let mut column_idx = 0;
        for &(table, count) in LOOKUP_CONFIG {
            for _ in 0usize..count {
                columns[column_idx].cell_type = CellType::Lookup(table);
                column_idx += 1;
            }
        }

        Self {
            width,
            height,
            cells,
            columns,
        }
    }

    pub(crate) fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        let mut cells = Vec::with_capacity(count);
        while cells.len() < count {
            let column_idx = self.next_column(cell_type);
            let column = &mut self.columns[column_idx];
            cells.push(self.cells[column_idx * self.height + column.height].clone());
            column.height += 1;
        }
        cells
    }

    pub(crate) fn query_cell(&mut self, cell_type: CellType) -> Cell<F> {
        self.query_cells(cell_type, 1)[0].clone()
    }

    fn next_column(&self, cell_type: CellType) -> usize {
        let mut best_index: Option<usize> = None;
        let mut best_height = self.height;
        for column in self.columns.iter() {
            if column.cell_type == cell_type && column.height < best_height {
                best_index = Some(column.index);
                best_height = column.height;
            }
        }
        match best_index {
            Some(index) => index,
            None => unreachable!("not enough cells for query: {:?}", cell_type),
        }
    }

    pub(crate) fn get_height(&self) -> usize {
        self.columns
            .iter()
            .map(|column| column.height)
            .max()
            .unwrap()
    }

    pub(crate) fn get_stats(&self) -> BTreeMap<CellType, (usize, usize, usize)> {
        let mut data = BTreeMap::new();
        for column in self.columns.iter() {
            let (mut count, mut height, mut num_cells) =
                data.get(&column.cell_type).unwrap_or(&(0, 0, 0));
            count += 1;
            height = height.max(column.height);
            num_cells += column.height;
            data.insert(column.cell_type, (count, height, num_cells));
        }
        data
    }

    pub(crate) fn columns(&self) -> &[CellColumn<F>] {
        &self.columns
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RandomLinearCombination<F, const N: usize> {
    // random linear combination expression of cells
    expression: Expression<F>,
    // inner cells in little-endian for synthesis
    pub(crate) cells: [Cell<F>; N],
}

impl<F: FieldExt, const N: usize> RandomLinearCombination<F, N> {
    const N_BYTES: usize = N;

    pub(crate) fn random_linear_combine(bytes: [u8; N], randomness: F) -> F {
        rlc::value(&bytes, randomness)
    }

    pub(crate) fn random_linear_combine_expr(
        bytes: [Expression<F>; N],
        power_of_randomness: &[Expression<F>],
    ) -> Expression<F> {
        rlc::expr(&bytes, power_of_randomness)
    }

    pub(crate) fn new(cells: [Cell<F>; N], power_of_randomness: &[Expression<F>]) -> Self {
        Self {
            expression: Self::random_linear_combine_expr(
                cells.clone().map(|cell| cell.expr()),
                power_of_randomness,
            ),
            cells,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        bytes: Option<[u8; N]>,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        bytes.map_or(Err(Error::Synthesis), |bytes| {
            self.cells
                .iter()
                .zip(bytes.iter())
                .map(|(cell, byte)| cell.assign(region, offset, Some(F::from(*byte as u64))))
                .collect()
        })
    }
}

impl<F: FieldExt, const N: usize> Expr<F> for RandomLinearCombination<F, N> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

pub(crate) type Word<F> = RandomLinearCombination<F, 32>;
pub(crate) type MemoryAddress<F> = RandomLinearCombination<F, N_BYTES_MEMORY_ADDRESS>;

/// Returns the sum of the passed in cells
pub(crate) mod sum {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        inputs
            .into_iter()
            .fold(0.expr(), |acc, input| acc + input.expr())
    }

    pub(crate) fn value<F: FieldExt>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::zero(), |acc, value| acc + F::from(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub(crate) mod and {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        inputs
            .into_iter()
            .fold(1.expr(), |acc, input| acc * input.expr())
    }

    pub(crate) fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::one(), |acc, input| acc * input)
    }
}

/// Returns `1` when `expr[0] || expr[1] || ... == 1`, and returns `0`
/// otherwise. Inputs need to be boolean
pub(crate) mod or {
    use super::{and, not};
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt, E: Expr<F>, I: IntoIterator<Item = E>>(
        inputs: I,
    ) -> Expression<F> {
        not::expr(and::expr(inputs.into_iter().map(not::expr)))
    }

    pub(crate) fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        not::value(and::value(inputs.into_iter().map(not::value).collect()))
    }
}

/// Returns `1` when `b == 0`, and returns `0` otherwise.
/// `b` needs to be boolean
pub(crate) mod not {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt, E: Expr<F>>(b: E) -> Expression<F> {
        1.expr() - b.expr()
    }

    pub(crate) fn value<F: FieldExt>(b: F) -> F {
        F::one() - b
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when
/// `selector == 0`. `selector` needs to be boolean.
pub(crate) mod select {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    pub(crate) fn value<F: FieldExt>(selector: F, when_true: F, when_false: F) -> F {
        selector * when_true + (F::one() - selector) * when_false
    }

    pub(crate) fn value_word<F: FieldExt>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::one() {
            when_true
        } else {
            when_false
        }
    }
}

/// Decodes a field element from its byte representation
pub(crate) mod from_bytes {
    use crate::{evm_circuit::param::MAX_N_BYTES_INTEGER, util::Expr};
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt, E: Expr<F>>(bytes: &[E]) -> Expression<F> {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from(256);
        }
        value
    }

    pub(crate) fn value<F: FieldExt>(bytes: &[u8]) -> F {
        debug_assert!(
            bytes.len() <= MAX_N_BYTES_INTEGER,
            "Too many bytes to compose an integer in field"
        );
        let mut value = F::zero();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value += F::from(*byte as u64) * multiplier;
            multiplier *= F::from(256);
        }
        value
    }
}

/// Returns the random linear combination of the inputs.
/// Encoding is done as follows: v_0 * R^0 + v_1 * R^1 + ...
pub(crate) mod rlc {
    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt, E: Expr<F>>(
        expressions: &[E],
        power_of_randomness: &[E],
    ) -> Expression<F> {
        debug_assert!(expressions.len() <= power_of_randomness.len() + 1);

        let mut rlc = expressions[0].expr();
        for (expression, randomness) in expressions[1..].iter().zip(power_of_randomness.iter()) {
            rlc = rlc + expression.expr() * randomness.expr();
        }
        rlc
    }

    pub(crate) fn value<F: FieldExt>(values: &[u8], randomness: F) -> F {
        values.iter().rev().fold(F::zero(), |acc, value| {
            acc * randomness + F::from(*value as u64)
        })
    }
}

/// Returns 2**by as FieldExt
pub(crate) fn pow_of_two<F: FieldExt>(by: usize) -> F {
    F::from(2).pow(&[by as u64, 0, 0, 0])
}

/// Returns 2**by as Expression
pub(crate) fn pow_of_two_expr<F: FieldExt>(by: usize) -> Expression<F> {
    Expression::Constant(pow_of_two(by))
}

/// Returns tuple consists of low and high part of U256
pub(crate) fn split_u256(value: &U256) -> (U256, U256) {
    (
        U256([value.0[0], value.0[1], 0, 0]),
        U256([value.0[2], value.0[3], 0, 0]),
    )
}

/// Split a U256 value into 4 64-bit limbs stored in U256 values.
pub(crate) fn split_u256_limb64(value: &U256) -> [U256; 4] {
    [
        U256([value.0[0], 0, 0, 0]),
        U256([value.0[1], 0, 0, 0]),
        U256([value.0[2], 0, 0, 0]),
        U256([value.0[3], 0, 0, 0]),
    ]
}
