use crate::{
    evm_circuit::{
        param::{
            LOOKUP_CONFIG, N_BYTES_MEMORY_ADDRESS, N_BYTES_U64, N_BYTE_LOOKUPS, N_COPY_COLUMNS,
            N_PHASE2_COLUMNS, N_PHASE2_COPY_COLUMNS,
        },
        table::Table,
    },
    table::RwTableTag,
    util::{query_expression, Challenges, Expr},
    witness::{Block, ExecStep, Rw, RwMap},
};
use bus_mapping::state_db::CodeDB;
use eth_types::{Address, ToLittleEndian, ToWord, U256};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};
use itertools::Itertools;
use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

pub(crate) mod common_gadget;
pub(crate) mod constraint_builder;
pub(crate) mod instrumentation;
pub(crate) mod math_gadget;
pub(crate) mod memory_gadget;
pub(crate) mod precompile_gadget;

pub use gadgets::util::{and, not, or, select, sum};

#[derive(Clone, Debug)]
pub(crate) struct Cell<F> {
    // expression for constraint
    expression: Expression<F>,
    column: Column<Advice>,
    // relative position to selector for synthesis
    rotation: usize,
    cell_column_index: usize,
}

impl<F: FieldExt> Cell<F> {
    pub(crate) fn new(
        meta: &mut VirtualCells<F>,
        column: Column<Advice>,
        rotation: usize,
        cell_column_index: usize,
    ) -> Self {
        Self {
            expression: meta.query_advice(column, Rotation(rotation as i32)),
            column,
            rotation,
            cell_column_index,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        value: Value<F>,
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
            || value,
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
    challenges: &'r Challenges<Value<F>>,
    advice_columns: Vec<Column<Advice>>,
    width_start: usize,
    height_start: usize,
}

impl<'r, 'b, F: FieldExt> CachedRegion<'r, 'b, F> {
    /// New cached region
    pub(crate) fn new(
        region: &'r mut Region<'b, F>,
        challenges: &'r Challenges<Value<F>>,
        advice_columns: Vec<Column<Advice>>,
        height: usize,
        height_start: usize,
    ) -> Self {
        Self {
            region,
            advice: vec![vec![F::zero(); height]; advice_columns.len()],
            challenges,
            width_start: advice_columns[0].index(),
            height_start,
            advice_columns,
        }
    }

    /// This method replicates the assignment of 1 row at height_start (which
    /// must be already assigned via the CachedRegion) into a range of rows
    /// indicated by offset_begin, offset_end. It can be used as a "quick"
    /// path for assignment for repeated padding rows.
    pub fn replicate_assignment_for_range<A, AR>(
        &mut self,
        annotation: A,
        offset_begin: usize,
        offset_end: usize,
    ) -> Result<(), Error>
    where
        A: Fn() -> AR,
        AR: Into<String>,
    {
        for (v, column) in self
            .advice
            .iter()
            .map(|values| values[0])
            .zip_eq(self.advice_columns.iter())
        {
            if v.is_zero_vartime() {
                continue;
            }
            let annotation: &String = &annotation().into();
            for offset in offset_begin..offset_end {
                self.region
                    .assign_advice(|| annotation, *column, offset, || Value::known(v))?;
            }
        }

        Ok(())
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
        V: Fn() -> Value<VR> + 'v,
        for<'vr> Assigned<F>: From<&'vr VR>,
        A: Fn() -> AR,
        AR: Into<String>,
    {
        // Actually set the value
        let res = self.region.assign_advice(annotation, column, offset, &to);
        // Cache the value
        // Note that the `value_field` in `AssignedCell` might be `Value::unkonwn` if
        // the column has different phase than current one, so we call to `to`
        // again here to cache the value.
        if res.is_ok() {
            to().map(|f| {
                self.advice[column.index() - self.width_start][offset - self.height_start] =
                    Assigned::from(&f).evaluate();
            });
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

    pub fn challenges(&self) -> &Challenges<Value<F>> {
        self.challenges
    }

    pub fn word_rlc(&self, n: U256) -> Value<F> {
        self.challenges
            .evm_word()
            .map(|r| rlc::value(&n.to_le_bytes(), r))
    }

    pub fn code_hash(&self, n: U256) -> Value<F> {
        self.challenges.evm_word().map(|r| {
            if cfg!(feature = "poseidon-codehash") {
                // only FieldExt is not enough for ToScalar trait so we have to make workaround
                rlc::value(&n.to_le_bytes(), F::from(256u64))
            } else {
                rlc::value(&n.to_le_bytes(), r)
            }
        })
    }

    pub fn keccak_rlc(&self, le_bytes: &[u8]) -> Value<F> {
        self.challenges
            .keccak_input()
            .map(|r| rlc::value(le_bytes, r))
    }

    pub fn empty_code_hash_rlc(&self) -> Value<F> {
        self.code_hash(CodeDB::empty_code_hash().to_word())
    }

    /// Constrains a cell to have a constant value.
    ///
    /// Returns an error if the cell is in a column where equality has not been
    /// enabled.
    pub fn constrain_constant<VR>(
        &mut self,
        cell: AssignedCell<F, F>,
        constant: VR,
    ) -> Result<(), Error>
    where
        VR: Into<Assigned<F>>,
    {
        self.region.constrain_constant(cell.cell(), constant.into())
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

impl<F> Hash for StoredExpression<F> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.expr_id.hash(state);
        self.cell_type.hash(state);
    }
}

impl<F: FieldExt> StoredExpression<F> {
    pub fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
    ) -> Result<Value<F>, Error> {
        let value = self.expr.evaluate(
            &|scalar| Value::known(scalar),
            &|_| unimplemented!("selector column"),
            &|fixed_query| {
                Value::known(region.get_fixed(
                    offset,
                    fixed_query.column_index(),
                    fixed_query.rotation(),
                ))
            },
            &|advice_query| {
                Value::known(region.get_advice(
                    offset,
                    advice_query.column_index(),
                    advice_query.rotation(),
                ))
            },
            &|_| unimplemented!("instance column"),
            &|challenge| *region.challenges().indexed()[challenge.index()],
            &|a| -a,
            &|a, b| a + b,
            &|a, b| a * b,
            &|a, scalar| a * Value::known(scalar),
        );
        self.cell.assign(region, offset, value)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum CellType {
    StoragePhase1,
    StoragePhase2,
    StoragePermutation,
    StoragePermutationPhase2,
    LookupByte,
    Lookup(Table),
}

impl CellType {
    // The phase that given `Expression` becomes evaluateable.
    fn expr_phase<F: FieldExt>(expr: &Expression<F>) -> u8 {
        use Expression::*;
        match expr {
            Challenge(challenge) => challenge.phase() + 1,
            Advice(query) => query.phase(),
            Constant(_) | Selector(_) | Fixed(_) | Instance(_) => 0,
            Negated(a) | Expression::Scaled(a, _) => Self::expr_phase(a),
            Sum(a, b) | Product(a, b) => std::cmp::max(Self::expr_phase(a), Self::expr_phase(b)),
        }
    }

    /// Return the storage phase of phase
    pub(crate) fn storage_for_phase(phase: u8) -> CellType {
        match phase {
            0 => CellType::StoragePhase1,
            1 => CellType::StoragePhase2,
            _ => unreachable!(),
        }
    }

    /// Return the storage cell of the expression
    pub(crate) fn storage_for_expr<F: FieldExt>(expr: &Expression<F>) -> CellType {
        Self::storage_for_phase(Self::expr_phase::<F>(expr))
    }
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
        let mut columns = Vec::with_capacity(width);
        query_expression(meta, |meta| {
            for c in 0..width {
                for r in 0..height {
                    cells.push(Cell::new(meta, advices[c], height_offset + r, c));
                }
                columns.push(CellColumn {
                    index: c,
                    cell_type: CellType::StoragePhase1,
                    height: 0,
                    expr: cells[c * height].expr(),
                });
            }
        });

        let mut column_idx = 0;

        // Mark columns used for lookups in Phase3
        for &(table, count) in LOOKUP_CONFIG {
            for _ in 0usize..count {
                columns[column_idx].cell_type = CellType::Lookup(table);
                column_idx += 1;
            }
        }

        // Mark columns used for copy constraints on phase2
        for _ in 0..N_PHASE2_COPY_COLUMNS {
            meta.enable_equality(advices[column_idx]);
            columns[column_idx].cell_type = CellType::StoragePermutationPhase2;
            column_idx += 1;
        }

        // Mark columns used for Phase2 constraints
        for _ in N_PHASE2_COPY_COLUMNS..N_PHASE2_COLUMNS {
            columns[column_idx].cell_type = CellType::StoragePhase2;
            column_idx += 1;
        }

        // Mark columns used for copy constraints
        for _ in 0..N_COPY_COLUMNS {
            meta.enable_equality(advices[column_idx]);
            columns[column_idx].cell_type = CellType::StoragePermutation;
            column_idx += 1;
        }

        // Mark columns used for byte lookup
        for _ in 0..N_BYTE_LOOKUPS {
            columns[column_idx].cell_type = CellType::LookupByte;
            assert_eq!(advices[column_idx].column_type().phase(), 0);
            column_idx += 1;
        }

        Self {
            width,
            height,
            cells,
            columns,
        }
    }

    pub(crate) fn reset_heights_to(&mut self, heights: &[usize]) {
        for (column, &height) in self.columns.iter_mut().zip_eq(heights.iter()) {
            column.height = height;
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
        // Replace a CellType::Storage by CellType::StoragePermutation (phase 1 or phase 2) if the
        // later has better height
        if cell_type == CellType::StoragePhase1 {
            for column in self.columns.iter() {
                if column.cell_type == CellType::StoragePermutation && column.height < best_height {
                    best_index = Some(column.index);
                    best_height = column.height;
                }
            }
        } else if cell_type == CellType::StoragePhase2 {
            for column in self.columns.iter() {
                if column.cell_type == CellType::StoragePermutationPhase2
                    && column.height < best_height
                {
                    best_index = Some(column.index);
                    best_height = column.height;
                }
            }
        }

        match best_index {
            Some(index) => index,
            // If we reach this case, it means that all the columns of cell_type have assignments
            // taking self.height rows, so there's no more space.
            None => panic!("not enough cells for query: {:?}", cell_type),
        }
    }

    pub(crate) fn get_height(&self) -> usize {
        self.columns
            .iter()
            .map(|column| column.height)
            .max()
            .unwrap()
    }

    pub(crate) fn get_heights(&self) -> Vec<usize> {
        self.columns().iter().map(|column| column.height).collect()
    }

    /// Returns a map of CellType -> (width, height, num_cells)
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

    pub(crate) fn new(cells: [Cell<F>; N], randomness: Expression<F>) -> Self {
        Self {
            expression: rlc::expr(&cells.clone().map(|cell| cell.expr()), randomness),
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
                .map(|(cell, byte)| {
                    cell.assign(region, offset, Value::known(F::from(*byte as u64)))
                })
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
pub(crate) type U64Word<F> = RandomLinearCombination<F, N_BYTES_U64>;
pub(crate) type MemoryAddress<F> = RandomLinearCombination<F, N_BYTES_MEMORY_ADDRESS>;

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
    use std::ops::{Add, Mul};

    use crate::util::Expr;
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt, E: Expr<F>>(expressions: &[E], randomness: E) -> Expression<F> {
        if !expressions.is_empty() {
            generic(expressions.iter().map(|e| e.expr()), randomness.expr())
        } else {
            0.expr()
        }
    }

    pub(crate) fn value<'a, F: FieldExt, I>(values: I, randomness: F) -> F
    where
        I: IntoIterator<Item = &'a u8>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        let values = values
            .into_iter()
            .map(|v| F::from(*v as u64))
            .collect::<Vec<F>>();
        if !values.is_empty() {
            generic(values, randomness)
        } else {
            F::zero()
        }
    }

    fn generic<V, I>(values: I, randomness: V) -> V
    where
        I: IntoIterator<Item = V>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
        V: Clone + Add<Output = V> + Mul<Output = V>,
    {
        let mut values = values.into_iter().rev();
        let init = values.next().expect("values should not be empty");

        values.fold(init, |acc, value| acc * randomness.clone() + value)
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

/// Transposes an `Value` of a [`Result`] into a [`Result`] of an `Value`.
pub(crate) fn transpose_val_ret<F, E>(value: Value<Result<F, E>>) -> Result<Value<F>, E> {
    let mut ret = Ok(Value::unknown());
    value.map(|value| {
        ret = value.map(Value::known);
    });
    ret
}

pub(crate) fn is_precompiled(address: &Address) -> bool {
    address.0[0..19] == [0u8; 19] && (1..=9).contains(&address.0[19])
}

/// Helper struct to read rw operations from a step sequentially.
pub(crate) struct StepRws<'a> {
    rws: &'a RwMap,
    rw_indices: &'a Vec<(RwTableTag, usize)>,
    offset: usize,
}

impl<'a> StepRws<'a> {
    /// Create a new StateRws by taking the reference to a block and the step.
    pub(crate) fn new<F>(block: &'a Block<F>, step: &'a ExecStep) -> Self {
        Self {
            rws: &block.rws,
            rw_indices: &step.rw_indices,
            offset: 0,
        }
    }
    /// Increment the step rw operation offset by `offset`.
    pub(crate) fn offset_add(&mut self, offset: usize) {
        self.offset = offset
    }
    /// Return the next rw operation from the step.
    pub(crate) fn next(&mut self) -> Rw {
        let rw = self.rws[self.rw_indices[self.offset]];
        self.offset += 1;
        rw
    }
}
