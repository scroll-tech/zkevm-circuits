use super::util::{
    get_num_bits_per_lookup, load_lookup_table, load_normalize_table, load_pack_table,
    CHI_BASE_LOOKUP_TABLE, NUM_ROUNDS,
};
use crate::evm_circuit::util::{not, rlc};
use crate::keccak_circuit::util::{
    compose_rlc, field_xor, get_absorb_positions, into_bits, pack, pack_u64, pack_with_base,
    rotate, scatter, target_part_sizes, to_bytes, unpack, BIT_SIZE, NUM_WORDS_TO_ABSORB,
    NUM_WORDS_TO_SQUEEZE, RATE, RATE_IN_BITS, RHO_MATRIX, ROUND_CST,
};
use crate::table::KeccakTable;
use crate::{evm_circuit::util::constraint_builder::BaseConstraintBuilder, util::Expr};
use eth_types::Field;
use gadgets::util::{and, select, sum};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::VirtualCells;
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, TableColumn},
    poly::Rotation,
};
use log::{debug, info};
use std::env::var;
use std::{marker::PhantomData, vec};

const MAX_DEGREE: usize = 4;
const ABSORB_LOOKUP_RANGE: usize = 3;
const THETA_C_LOOKUP_RANGE: usize = 6;
const RHO_PI_LOOKUP_RANGE: usize = 4;
const CHI_BASE_LOOKUP_RANGE: usize = 5;

fn get_num_rows_per_round() -> usize {
    var("KECCAK_ROWS")
        .unwrap_or_else(|_| "25".to_string())
        .parse()
        .expect("Cannot parse KECCAK_ROWS env var as usize")
}

fn get_num_bits_per_absorb_lookup() -> usize {
    get_num_bits_per_lookup(ABSORB_LOOKUP_RANGE)
}

fn get_num_bits_per_theta_c_lookup() -> usize {
    get_num_bits_per_lookup(THETA_C_LOOKUP_RANGE)
}

fn get_num_bits_per_rho_pi_lookup() -> usize {
    get_num_bits_per_lookup(CHI_BASE_LOOKUP_RANGE.max(RHO_PI_LOOKUP_RANGE))
}

fn get_num_bits_per_base_chi_lookup() -> usize {
    get_num_bits_per_lookup(CHI_BASE_LOOKUP_RANGE.max(RHO_PI_LOOKUP_RANGE))
}

/// AbsorbData
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct AbsorbData<F: Field> {
    from: F,
    absorb: F,
    result: F,
}

/// SqueezeData
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct SqueezeData<F: Field> {
    packed: F,
}

/// KeccakRow
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct KeccakRow<F: Field> {
    q_enable: bool,
    q_enable_row: bool,
    q_round: bool,
    q_absorb: bool,
    q_round_last: bool,
    q_padding: bool,
    q_padding_last: bool,
    round_cst: F,
    is_final: bool,
    cell_values: Vec<F>,
    length: usize,
    data_rlc: F,
    hash_rlc: F,
    bytes_left: F, // from len to 1
    hash_id: F,    // 0 when first row, then 1,2,3,..
    value: F,      // byte
}

/// Part
#[derive(Clone, Debug)]
pub(crate) struct Part<F: Field> {
    cell: Cell<F>,
    expr: Expression<F>,
    num_bits: usize,
}

/// Part Value
#[derive(Clone, Copy, Debug)]
pub(crate) struct PartValue<F: Field> {
    value: F,
    rot: i32,
    num_bits: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct KeccakRegion<F> {
    pub(crate) rows: Vec<Vec<F>>,
}

impl<F: FieldExt> KeccakRegion<F> {
    pub(crate) fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub(crate) fn assign(&mut self, column: usize, offset: usize, value: F) {
        while offset >= self.rows.len() {
            self.rows.push(Vec::new());
        }
        let row = &mut self.rows[offset];
        while column >= row.len() {
            row.push(F::zero());
        }
        row[column] = value;
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Cell<F> {
    expression: Expression<F>,
    column_expression: Expression<F>,
    column: Option<Column<Advice>>,
    column_idx: usize,
    rotation: i32,
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
        region.assign(
            self.column_idx,
            ((offset as i32) + self.rotation) as usize,
            value,
        );
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
pub(crate) struct CellColumn<F> {
    advice: Column<Advice>,
    expr: Expression<F>,
}

/// CellManager
#[derive(Clone, Debug)]
pub(crate) struct CellManager<F> {
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

    pub(crate) fn query_cell_at_pos(
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

    pub(crate) fn query_cell_value(&mut self) -> Cell<F> {
        let (row_idx, column_idx) = self.get_position();
        self.query_cell_value_at_pos(row_idx as i32, column_idx)
    }

    pub(crate) fn query_cell_value_at_row(&mut self, row_idx: i32) -> Cell<F> {
        let column_idx = self.rows[row_idx as usize];
        self.rows[row_idx as usize] += 1;
        self.query_cell_value_at_pos(row_idx, column_idx)
    }

    pub(crate) fn query_cell_value_at_pos(&mut self, row_idx: i32, column_idx: usize) -> Cell<F> {
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

    pub(crate) fn get_width(&self) -> usize {
        self.rows.iter().cloned().max().unwrap()
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

    pub(crate) fn columns(&self) -> &[CellColumn<F>] {
        &self.columns
    }

    pub(crate) fn get_num_unused_cells(&self) -> usize {
        self.num_unused_cells
    }
}

/// KeccakConfig
#[derive(Clone, Debug)]
pub struct KeccakPackedConfig<F> {
    // q_enable only on the first row of valid rounds,
    // while q_enable_row on every row of valid rounds
    // q_enable_row can be optimzied out using expression like
    // (1..get_num_rows_per_round() as i32).map(|i| meta.query_fixed(q_enable,
    // Rotation(-i))).fold(0.expr(), |acc, elem| acc + elem), now we keep it here to make codes
    // easier to read
    q_enable: Column<Fixed>,
    q_enable_row: Column<Fixed>,
    q_first: Column<Fixed>,
    q_round: Column<Fixed>,
    q_absorb: Column<Fixed>,
    q_round_last: Column<Fixed>,
    q_padding: Column<Fixed>,
    q_padding_last: Column<Fixed>,
    /// The columns for other circuits to lookup Keccak hash results
    pub keccak_table: KeccakTable,
    cell_manager: CellManager<F>,
    round_cst: Column<Fixed>,
    normalize_3: [TableColumn; 2],
    normalize_4: [TableColumn; 2],
    normalize_6: [TableColumn; 2],
    chi_base_table: [TableColumn; 2],
    pack_table: [TableColumn; 2],
    _marker: PhantomData<F>,
}

/// KeccakPackedCircuit
#[derive(Default)]
pub struct KeccakPackedCircuit<F: Field> {
    witness: Vec<KeccakRow<F>>,
    num_rows: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> KeccakPackedCircuit<F> {
    fn r() -> F {
        F::from(123456)
    }
}

impl<F: Field> Circuit<F> for KeccakPackedCircuit<F> {
    type Config = KeccakPackedConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        KeccakPackedConfig::configure(meta, Expression::Constant(KeccakPackedCircuit::r()))
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load(&mut layouter)?;
        config.assign(&mut layouter, &self.witness)?;
        Ok(())
    }
}

impl<F: Field> KeccakPackedCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(num_rows: usize) -> Self {
        KeccakPackedCircuit {
            witness: Vec::new(),
            num_rows,
            _marker: PhantomData,
        }
    }

    /// The number of keccak_f's that can be done in this circuit
    pub fn capacity(&self) -> usize {
        // Subtract two for unusable rows
        self.num_rows / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2
    }

    /// Sets the witness using the data to be hashed
    pub fn generate_witness(&mut self, inputs: &[Vec<u8>]) {
        self.witness = multi_keccak(inputs, KeccakPackedCircuit::r(), Some(self.capacity()))
            .expect("Too many inputs for given capacity");
    }
}

/// Recombines parts back together
mod decode {
    use super::{Part, PartValue};
    use crate::keccak_circuit::util::BIT_SIZE;
    use crate::util::Expr;
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(parts: Vec<Part<F>>) -> Expression<F> {
        parts.iter().rev().fold(0.expr(), |acc, part| {
            acc * F::from((BIT_SIZE as u32).pow(part.num_bits as u32) as u64) + part.expr.clone()
        })
    }

    pub(crate) fn value<F: Field>(parts: Vec<PartValue<F>>) -> F {
        parts.iter().rev().fold(F::zero(), |acc, part| {
            acc * F::from((BIT_SIZE as u32).pow(part.num_bits as u32) as u64) + part.value
        })
    }
}

/// Splits a word into parts
mod split {
    use super::{decode, CellManager, KeccakRegion, Part, PartValue};
    use crate::keccak_circuit::util::{pack, pack_part, unpack, WordParts};
    use crate::{evm_circuit::util::constraint_builder::BaseConstraintBuilder, util::Expr};
    use eth_types::Field;
    use halo2_proofs::plonk::{ConstraintSystem, Expression};

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expr<F: Field>(
        meta: &mut ConstraintSystem<F>,
        cell_manager: &mut CellManager<F>,
        cb: &mut BaseConstraintBuilder<F>,
        input: Expression<F>,
        rot: usize,
        target_part_size: usize,
        normalize: bool,
        row: Option<usize>,
    ) -> Vec<Part<F>> {
        let mut parts = Vec::new();
        let word = WordParts::new(target_part_size, rot, normalize);
        for word_part in word.parts {
            let cell = if let Some(row) = row {
                cell_manager.query_cell_at_row(meta, row as i32)
            } else {
                cell_manager.query_cell(meta)
            };
            parts.push(Part {
                num_bits: word_part.bits.len(),
                cell: cell.clone(),
                expr: cell.expr(),
            });
        }
        // Input parts need to equal original input expression
        cb.require_equal("split", decode::expr(parts.clone()), input);
        parts
    }

    pub(crate) fn value<F: Field>(
        cell_manager: &mut CellManager<F>,
        region: &mut KeccakRegion<F>,
        input: F,
        rot: usize,
        target_part_size: usize,
        normalize: bool,
        row: Option<usize>,
    ) -> Vec<PartValue<F>> {
        let input_bits = unpack(input);
        debug_assert_eq!(pack::<F>(&input_bits), input);
        let mut parts = Vec::new();
        let word = WordParts::new(target_part_size, rot, normalize);
        for word_part in word.parts {
            let value = pack_part(&input_bits, &word_part);
            let cell = if let Some(row) = row {
                cell_manager.query_cell_value_at_row(row as i32)
            } else {
                cell_manager.query_cell_value()
            };
            cell.assign(region, 0, F::from(value));
            parts.push(PartValue {
                num_bits: word_part.bits.len(),
                rot: cell.rotation,
                value: F::from(value),
            });
        }
        debug_assert_eq!(decode::value(parts.clone()), input);
        parts
    }
}

// Split into parts, but storing the parts in a specific way to have the same
// table layout in `output_cells` regardless of rotation.
mod split_uniform {
    use super::{decode, target_part_sizes, Cell, CellManager, KeccakRegion, Part, PartValue};
    use crate::keccak_circuit::keccak_packed_multi::BIT_SIZE;
    use crate::keccak_circuit::util::{pack, pack_part, rotate, rotate_rev, unpack, WordParts};
    use crate::{evm_circuit::util::constraint_builder::BaseConstraintBuilder, util::Expr};
    use eth_types::Field;
    use halo2_proofs::plonk::{ConstraintSystem, Expression};

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expr<F: Field>(
        meta: &mut ConstraintSystem<F>,
        output_cells: &[Cell<F>],
        cell_manager: &mut CellManager<F>,
        cb: &mut BaseConstraintBuilder<F>,
        input: Expression<F>,
        rot: usize,
        target_part_size: usize,
        normalize: bool,
    ) -> Vec<Part<F>> {
        let mut input_parts = Vec::new();
        let mut output_parts = Vec::new();
        let word = WordParts::new(target_part_size, rot, normalize);

        let word = rotate(word.parts, rot, target_part_size);

        let target_sizes = target_part_sizes(target_part_size);
        let mut word_iter = word.iter();
        let mut counter = 0;
        while let Some(word_part) = word_iter.next() {
            if word_part.bits.len() == target_sizes[counter] {
                // Input and output part are the same
                let part = Part {
                    num_bits: target_sizes[counter],
                    cell: output_cells[counter].clone(),
                    expr: output_cells[counter].expr(),
                };
                input_parts.push(part.clone());
                output_parts.push(part);
                counter += 1;
            } else if let Some(extra_part) = word_iter.next() {
                // The two parts combined need to have the expected combined length
                debug_assert_eq!(
                    word_part.bits.len() + extra_part.bits.len(),
                    target_sizes[counter]
                );

                // Needs two cells here to store the parts
                // These still need to be range checked elsewhere!
                let part_a = cell_manager.query_cell(meta);
                let part_b = cell_manager.query_cell(meta);

                // Make sure the parts combined equal the value in the uniform output
                let expr = part_a.expr()
                    + part_b.expr()
                        * F::from((BIT_SIZE as u32).pow(word_part.bits.len() as u32) as u64);
                cb.require_equal("rot part", expr, output_cells[counter].expr());

                // Input needs the two parts because it needs to be able to undo the rotation
                input_parts.push(Part {
                    num_bits: word_part.bits.len(),
                    cell: part_a.clone(),
                    expr: part_a.expr(),
                });
                input_parts.push(Part {
                    num_bits: extra_part.bits.len(),
                    cell: part_b.clone(),
                    expr: part_b.expr(),
                });
                // Output only has the combined cell
                output_parts.push(Part {
                    num_bits: target_sizes[counter],
                    cell: output_cells[counter].clone(),
                    expr: output_cells[counter].expr(),
                });
                counter += 1;
            } else {
                unreachable!();
            }
        }
        let input_parts = rotate_rev(input_parts, rot, target_part_size);
        // Input parts need to equal original input expression
        cb.require_equal("split", decode::expr(input_parts), input);
        // Uniform output
        output_parts
    }

    pub(crate) fn value<F: Field>(
        output_cells: &[Cell<F>],
        cell_manager: &mut CellManager<F>,
        region: &mut KeccakRegion<F>,
        input: F,
        rot: usize,
        target_part_size: usize,
        normalize: bool,
    ) -> Vec<PartValue<F>> {
        let input_bits = unpack(input);
        debug_assert_eq!(pack::<F>(&input_bits), input);

        let mut input_parts = Vec::new();
        let mut output_parts = Vec::new();
        let word = WordParts::new(target_part_size, rot, normalize);

        let word = rotate(word.parts, rot, target_part_size);

        let target_sizes = target_part_sizes(target_part_size);
        let mut word_iter = word.iter();
        let mut counter = 0;
        while let Some(word_part) = word_iter.next() {
            if word_part.bits.len() == target_sizes[counter] {
                let value = pack_part(&input_bits, word_part);
                output_cells[counter].assign(region, 0, F::from(value));
                input_parts.push(PartValue {
                    num_bits: word_part.bits.len(),
                    rot: output_cells[counter].rotation,
                    value: F::from(value),
                });
                output_parts.push(PartValue {
                    num_bits: word_part.bits.len(),
                    rot: output_cells[counter].rotation,
                    value: F::from(value),
                });
                counter += 1;
            } else if let Some(extra_part) = word_iter.next() {
                debug_assert_eq!(
                    word_part.bits.len() + extra_part.bits.len(),
                    target_sizes[counter]
                );

                let part_a = cell_manager.query_cell_value();
                let part_b = cell_manager.query_cell_value();

                let value_a = pack_part(&input_bits, word_part);
                let value_b = pack_part(&input_bits, extra_part);

                part_a.assign(region, 0, F::from(value_a));
                part_b.assign(region, 0, F::from(value_b));

                let value = value_a + value_b * (BIT_SIZE as u64).pow(word_part.bits.len() as u32);

                output_cells[counter].assign(region, 0, F::from(value));

                input_parts.push(PartValue {
                    num_bits: word_part.bits.len(),
                    value: F::from(value_a),
                    rot: part_a.rotation,
                });
                input_parts.push(PartValue {
                    num_bits: extra_part.bits.len(),
                    value: F::from(value_b),
                    rot: part_b.rotation,
                });
                output_parts.push(PartValue {
                    num_bits: target_sizes[counter],
                    value: F::from(value),
                    rot: output_cells[counter].rotation,
                });
                counter += 1;
            } else {
                unreachable!();
            }
        }
        let input_parts = rotate_rev(input_parts, rot, target_part_size);
        debug_assert_eq!(decode::value(input_parts), input);
        output_parts
    }
}

// Transform values using a lookup table
mod transform {
    use super::{transform_to, CellManager, KeccakRegion, Part, PartValue};
    use eth_types::Field;
    use halo2_proofs::plonk::ConstraintSystem;
    use halo2_proofs::plonk::TableColumn;

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expr<F: Field>(
        name: &'static str,
        meta: &mut ConstraintSystem<F>,
        cell_manager: &mut CellManager<F>,
        lookup_counter: &mut usize,
        input: Vec<Part<F>>,
        transform_table: [TableColumn; 2],
        uniform_lookup: bool,
    ) -> Vec<Part<F>> {
        let mut cells = Vec::new();
        for input_part in input.iter() {
            cells.push(if uniform_lookup {
                cell_manager.query_cell_at_row(meta, input_part.cell.rotation)
            } else {
                cell_manager.query_cell(meta)
            });
        }
        transform_to::expr(
            name,
            meta,
            &cells,
            lookup_counter,
            input,
            transform_table,
            uniform_lookup,
        )
    }

    pub(crate) fn value<F: Field>(
        cell_manager: &mut CellManager<F>,
        region: &mut KeccakRegion<F>,
        input: Vec<PartValue<F>>,
        do_packing: bool,
        f: fn(&u8) -> u8,
        uniform_lookup: bool,
    ) -> Vec<PartValue<F>> {
        let mut cells = Vec::new();
        for input_part in input.iter() {
            cells.push(if uniform_lookup {
                cell_manager.query_cell_value_at_row(input_part.rot)
            } else {
                cell_manager.query_cell_value()
            });
        }
        transform_to::value(&cells, region, input, do_packing, f)
    }
}

// Transfroms values to cells
mod transform_to {
    use super::{Cell, KeccakRegion, Part, PartValue};
    use crate::keccak_circuit::util::{pack, to_bytes, unpack};
    use crate::util::Expr;
    use eth_types::Field;
    use halo2_proofs::plonk::ConstraintSystem;
    use halo2_proofs::plonk::TableColumn;

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn expr<F: Field>(
        name: &'static str,
        meta: &mut ConstraintSystem<F>,
        cells: &[Cell<F>],
        lookup_counter: &mut usize,
        input: Vec<Part<F>>,
        transform_table: [TableColumn; 2],
        uniform_lookup: bool,
    ) -> Vec<Part<F>> {
        let mut output = Vec::new();
        for (idx, input_part) in input.iter().enumerate() {
            let output_part = cells[idx].clone();
            if !uniform_lookup || input_part.cell.rotation == 0 {
                meta.lookup(name, |_| {
                    vec![
                        (input_part.expr.clone(), transform_table[0]),
                        (output_part.expr(), transform_table[1]),
                    ]
                });
                *lookup_counter += 1;
            }
            output.push(Part {
                num_bits: input_part.num_bits,
                cell: output_part.clone(),
                expr: output_part.expr(),
            });
        }
        output
    }

    pub(crate) fn value<F: Field>(
        cells: &[Cell<F>],
        region: &mut KeccakRegion<F>,
        input: Vec<PartValue<F>>,
        do_packing: bool,
        f: fn(&u8) -> u8,
    ) -> Vec<PartValue<F>> {
        let mut output = Vec::new();
        for (idx, input_part) in input.iter().enumerate() {
            let input_bits = &unpack(input_part.value)[0..input_part.num_bits];
            let output_bits = input_bits.iter().map(f).collect::<Vec<_>>();
            let value = if do_packing {
                pack(&output_bits)
            } else {
                F::from(to_bytes::value(&output_bits)[0] as u64)
            };
            let output_part = cells[idx].clone();
            output_part.assign(region, 0, value);
            output.push(PartValue {
                num_bits: input_part.num_bits,
                rot: output_part.rotation,
                value,
            });
        }
        output
    }
}

impl<F: Field> KeccakPackedConfig<F> {
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>, r: Expression<F>) -> Self {
        let q_enable = meta.fixed_column();
        let q_enable_row = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_round = meta.fixed_column();
        let q_absorb = meta.fixed_column();
        let q_round_last = meta.fixed_column();
        let q_padding = meta.fixed_column();
        let q_padding_last = meta.fixed_column();
        let round_cst = meta.fixed_column();

        let keccak_table = KeccakTable::construct(meta);
        let is_final = keccak_table.is_enabled;
        let length = keccak_table.input_len;
        let data_rlc = keccak_table.input_rlc;
        let hash_rlc = keccak_table.output_rlc;

        let normalize_3 = array_init::array_init(|_| meta.lookup_table_column());
        let normalize_4 = array_init::array_init(|_| meta.lookup_table_column());
        let normalize_6 = array_init::array_init(|_| meta.lookup_table_column());
        let chi_base_table = array_init::array_init(|_| meta.lookup_table_column());
        let pack_table = array_init::array_init(|_| meta.lookup_table_column());

        let mut cell_manager = CellManager::new(get_num_rows_per_round());
        let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
        let mut total_lookup_counter = 0;

        let start_new_hash = |meta: &mut VirtualCells<F>, rot| {
            // A new hash is started when the previous hash is done or on the first row
            meta.query_fixed(q_first, rot) + meta.query_advice(is_final, rot)
        };

        // Round constant
        let mut round_cst_expr = 0.expr();
        meta.create_gate("Query round cst", |meta| {
            round_cst_expr = meta.query_fixed(round_cst, Rotation::cur());
            vec![0u64.expr()]
        });
        // State data
        let mut s = vec![vec![0u64.expr(); 5]; 5];
        let mut s_next = vec![vec![0u64.expr(); 5]; 5];
        for i in 0..5 {
            for j in 0..5 {
                let cell = cell_manager.query_cell(meta);
                s[i][j] = cell.expr();
                s_next[i][j] = cell.at_offset(meta, get_num_rows_per_round() as i32).expr();
            }
        }
        // Absorb data
        let absorb_from = cell_manager.query_cell(meta);
        let absorb_data = cell_manager.query_cell(meta);
        let absorb_result = cell_manager.query_cell(meta);
        let mut absorb_from_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        let mut absorb_data_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        let mut absorb_result_next = vec![0u64.expr(); NUM_WORDS_TO_ABSORB];
        for i in 0..NUM_WORDS_TO_ABSORB {
            let rot = ((i + 1) * get_num_rows_per_round()) as i32;
            absorb_from_next[i] = absorb_from.at_offset(meta, rot).expr();
            absorb_data_next[i] = absorb_data.at_offset(meta, rot).expr();
            absorb_result_next[i] = absorb_result.at_offset(meta, rot).expr();
        }

        // Store the pre-state
        let pre_s = s.clone();

        // Absorb
        // The absorption happening at the start of the 24 rounds is done spread out
        // over those 24 rounds. In a single round (in 17 of the 24 rounds) a
        // single word is absorbed so the work is spread out. The absorption is
        // done simply by doing state + data and then normalizing the result to [0,1].
        // We also need to convert the input data into bytes to calculate the input data
        // rlc.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size = get_num_bits_per_absorb_lookup();
        let input = absorb_from.expr() + absorb_data.expr();
        let absorb_fat = split::expr(
            meta,
            &mut cell_manager,
            &mut cb,
            input,
            0,
            part_size,
            false,
            None,
        );
        cell_manager.start_region();
        let absorb_res = transform::expr(
            "absorb",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            absorb_fat,
            normalize_3,
            true,
        );
        cb.require_equal(
            "absorb result",
            decode::expr(absorb_res),
            absorb_result.expr(),
        );
        info!("- Post absorb:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Squeeze
        // The squeezing happening at the end of the 24 rounds is done spread out
        // over those 24 rounds. In a single round (in 4 of the 24 rounds) a
        // single word is converted to bytes.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        // Potential optimization: could do multiple bytes per lookup
        let packed_parts = split::expr(
            meta,
            &mut cell_manager,
            &mut cb,
            absorb_data.expr(),
            0,
            8,
            false,
            None,
        );
        cell_manager.start_region();
        let input_bytes = transform::expr(
            "squeeze unpack",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            packed_parts,
            pack_table
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            true,
        );

        // Padding data
        cell_manager.start_region();
        let mut is_paddings = Vec::new();
        let mut data_rlcs = Vec::new();
        for _ in input_bytes.iter() {
            is_paddings.push(cell_manager.query_cell(meta));
            data_rlcs.push(cell_manager.query_cell(meta));
        }
        info!("- Post padding:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Theta
        // Calculate
        // - `c[i] = s[i][0] + s[i][1] + s[i][2] + s[i][3] + s[i][4]`
        // - `bc[i] = normalize(c)`.
        // - `t[i] = bc[(i + 4) % 5] + rot(bc[(i + 1)% 5], 1)`
        // This is done by splitting the bc values in parts in a way
        // that allows us to also calculate the rotated value "for free".
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size_c = get_num_bits_per_theta_c_lookup();
        let mut c_parts = Vec::new();
        for s in s.iter() {
            // Calculate c and split into parts
            let c = s[0].clone() + s[1].clone() + s[2].clone() + s[3].clone() + s[4].clone();
            c_parts.push(split::expr(
                meta,
                &mut cell_manager,
                &mut cb,
                c,
                1,
                part_size_c,
                false,
                None,
            ));
        }
        // Now calculate `bc` by normalizing `c`
        cell_manager.start_region();
        let mut bc = Vec::new();
        for c in c_parts {
            // Normalize c
            bc.push(transform::expr(
                "theta c",
                meta,
                &mut cell_manager,
                &mut lookup_counter,
                c,
                normalize_6,
                true,
            ));
        }
        // Now do `bc[(i + 4) % 5] + rot(bc[(i + 1) % 5], 1)` using just expressions.
        // We don't normalize the result here. We do it as part of the rho/pi step, even
        // though we would only have to normalize 5 values instead of 25, because of the
        // way the rho/pi and chi steps can be combined it's more efficient to
        // do it there (the max value for chi is 4 already so that's the
        // limiting factor).
        let mut os = vec![vec![0u64.expr(); 5]; 5];
        for i in 0..5 {
            let t = decode::expr(bc[(i + 4) % 5].clone())
                + decode::expr(rotate(bc[(i + 1) % 5].clone(), 1, part_size_c));
            for j in 0..5 {
                os[i][j] = s[i][j].clone() + t.clone();
            }
        }
        s = os.clone();
        info!("- Post theta:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Rho/Pi
        // For the rotation of rho/pi we split up the words like expected, but in a way
        // that allows reusing the same parts in an optimal way for the chi step.
        // We can save quite a few columns by not recombining the parts after rho/pi and
        // re-splitting the words again before chi. Instead we do chi directly
        // on the output parts of rho/pi. For rho/pi specically we do
        // `s[j][2 * i + 3 * j) % 5] = normalize(rot(s[i][j], RHOM[i][j]))`.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        let part_size = get_num_bits_per_base_chi_lookup();
        // To combine the rho/pi/chi steps we have to ensure a specific layout so
        // query those cells here first.
        // For chi we have to do `s[i][j] ^ ((~s[(i+1)%5][j]) & s[(i+2)%5][j])`. `j`
        // remains static but `i` is accessed in a wrap around manner. To do this using
        // multiple rows with lookups in a way that doesn't require any
        // extra additional cells or selectors we have to put all `s[i]`'s on the same
        // row. This isn't that strong of a requirement actually because we the
        // words are split into multipe parts, and so only the parts at the same
        // position of those words need to be on the same row.
        let target_word_sizes = target_part_sizes(part_size);
        let num_word_parts = target_word_sizes.len();
        let mut rho_pi_chi_cells: [[[Vec<Cell<F>>; 5]; 5]; 3] = array_init::array_init(|_| {
            array_init::array_init(|_| array_init::array_init(|_| Vec::new()))
        });
        let mut num_columns = 0;
        let mut column_starts = [0usize; 3];
        for p in 0..3 {
            column_starts[p] = cell_manager.start_region();
            let mut row_idx = 0;
            num_columns = 0;
            for j in 0..5 {
                for _ in 0..num_word_parts {
                    for i in 0..5 {
                        rho_pi_chi_cells[p][i][j]
                            .push(cell_manager.query_cell_at_row(meta, row_idx));
                    }
                    if row_idx == 0 {
                        num_columns += 1;
                    }
                    row_idx = (((row_idx as usize) + 1) % get_num_rows_per_round()) as i32;
                }
            }
        }
        // Do the transformation, resulting in the word parts also being normalized.
        let pi_region_start = cell_manager.start_region();
        let mut os_parts = vec![vec![Vec::new(); 5]; 5];
        for (j, os_part) in os_parts.iter_mut().enumerate() {
            for i in 0..5 {
                // Split s into parts
                let s_parts = split_uniform::expr(
                    meta,
                    &rho_pi_chi_cells[0][j][(2 * i + 3 * j) % 5],
                    &mut cell_manager,
                    &mut cb,
                    s[i][j].clone(),
                    RHO_MATRIX[i][j],
                    part_size,
                    true,
                );
                // Normalize the data to the target cells
                let s_parts = transform_to::expr(
                    "rho/pi",
                    meta,
                    &rho_pi_chi_cells[1][j][(2 * i + 3 * j) % 5],
                    &mut lookup_counter,
                    s_parts.clone(),
                    normalize_4,
                    true,
                );
                os_part[(2 * i + 3 * j) % 5] = s_parts.clone();
            }
        }
        let pi_region_end = cell_manager.start_region();
        // Pi parts range checks
        // To make the uniform stuff work we had to combine some parts together
        // in new cells (see split_uniform). Here we make sure those parts are range
        // checked. Potential improvement: Could combine multiple smaller parts
        // in a single lookup but doesn't save that much.
        for c in pi_region_start..pi_region_end {
            meta.lookup("pi part range check", |_| {
                vec![(cell_manager.columns()[c].expr.clone(), normalize_4[0])]
            });
            lookup_counter += 1;
        }
        info!("- Post rho/pi:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // Chi
        // In groups of 5 columns, we have to do `s[i][j] ^ ((~s[(i+1)%5][j]) &
        // s[(i+2)%5][j])` five times, on each row (no selector needed).
        // This is calculated by making use of `CHI_BASE_LOOKUP_TABLE`.
        let mut lookup_counter = 0;
        let part_size_base = get_num_bits_per_base_chi_lookup();
        for idx in 0..num_columns {
            // First fetch the cells we wan to use
            let mut input: [Expression<F>; 5] = array_init::array_init(|_| 0.expr());
            let mut output: [Expression<F>; 5] = array_init::array_init(|_| 0.expr());
            for c in 0..5 {
                input[c] = cell_manager.columns()[column_starts[1] + idx * 5 + c]
                    .expr
                    .clone();
                output[c] = cell_manager.columns()[column_starts[2] + idx * 5 + c]
                    .expr
                    .clone();
            }
            // Now calculate `a ^ ((~b) & c)` by doing `lookup[3 - 2*a + b - c]`
            for i in 0..5 {
                let input = scatter::expr(3, part_size_base) - 2.expr() * input[i].clone()
                    + input[(i + 1) % 5].clone()
                    - input[(i + 2) % 5].clone().clone();
                let output = output[i].clone();
                meta.lookup("chi base", |_| {
                    vec![
                        (input.clone(), chi_base_table[0]),
                        (output.clone(), chi_base_table[1]),
                    ]
                });
                lookup_counter += 1;
            }
        }
        // Now just decode the parts after the chi transformation done with the lookups
        // above.
        let mut os = vec![vec![0u64.expr(); 5]; 5];
        for (i, os) in os.iter_mut().enumerate() {
            for (j, os) in os.iter_mut().enumerate() {
                let mut parts = Vec::new();
                for idx in 0..num_word_parts {
                    parts.push(Part {
                        num_bits: part_size_base,
                        cell: rho_pi_chi_cells[2][i][j][idx].clone(),
                        expr: rho_pi_chi_cells[2][i][j][idx].expr(),
                    });
                }
                *os = decode::expr(parts);
            }
        }
        s = os.clone();

        // iota
        // Simply do the single xor on state [0][0].
        cell_manager.start_region();
        let part_size = get_num_bits_per_absorb_lookup();
        let input = s[0][0].clone() + round_cst_expr.clone();
        let iota_parts = split::expr(
            meta,
            &mut cell_manager,
            &mut cb,
            input,
            0,
            part_size,
            false,
            None,
        );
        cell_manager.start_region();
        // Could share columns with absorb which may end up using 1 lookup/column
        // fewer...
        s[0][0] = decode::expr(transform::expr(
            "iota",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            iota_parts,
            normalize_3,
            true,
        ));
        // Final results stored in the next row
        for i in 0..5 {
            for j in 0..5 {
                cb.require_equal("next row check", s[i][j].clone(), s_next[i][j].clone());
            }
        }
        info!("- Post chi:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        let mut lookup_counter = 0;
        cell_manager.start_region();

        // Squeeze data
        let squeeze_from = cell_manager.query_cell(meta);
        let mut squeeze_from_prev = vec![0u64.expr(); NUM_WORDS_TO_SQUEEZE];
        for (idx, squeeze_from_prev) in squeeze_from_prev.iter_mut().enumerate() {
            let rot = (-(idx as i32) - 1) * get_num_rows_per_round() as i32;
            *squeeze_from_prev = squeeze_from.at_offset(meta, rot).expr();
        }
        // Squeeze
        // The squeeze happening at the end of the 24 rounds is done spread out
        // over those 24 rounds. In a single round (in 4 of the 24 rounds) a
        // single word is converted to bytes.
        // Potential optimization: could do multiple bytes per lookup
        cell_manager.start_region();
        // Unpack a single word into bytes (for the squeeze)
        // Potential optimization: could do multiple bytes per lookup
        let squeeze_from_parts = split::expr(
            meta,
            &mut cell_manager,
            &mut cb,
            squeeze_from.expr(),
            0,
            8,
            false,
            None,
        );
        cell_manager.start_region();
        let squeeze_bytes = transform::expr(
            "squeeze unpack",
            meta,
            &mut cell_manager,
            &mut lookup_counter,
            squeeze_from_parts,
            pack_table
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            true,
        );
        info!("- Post squeeze:");
        info!("Lookups: {}", lookup_counter);
        info!("Columns: {}", cell_manager.get_width());
        total_lookup_counter += lookup_counter;

        // The round constraints that we've been building up till now
        meta.create_gate("round", |meta| {
            cb.gate(meta.query_fixed(q_round, Rotation::cur()))
        });

        // Absorb
        meta.create_gate("absorb", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let continue_hash = not::expr(start_new_hash(meta, Rotation::cur()));
            let absorb_positions = get_absorb_positions();
            let mut a_slice = 0;
            for j in 0..5 {
                for i in 0..5 {
                    if absorb_positions.contains(&(i, j)) {
                        cb.condition(continue_hash.clone(), |cb| {
                            cb.require_equal(
                                "absorb verify input",
                                absorb_from_next[a_slice].clone(),
                                pre_s[i][j].clone(),
                            );
                        });
                        cb.require_equal(
                            "absorb result copy",
                            select::expr(
                                continue_hash.clone(),
                                absorb_result_next[a_slice].clone(),
                                absorb_data_next[a_slice].clone(),
                            ),
                            s_next[i][j].clone(),
                        );
                        a_slice += 1;
                    } else {
                        cb.require_equal(
                            "absorb state copy",
                            pre_s[i][j].clone() * continue_hash.clone(),
                            s_next[i][j].clone(),
                        );
                    }
                }
            }
            cb.gate(meta.query_fixed(q_absorb, Rotation::cur()))
        });

        // Collect the bytes that are spread out over previous rows
        let mut hash_bytes = Vec::new();
        for i in 0..NUM_WORDS_TO_SQUEEZE {
            for byte in squeeze_bytes.iter() {
                let rot = (-(i as i32) - 1) * get_num_rows_per_round() as i32;
                hash_bytes.push(byte.cell.at_offset(meta, rot).expr());
            }
        }

        // Squeeze
        meta.create_gate("squeeze", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let start_new_hash = start_new_hash(meta, Rotation::cur());
            // The words to squeeze
            let hash_words: Vec<_> = pre_s
                .into_iter()
                .take(4)
                .map(|a| a[0].clone())
                .take(4)
                .collect();
            // Verify if we converted the correct words to bytes on previous rows
            for (idx, word) in hash_words.iter().enumerate() {
                cb.condition(start_new_hash.clone(), |cb| {
                    cb.require_equal(
                        "squeeze verify packed",
                        word.clone(),
                        squeeze_from_prev[idx].clone(),
                    );
                });
            }
            let hash_bytes_le = hash_bytes.into_iter().rev().collect::<Vec<_>>();
            let rlc = compose_rlc::expr(&hash_bytes_le, r.clone());
            cb.condition(start_new_hash, |cb| {
                cb.require_equal(
                    "hash rlc check",
                    rlc,
                    meta.query_advice(hash_rlc, Rotation::cur()),
                );
            });
            cb.gate(meta.query_fixed(q_round_last, Rotation::cur()))
        });

        // Some general input checks
        meta.create_gate("input checks", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_boolean(
                "boolean is_final",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // Enforce fixed values on the first row
        meta.create_gate("first row", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            cb.require_zero(
                "is_final needs to be disabled on the first row",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.gate(meta.query_fixed(q_first, Rotation::cur()))
        });

        // some utility query functions
        let q = |col: Column<Fixed>, meta: &mut VirtualCells<'_, F>| {
            meta.query_fixed(col, Rotation::cur())
        };
        let q_in_round = |col: Column<Fixed>, meta: &mut VirtualCells<'_, F>| {
            (0..get_num_rows_per_round() as i32)
                .map(|i| meta.query_fixed(col, Rotation(-i)))
                .fold(0.expr(), |acc, elem| acc + elem)
        };
        let q_prev_round = |col: Column<Fixed>, meta: &mut VirtualCells<'_, F>| {
            meta.query_fixed(col, Rotation(-(get_num_rows_per_round() as i32)))
        };
        /*
        eg：
            data:
                get_num_rows_per_round: 18
                input: "12345678abc"

            table:
                Note[1]: be careful: is_paddings is not column here! It is [Cell; 8].

        offset  value bytes_left  is_paddings q_enable q_padding_last
        18        1      11          0         1        0 // 1st round begin
        19        2      10          0         0        0
        20        3      9           0         0        0
        21        4      8           0         0        0
        22        5      7           0         0        0
        23        6      6           0         0        0
        24        7      5           0         0        0
        25        8      4           0         0        0
        26        8      4           NA        0        0
        ...
        35        8      4           NA        0        0  // 1st round end
        36        a      3           0         1        1  // 2nd round begin
        37        b      2           0         0        0
        38        c      1           0         0        0
        39        0      0           1         0        0
        40        0      0           1         0        0
        41        0      0           1         0        0
        42        0      0           1         0        0
        43        0      0           1         0        0

             */

        meta.create_gate("hash_id", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            cb.condition(q_in_round(q_first, meta), |cb| {
                cb.require_zero(
                    "hash_id needs to be zero on the first row",
                    meta.query_advice(keccak_table.hash_id, Rotation::cur()),
                );
            });
            cb.condition(
                (q(q_enable, meta) - q(q_first, meta))
                    * meta.query_advice(is_final, Rotation::cur()),
                |cb| {
                    let hash_id = meta.query_advice(keccak_table.hash_id, Rotation::cur());
                    let hash_rlc = meta.query_advice(hash_rlc, Rotation::cur());
                    cb.require_equal("hash_id == hash_output", hash_rlc, hash_id);
                },
            );
            cb.condition(
                q_in_round(q_enable, meta)
                    - q_in_round(q_first, meta)
                    - q(q_enable, meta) * q_prev_round(q_absorb, meta),
                |cb| {
                    let counter = meta.query_advice(keccak_table.hash_id, Rotation::cur());
                    let counter_prev = meta.query_advice(keccak_table.hash_id, Rotation::prev());
                    cb.require_equal(
                        "hash_id keeps same when no new hash input",
                        counter_prev,
                        counter,
                    );
                },
            );
            cb.gate(1.expr())
        });
        meta.create_gate("byte_value", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            for idx in 0..get_num_rows_per_round() {
                cb.condition(
                    q(q_padding, meta) * not::expr(is_paddings[std::cmp::min(idx, 7)].expr()),
                    |cb| {
                        cb.require_equal(
                            "input byte",
                            input_bytes[std::cmp::min(idx, 7)].expr.clone(),
                            meta.query_advice(keccak_table.byte_value, Rotation(idx as i32)),
                        );
                    },
                );
            }
            cb.gate(q(q_enable, meta))
        });
        meta.create_gate("bytes_left", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // TODO: is this needed?
            cb.condition(q_in_round(q_first, meta), |cb| {
                cb.require_zero(
                    "bytes_left needs to be zero on the first row",
                    meta.query_advice(keccak_table.bytes_left, Rotation::cur()),
                );
            });
            // is_paddings only be true when
            cb.condition(q(q_padding, meta), |cb| {
                for i in 0..get_num_rows_per_round() {
                    let bytes_left = meta.query_advice(keccak_table.bytes_left, Rotation(i as i32));
                    let bytes_left_next =
                        meta.query_advice(keccak_table.bytes_left, Rotation(i as i32 + 1));
                    // real input only when !is_paddings[i] && i < 8
                    cb.require_equal(
                        "if not padding, bytes_left decreases by 1, else, stay same",
                        bytes_left_next,
                        bytes_left.clone()
                            - if i < 7 || i == get_num_rows_per_round() - 1 {
                                not::expr(is_paddings[std::cmp::min(i, 7)].expr())
                            } else {
                                0.expr()
                            },
                    );
                    cb.require_zero(
                        "bytes_left should be 0 when padding",
                        bytes_left * is_paddings[std::cmp::min(i, 7)].expr(),
                    );
                }
            });
            cb.condition(
                (q_in_round(q_enable, meta)
                    - q_in_round(q_padding, meta)
                    - q_in_round(q_first, meta))
                    * meta.query_advice(is_final, Rotation::next()),
                |cb| {
                    let bytes_left = meta.query_advice(keccak_table.bytes_left, Rotation::cur());
                    let bytes_left_next =
                        meta.query_advice(keccak_table.bytes_left, Rotation::next());
                    cb.require_equal(
                        "bytes_left should stay same on non absorb round",
                        bytes_left,
                        bytes_left_next,
                    );
                },
            );
            cb.condition(
                q(q_enable, meta) * meta.query_advice(is_final, Rotation::cur()),
                |cb| {
                    let bytes_left = meta.query_advice(keccak_table.bytes_left, Rotation::cur());
                    cb.require_zero("bytes_left should be 0 when is_final", bytes_left);
                },
            );
            cb.gate(1.expr())
        });

        // Enforce logic for when this block is the last block for a hash
        let last_is_padding_in_block = is_paddings.last().unwrap().at_offset(
            meta,
            -(((NUM_ROUNDS + 1 - NUM_WORDS_TO_ABSORB) * get_num_rows_per_round()) as i32),
        );
        meta.create_gate("is final", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // All absorb rows except the first row
            cb.condition(
                meta.query_fixed(q_absorb, Rotation::cur())
                    - meta.query_fixed(q_first, Rotation::cur()),
                |cb| {
                    cb.require_equal(
                        "is_final needs to be the same as the last is_padding in the block",
                        meta.query_advice(is_final, Rotation::cur()),
                        last_is_padding_in_block.expr(),
                    );
                },
            );
            // For all the rows of a round, only the first row can have `is_final == 1`.
            cb.condition(
                (1..get_num_rows_per_round() as i32)
                    .map(|i| meta.query_fixed(q_enable, Rotation(-i)))
                    .fold(0.expr(), |acc, elem| acc + elem),
                |cb| {
                    cb.require_zero(
                        "is_final only when q_enable",
                        meta.query_advice(is_final, Rotation::cur()),
                    );
                },
            );
            cb.gate(1.expr())
        });

        // Padding
        // May be cleaner to do this padding logic in the byte conversion lookup but
        // currently easier to do it like this.
        let prev_is_padding = is_paddings
            .last()
            .unwrap()
            .at_offset(meta, -(get_num_rows_per_round() as i32));
        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let q_padding_last = meta.query_fixed(q_padding_last, Rotation::cur());

            // All padding selectors need to be boolean
            for is_padding in is_paddings.iter() {
                cb.condition(meta.query_fixed(q_enable, Rotation::cur()), |cb| {
                    cb.require_boolean("is_padding boolean", is_padding.expr());
                });
            }
            // This last padding selector will be used on the first round row so needs to be
            // zero
            cb.condition(meta.query_fixed(q_absorb, Rotation::cur()), |cb| {
                cb.require_zero(
                    "last is_padding should be zero on absorb rows",
                    is_paddings.last().unwrap().expr(),
                );
            });
            // Now for each padding selector
            for idx in 0..is_paddings.len() {
                // Previous padding selector can be on the previous row
                let is_padding_prev = if idx == 0 {
                    prev_is_padding.expr()
                } else {
                    is_paddings[idx - 1].expr()
                };
                let is_first_padding = is_paddings[idx].expr() - is_padding_prev.clone();

                // Check padding transition 0 -> 1 done only once
                cb.condition(q_padding.expr(), |cb| {
                    cb.require_boolean("padding step boolean", is_first_padding.clone());
                });

                // Padding start/intermediate/end byte checks
                if idx == is_paddings.len() - 1 {
                    // These can be combined in the future, but currently this would increase the
                    // degree by one Padding start/intermediate byte, all
                    // padding rows except the last one
                    cb.condition(
                        and::expr([
                            q_padding.expr() - q_padding_last.expr(),
                            is_paddings[idx].expr(),
                        ]),
                        |cb| {
                            // Input bytes need to be zero, or one if this is the first padding byte
                            cb.require_equal(
                                "padding start/intermediate byte last byte",
                                input_bytes[idx].expr.clone(),
                                is_first_padding.expr(),
                            );
                        },
                    );
                    // Padding start/end byte, only on the last padding row
                    cb.condition(
                        and::expr([q_padding_last.expr(), is_paddings[idx].expr()]),
                        |cb| {
                            // The input byte needs to be 128, unless it's also the first padding
                            // byte then it's 129
                            cb.require_equal(
                                "padding start/end byte",
                                input_bytes[idx].expr.clone(),
                                is_first_padding.expr() + 128.expr(),
                            );
                        },
                    );
                } else {
                    // Padding start/intermediate byte
                    cb.condition(
                        and::expr([q_padding.expr(), is_paddings[idx].expr()]),
                        |cb| {
                            // Input bytes need to be zero, or one if this is the first padding byte
                            cb.require_equal(
                                "padding start/intermediate byte",
                                input_bytes[idx].expr.clone(),
                                is_first_padding.expr(),
                            );
                        },
                    );
                }
            }
            cb.gate(1.expr())
        });

        // Length and input data rlc
        meta.create_gate("length and data rlc", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let start_new_hash_prev =
                start_new_hash(meta, Rotation(-(get_num_rows_per_round() as i32)));
            let length_prev =
                meta.query_advice(length, Rotation(-(get_num_rows_per_round() as i32)));
            let length = meta.query_advice(length, Rotation::cur());
            let data_rlc_prev =
                meta.query_advice(data_rlc, Rotation(-(get_num_rows_per_round() as i32)));
            let data_rlc = meta.query_advice(data_rlc, Rotation::cur());

            // Update the length/data_rlc on rows where we absorb data
            cb.condition(q_padding.expr(), |cb| {
                // Length increases by the number of bytes that aren't padding
                cb.require_equal(
                    "update length",
                    length.clone(),
                    length_prev.clone() * not::expr(start_new_hash_prev.expr())
                        + sum::expr(
                            is_paddings
                                .iter()
                                .map(|is_padding| not::expr(is_padding.expr())),
                        ),
                );
                // Use intermediate cells to keep the degree low
                let mut new_data_rlc =
                    data_rlc_prev.clone() * not::expr(start_new_hash_prev.expr());
                cb.require_equal("initial data rlc", data_rlcs[0].expr(), new_data_rlc);
                new_data_rlc = data_rlcs[0].expr();
                for (idx, (byte, is_padding)) in
                    input_bytes.iter().zip(is_paddings.iter()).enumerate()
                {
                    new_data_rlc = select::expr(
                        is_padding.expr(),
                        new_data_rlc.clone(),
                        new_data_rlc.clone() * r.clone() + byte.expr.clone(),
                    );
                    if idx < data_rlcs.len() - 1 {
                        cb.require_equal(
                            "intermediate data rlc",
                            data_rlcs[idx + 1].expr(),
                            new_data_rlc,
                        );
                        new_data_rlc = data_rlcs[idx + 1].expr();
                    }
                }
                cb.require_equal("update data rlc", data_rlc.clone(), new_data_rlc);
            });
            // Keep length/data_rlc the same on rows where we don't absorb data
            cb.condition(
                and::expr([
                    meta.query_fixed(q_enable, Rotation::cur())
                        - meta.query_fixed(q_first, Rotation::cur()),
                    not::expr(q_padding),
                ]),
                |cb| {
                    cb.require_equal("length equality check", length.clone(), length_prev.clone());
                    cb.require_equal(
                        "data_rlc equality check",
                        data_rlc.clone(),
                        data_rlc_prev.clone(),
                    );
                },
            );
            cb.gate(1.expr())
        });

        info!("Degree: {}", meta.degree());
        info!("Minimum rows: {}", meta.minimum_rows());
        info!("Total Lookups: {}", total_lookup_counter);
        info!("Total Columns: {}", cell_manager.get_width());
        info!("num unused cells: {}", cell_manager.get_num_unused_cells());
        info!("part_size absorb: {}", get_num_bits_per_absorb_lookup());
        info!("part_size theta: {}", get_num_bits_per_theta_c_lookup());
        info!(
            "part_size theta c: {}",
            get_num_bits_per_lookup(THETA_C_LOOKUP_RANGE)
        );
        info!("part_size theta t: {}", get_num_bits_per_lookup(4));
        info!("part_size rho/pi: {}", get_num_bits_per_rho_pi_lookup());
        info!("part_size chi base: {}", get_num_bits_per_base_chi_lookup());
        info!(
            "uniform part sizes: {:?}",
            target_part_sizes(get_num_bits_per_theta_c_lookup())
        );

        KeccakPackedConfig {
            q_enable,
            q_enable_row,
            q_first,
            q_round,
            q_absorb,
            q_round_last,
            q_padding,
            q_padding_last,
            keccak_table,
            cell_manager,
            round_cst,
            normalize_3,
            normalize_4,
            normalize_6,
            chi_base_table,
            pack_table,
            _marker: PhantomData,
        }
    }

    /// Sets the witness using the data to be hashed
    /// The `capacity`, when enabled, sets up the circuit to support a fixed
    /// number of permutations/keccak_f's, independently of the permutations
    /// required by `inputs`.
    pub fn assign_from_witness(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: &[Vec<u8>],
        r: F,
        capacity: Option<usize>,
    ) -> Result<(), Error> {
        let witness = multi_keccak(inputs, r, capacity)?;
        self.assign(layouter, &witness)
    }

    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &[KeccakRow<F>],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign keccak rows",
            |mut region| {
                for (offset, keccak_row) in witness.iter().enumerate() {
                    self.set_row(&mut region, offset, keccak_row)?;
                }
                Ok(())
            },
        )
    }

    fn set_row(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        row: &KeccakRow<F>,
    ) -> Result<(), Error> {
        // Fixed selectors
        for (name, column, value) in &[
            ("q_enable", self.q_enable, F::from(row.q_enable)),
            ("q_first", self.q_first, F::from(offset == 0)),
            ("q_round", self.q_round, F::from(row.q_round)),
            ("q_round_last", self.q_round_last, F::from(row.q_round_last)),
            ("q_absorb", self.q_absorb, F::from(row.q_absorb)),
            ("q_padding", self.q_padding, F::from(row.q_padding)),
            (
                "q_padding_last",
                self.q_padding_last,
                F::from(row.q_padding_last),
            ),
        ] {
            region.assign_fixed(
                || format!("assign {} {}", name, offset),
                *column,
                offset,
                || Value::known(*value),
            )?;
        }

        self.keccak_table.assign_row(
            region,
            offset,
            [
                F::from(row.is_final),
                row.data_rlc,
                F::from(row.length as u64),
                row.hash_rlc,
                row.hash_id,
                row.value,
                row.bytes_left,
            ],
        )?;

        // Cell values
        for (idx, (bit, column)) in row
            .cell_values
            .iter()
            .zip(self.cell_manager.columns())
            .enumerate()
        {
            region.assign_advice(
                || format!("assign lookup value {} {}", idx, offset),
                column.advice,
                offset,
                || Value::known(*bit),
            )?;
        }

        // Round constant
        region.assign_fixed(
            || format!("assign round cst {}", offset),
            self.round_cst,
            offset,
            || Value::known(row.round_cst),
        )?;

        Ok(())
    }

    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        load_normalize_table(layouter, "normalize_6", &self.normalize_6, 6u64)?;
        load_normalize_table(layouter, "normalize_4", &self.normalize_4, 4u64)?;
        load_normalize_table(layouter, "normalize_3", &self.normalize_3, 3u64)?;
        load_lookup_table(
            layouter,
            "chi base",
            &self.chi_base_table,
            get_num_bits_per_base_chi_lookup(),
            &CHI_BASE_LOOKUP_TABLE,
        )?;
        load_pack_table(layouter, &self.pack_table)
    }
}

fn keccak<F: Field>(rows: &mut Vec<KeccakRow<F>>, bytes: &[u8], r: F) {
    let mut bits = into_bits(bytes);
    let mut s = [[F::zero(); 5]; 5];
    let absorb_positions = get_absorb_positions();
    let num_bytes_in_last_block = bytes.len() % RATE;
    let two = F::from(2u64);

    // Padding
    bits.push(1);
    while (bits.len() + 1) % RATE_IN_BITS != 0 {
        bits.push(0);
    }
    bits.push(1);

    let mut hash_out: [u8; 32] = ethers_core::utils::keccak256(bytes);
    hash_out.reverse();
    let hash_id = rlc::value(&hash_out, r);
    let mut length = 0usize;
    let mut data_rlc = F::zero();
    let chunks = bits.chunks(RATE_IN_BITS);
    let num_chunks = chunks.len();
    for (idx, chunk) in chunks.enumerate() {
        let is_final_block = idx == num_chunks - 1;

        let mut absorb_rows = Vec::new();
        // Absorb
        for (idx, &(i, j)) in absorb_positions.iter().enumerate() {
            let absorb = pack(&chunk[idx * 64..(idx + 1) * 64]);
            let from = s[i][j];
            s[i][j] = field_xor(s[i][j], absorb);
            absorb_rows.push(AbsorbData {
                from,
                absorb,
                result: s[i][j],
            });
        }

        let mut hash_words: Vec<F> = Vec::new();

        let mut cell_managers = Vec::new();
        let mut regions = Vec::new();

        let mut hash_rlc = F::zero();
        let mut round_lengths = Vec::new();
        let mut round_data_rlcs = Vec::new();
        for round in 0..NUM_ROUNDS + 1 {
            let mut cell_manager = CellManager::new(get_num_rows_per_round());
            let mut region = KeccakRegion::new();

            let mut absorb_row = AbsorbData::default();
            if round < NUM_WORDS_TO_ABSORB {
                absorb_row = absorb_rows[round].clone();
            }

            // State data
            for s in &s {
                for s in s {
                    let cell = cell_manager.query_cell_value();
                    cell.assign(&mut region, 0, *s);
                }
            }

            // Absorb data
            let absorb_from = cell_manager.query_cell_value();
            let absorb_data = cell_manager.query_cell_value();
            let absorb_result = cell_manager.query_cell_value();
            absorb_from.assign(&mut region, 0, absorb_row.from);
            absorb_data.assign(&mut region, 0, absorb_row.absorb);
            absorb_result.assign(&mut region, 0, absorb_row.result);

            // Absorb
            cell_manager.start_region();
            let part_size = get_num_bits_per_absorb_lookup();
            let input = absorb_row.from + absorb_row.absorb;
            let absorb_fat = split::value(
                &mut cell_manager,
                &mut region,
                input,
                0,
                part_size,
                false,
                None,
            );
            cell_manager.start_region();
            let _absorb_result = transform::value(
                &mut cell_manager,
                &mut region,
                absorb_fat.clone(),
                true,
                |v| v & 1,
                true,
            );

            // Padding
            cell_manager.start_region();
            // Unpack a single word into bytes (for the absorption)
            // Potential optimization: could do multiple bytes per lookup
            let packed = split::value(
                &mut cell_manager,
                &mut region,
                absorb_row.absorb,
                0,
                8,
                false,
                None,
            );
            cell_manager.start_region();
            let input_bytes =
                transform::value(&mut cell_manager, &mut region, packed, false, |v| *v, true);
            cell_manager.start_region();
            let mut is_paddings = Vec::new();
            let mut data_rlcs = Vec::new();
            for _ in input_bytes.iter() {
                is_paddings.push(cell_manager.query_cell_value());
                data_rlcs.push(cell_manager.query_cell_value());
            }
            if round < NUM_WORDS_TO_ABSORB {
                let mut paddings = Vec::new();
                for (padding_idx, is_padding) in is_paddings.iter_mut().enumerate() {
                    let byte_idx = round * 8 + padding_idx;
                    let padding = if is_final_block && byte_idx >= num_bytes_in_last_block {
                        true
                    } else {
                        length += 1;
                        false
                    };
                    paddings.push(padding);
                    is_padding.assign(&mut region, 0, if padding { F::one() } else { F::zero() });
                }

                data_rlcs[0].assign(&mut region, 0, data_rlc);
                for (idx, (byte, padding)) in input_bytes.iter().zip(paddings.iter()).enumerate() {
                    if !*padding {
                        let byte_value: F = byte.value;
                        data_rlc = data_rlc * r + byte_value;
                    }
                    if idx < data_rlcs.len() - 1 {
                        data_rlcs[idx + 1].assign(&mut region, 0, data_rlc);
                    }
                }
            }
            cell_manager.start_region();

            if round != NUM_ROUNDS {
                // Theta
                let part_size = get_num_bits_per_theta_c_lookup();
                let mut bcf = Vec::new();
                for s in &s {
                    let c = s[0] + s[1] + s[2] + s[3] + s[4];
                    let bc_fat =
                        split::value(&mut cell_manager, &mut region, c, 1, part_size, false, None);
                    bcf.push(bc_fat);
                }
                cell_manager.start_region();
                let mut bc = Vec::new();
                for bc_fat in bcf {
                    let bc_norm = transform::value(
                        &mut cell_manager,
                        &mut region,
                        bc_fat.clone(),
                        true,
                        |v| v & 1,
                        true,
                    );
                    bc.push(bc_norm);
                }
                cell_manager.start_region();
                let mut os = [[F::zero(); 5]; 5];
                for i in 0..5 {
                    let t = decode::value(bc[(i + 4) % 5].clone())
                        + decode::value(rotate(bc[(i + 1) % 5].clone(), 1, part_size));
                    for j in 0..5 {
                        os[i][j] = s[i][j] + t;
                    }
                }
                s = os;
                cell_manager.start_region();

                // Rho/Pi
                let part_size = get_num_bits_per_base_chi_lookup();
                let target_word_sizes = target_part_sizes(part_size);
                let num_word_parts = target_word_sizes.len();
                let mut rho_pi_chi_cells: [[[Vec<Cell<F>>; 5]; 5]; 3] =
                    array_init::array_init(|_| {
                        array_init::array_init(|_| array_init::array_init(|_| Vec::new()))
                    });
                let mut column_starts = [0usize; 3];
                for p in 0..3 {
                    column_starts[p] = cell_manager.start_region();
                    let mut row_idx = 0;
                    for j in 0..5 {
                        for _ in 0..num_word_parts {
                            for i in 0..5 {
                                rho_pi_chi_cells[p][i][j]
                                    .push(cell_manager.query_cell_value_at_row(row_idx as i32));
                            }
                            row_idx = (row_idx + 1) % get_num_rows_per_round();
                        }
                    }
                }
                cell_manager.start_region();
                let mut os_parts: [[Vec<PartValue<F>>; 5]; 5] =
                    array_init::array_init(|_| array_init::array_init(|_| Vec::new()));
                for (j, os_part) in os_parts.iter_mut().enumerate() {
                    for i in 0..5 {
                        let s_parts = split_uniform::value(
                            &rho_pi_chi_cells[0][j][(2 * i + 3 * j) % 5],
                            &mut cell_manager,
                            &mut region,
                            s[i][j],
                            RHO_MATRIX[i][j],
                            part_size,
                            true,
                        );

                        let s_parts = transform_to::value(
                            &rho_pi_chi_cells[1][j][(2 * i + 3 * j) % 5],
                            &mut region,
                            s_parts.clone(),
                            true,
                            |v| v & 1,
                        );
                        os_part[(2 * i + 3 * j) % 5] = s_parts.clone();
                    }
                }
                cell_manager.start_region();

                // Chi
                let part_size_base = get_num_bits_per_base_chi_lookup();
                let three_packed = pack::<F>(&vec![3u8; part_size_base]);
                let mut os = [[F::zero(); 5]; 5];
                for j in 0..5 {
                    for i in 0..5 {
                        let mut s_parts = Vec::new();
                        for ((part_a, part_b), part_c) in os_parts[i][j]
                            .iter()
                            .zip(os_parts[(i + 1) % 5][j].iter())
                            .zip(os_parts[(i + 2) % 5][j].iter())
                        {
                            let value =
                                three_packed - two * part_a.value + part_b.value - part_c.value;
                            s_parts.push(PartValue {
                                num_bits: part_size_base,
                                rot: j as i32,
                                value,
                            });
                        }
                        os[i][j] = decode::value(transform_to::value(
                            &rho_pi_chi_cells[2][i][j],
                            &mut region,
                            s_parts.clone(),
                            true,
                            |v| CHI_BASE_LOOKUP_TABLE[*v as usize],
                        ));
                    }
                }
                s = os;
                cell_manager.start_region();

                // iota
                let part_size = get_num_bits_per_absorb_lookup();
                let input = s[0][0] + pack_u64::<F>(ROUND_CST[round]);
                let iota_parts = split::value::<F>(
                    &mut cell_manager,
                    &mut region,
                    input,
                    0,
                    part_size,
                    false,
                    None,
                );
                cell_manager.start_region();
                s[0][0] = decode::value(transform::value(
                    &mut cell_manager,
                    &mut region,
                    iota_parts.clone(),
                    true,
                    |v| v & 1,
                    true,
                ));
            }

            // The rlc of the hash
            let is_final = is_final_block && round == NUM_ROUNDS;
            hash_rlc = if is_final {
                let hash_bytes_le = s
                    .into_iter()
                    .take(4)
                    .flat_map(|a| to_bytes::value(&unpack(a[0])))
                    .rev()
                    .collect::<Vec<_>>();
                debug_assert_eq!(hash_bytes_le, hash_out.to_vec());
                rlc::value(&hash_bytes_le, r)
            } else {
                F::zero()
            };

            // The words to squeeze out
            hash_words = s.into_iter().take(4).map(|a| a[0]).take(4).collect();
            round_lengths.push(length);
            round_data_rlcs.push(data_rlc);

            cell_managers.push(cell_manager);
            regions.push(region);
        }

        // Now that we know the state at the end of the rounds, set the squeeze data
        let num_rounds = cell_managers.len();
        for (idx, word) in hash_words.iter().enumerate() {
            let cell_manager = &mut cell_managers[num_rounds - 2 - idx];
            let region = &mut regions[num_rounds - 2 - idx];

            cell_manager.start_region();
            let squeeze_packed = cell_manager.query_cell_value();
            squeeze_packed.assign(region, 0, *word);

            cell_manager.start_region();
            let packed = split::value(cell_manager, region, *word, 0, 8, false, None);
            cell_manager.start_region();
            transform::value(cell_manager, region, packed, false, |v| *v, true);
        }

        for round in 0..NUM_ROUNDS + 1 {
            let round_cst = pack_u64(ROUND_CST[round]);
            for row_idx in 0..get_num_rows_per_round() {
                let byte_idx = if round < NUM_WORDS_TO_ABSORB {
                    round * 8 + std::cmp::min(row_idx, 7)
                } else {
                    NUM_WORDS_TO_ABSORB * 8
                } + idx * NUM_WORDS_TO_ABSORB * 8;

                let byte = if byte_idx >= bytes.len() {
                    0
                } else {
                    bytes[byte_idx]
                };
                let bytes_left = if byte_idx >= bytes.len() {
                    0
                } else {
                    bytes.len() - byte_idx
                };
                rows.push(KeccakRow {
                    q_enable: row_idx == 0,
                    q_enable_row: true,
                    q_round: row_idx == 0 && round < NUM_ROUNDS,
                    q_absorb: row_idx == 0 && round == NUM_ROUNDS,
                    q_round_last: row_idx == 0 && round == NUM_ROUNDS,
                    q_padding: row_idx == 0 && round < NUM_WORDS_TO_ABSORB,
                    q_padding_last: row_idx == 0 && round == NUM_WORDS_TO_ABSORB - 1,
                    round_cst,
                    is_final: is_final_block && round == NUM_ROUNDS && row_idx == 0,
                    length: round_lengths[round],
                    data_rlc: round_data_rlcs[round],
                    hash_rlc,
                    cell_values: regions[round].rows[row_idx].clone(),
                    value: F::from_u128(byte as u128),
                    // from len to 1
                    bytes_left: F::from_u128(bytes_left as u128),
                    hash_id,
                });
                {
                    let mut r = rows.last().unwrap().clone();
                    r.cell_values.clear();
                    log::trace!(
                        "offset {:?} row idx {} row {:?}",
                        rows.len() - 1,
                        row_idx,
                        r
                    );
                }
            }
            log::trace!(" = = = = = = round {} end", round);
        }
        log::trace!(" ====================== chunk {} end", idx);
    }

    let hash_bytes = s
        .into_iter()
        .take(4)
        .map(|a| {
            pack_with_base::<F>(&unpack(a[0]), 2)
                .to_repr()
                .into_iter()
                .take(8)
                .collect::<Vec<_>>()
                .to_vec()
        })
        .collect::<Vec<_>>();
    debug!("hash: {:x?}", &(hash_bytes[0..4].concat()));
    debug!("data rlc: {:x?}", data_rlc);
}

fn multi_keccak<F: Field>(
    bytes: &[Vec<u8>],
    r: F,
    capacity: Option<usize>,
) -> Result<Vec<KeccakRow<F>>, Error> {
    let mut rows: Vec<KeccakRow<F>> = Vec::new();
    // Dummy first row so that the initial data is absorbed
    // The initial data doesn't really matter, `is_final` just needs to be disabled.
    for idx in 0..get_num_rows_per_round() {
        rows.push(KeccakRow {
            q_enable: idx == 0,
            q_enable_row: true,
            q_round: false,
            q_absorb: idx == 0,
            q_round_last: false,
            q_padding: false,
            q_padding_last: false,
            round_cst: F::zero(),
            is_final: false,
            length: 0usize,
            data_rlc: F::zero(),
            hash_rlc: F::zero(),
            cell_values: Vec::new(),
            hash_id: F::zero(),
            value: F::zero(),
            bytes_left: F::zero(),
        });
    }
    // Actual keccaks
    for bytes in bytes.iter() {
        keccak(&mut rows, bytes, r);
    }
    if let Some(capacity) = capacity {
        // Pad with no data hashes to the expected capacity
        while rows.len() < (1 + capacity * (NUM_ROUNDS + 1)) * get_num_rows_per_round() {
            keccak(&mut rows, &[], r);
        }
        // Check that we are not over capacity
        if rows.len() > (1 + capacity * (NUM_ROUNDS + 1)) * get_num_rows_per_round() {
            return Err(Error::BoundsFailure);
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    fn verify<F: Field>(k: u32, inputs: Vec<Vec<u8>>, success: bool) {
        let mut circuit = KeccakPackedCircuit::new(2usize.pow(k));
        circuit.generate_witness(&inputs);

        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        let verify_result = prover.verify();
        if verify_result.is_ok() != success {
            if let Some(errors) = verify_result.err() {
                for error in errors.iter() {
                    println!("{}", error);
                }
            }
            panic!();
        }
    }

    #[test]
    fn packed_multi_keccak_simple() {
        let k = 14;
        let inputs = vec![
            vec![],
            (0u8..1).collect::<Vec<_>>(),
            (0u8..135).collect::<Vec<_>>(),
            (0u8..136).collect::<Vec<_>>(),
            (0u8..200).collect::<Vec<_>>(),
        ];
        verify::<Fr>(k, inputs, true);
    }
}
