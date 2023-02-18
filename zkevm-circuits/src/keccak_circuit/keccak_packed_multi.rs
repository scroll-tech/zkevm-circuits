use super::{cell_manager::*, param::*, util::*};
use crate::evm_circuit::util::rlc;
use crate::util::Challenges;
use eth_types::Field;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use log::{debug, trace};
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::ParallelIterator;
use std::{env::var, vec};

const MAX_DEGREE: usize = 9;

pub(crate) fn get_num_rows_per_round() -> usize {
    var("KECCAK_ROWS")
        .unwrap_or_else(|_| "12".to_string())
        .parse()
        .expect("Cannot parse KECCAK_ROWS env var as usize")
}

pub(crate) fn get_num_bits_per_absorb_lookup() -> usize {
    get_num_bits_per_lookup(ABSORB_LOOKUP_RANGE)
}

pub(crate) fn get_num_bits_per_theta_c_lookup() -> usize {
    get_num_bits_per_lookup(THETA_C_LOOKUP_RANGE)
}

pub(crate) fn get_num_bits_per_rho_pi_lookup() -> usize {
    get_num_bits_per_lookup(CHI_BASE_LOOKUP_RANGE.max(RHO_PI_LOOKUP_RANGE))
}

pub(crate) fn get_num_bits_per_base_chi_lookup() -> usize {
    get_num_bits_per_lookup(CHI_BASE_LOOKUP_RANGE.max(RHO_PI_LOOKUP_RANGE))
}

/// AbsorbData
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct AbsorbData<F: Field> {
    pub(crate) from: F,
    pub(crate) absorb: F,
    pub(crate) result: F,
}

/// SqueezeData
#[derive(Clone, Default, Debug, PartialEq)]
pub(crate) struct SqueezeData<F: Field> {
    packed: F,
}

/// KeccakRow
#[derive(Clone, Debug)]
pub struct KeccakRow<F: Field> {
    pub(crate) q_enable: bool,
    pub(crate) q_round: bool,
    pub(crate) q_absorb: bool,
    pub(crate) q_round_last: bool,
    pub(crate) q_padding: bool,
    pub(crate) q_padding_last: bool,
    pub(crate) round_cst: F,
    pub(crate) is_final: bool,
    pub(crate) cell_values: Vec<F>,
    pub(crate) length: usize,
    pub(crate) data_rlc: Value<F>,
    pub(crate) hash_rlc: Value<F>,
}

/// Part
#[derive(Clone, Debug)]
pub(crate) struct Part<F: Field> {
    pub(crate) cell: Cell<F>,
    pub(crate) expr: Expression<F>,
    pub(crate) num_bits: usize,
}

/// Part Value
#[derive(Clone, Copy, Debug)]
pub(crate) struct PartValue<F: Field> {
    pub(crate) value: F,
    pub(crate) rot: i32,
    pub(crate) num_bits: usize,
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

/// Recombines parts back together
pub(crate) mod decode {
    use super::{Part, PartValue};
    use crate::keccak_circuit::param::BIT_COUNT;
    use crate::util::Expr;
    use eth_types::Field;
    use halo2_proofs::plonk::Expression;

    pub(crate) fn expr<F: Field>(parts: Vec<Part<F>>) -> Expression<F> {
        parts.iter().rev().fold(0.expr(), |acc, part| {
            acc * F::from(1u64 << (BIT_COUNT * part.num_bits)) + part.expr.clone()
        })
    }

    pub(crate) fn value<F: Field>(parts: Vec<PartValue<F>>) -> F {
        parts.iter().rev().fold(F::zero(), |acc, part| {
            acc * F::from(1u64 << (BIT_COUNT * part.num_bits)) + part.value
        })
    }
}

/// Splits a word into parts
pub(crate) mod split {
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
pub(crate) mod split_uniform {
    use super::{decode, target_part_sizes, Cell, CellManager, KeccakRegion, Part, PartValue};
    use crate::keccak_circuit::param::BIT_COUNT;
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
                    + part_b.expr() * F::from(1u64 << (BIT_COUNT * word_part.bits.len()));
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

                let value = value_a + value_b * (1u64 << (BIT_COUNT * word_part.bits.len()));

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
pub(crate) mod transform {
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
pub(crate) mod transform_to {
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

fn keccak_rows<F: Field>(bytes: &[u8], challenges: Challenges<Value<F>>) -> Vec<KeccakRow<F>> {
    let mut rows = Vec::new();
    keccak(&mut rows, bytes, challenges);
    rows
}

pub(crate) fn keccak<F: Field>(
    rows: &mut Vec<KeccakRow<F>>,
    bytes: &[u8],
    challenges: Challenges<Value<F>>,
) {
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

    let mut length = 0usize;
    let mut data_rlc = Value::known(F::zero());
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

        let mut hash_rlc = Value::known(F::zero());
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
            let mut data_rlcs = vec![Value::known(F::zero()); get_num_rows_per_round()];
            for _ in input_bytes.iter() {
                is_paddings.push(cell_manager.query_cell_value());
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

                data_rlcs[NUM_BYTES_PER_WORD] = data_rlc; // Start at 0 or forward the previous value.
                for (idx, (byte, padding)) in input_bytes.iter().zip(paddings.iter()).enumerate() {
                    if !*padding {
                        let byte_value = Value::known(byte.value);
                        data_rlc = data_rlc * challenges.keccak_input() + byte_value;
                    }
                    data_rlcs[NUM_BYTES_PER_WORD - (idx + 1)] = data_rlc; // data_rlc_after_this_byte
                }
            } else {
                // In rounds without inputs, forward the previous value.
                data_rlcs[0] = data_rlc;
            }
            // Other positions of data_rlcs are not constrained and we leave them at 0.

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
                challenges
                    .evm_word()
                    .map(|challenge_value| rlc::value(&hash_bytes_le, challenge_value))
            } else {
                Value::known(F::zero())
            };

            // The words to squeeze out
            hash_words = s.into_iter().take(4).map(|a| a[0]).take(4).collect();
            round_lengths.push(length);
            round_data_rlcs.push(data_rlcs);

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
                rows.push(KeccakRow {
                    q_enable: row_idx == 0,
                    q_round: row_idx == 0 && round < NUM_ROUNDS,
                    q_absorb: row_idx == 0 && round == NUM_ROUNDS,
                    q_round_last: row_idx == 0 && round == NUM_ROUNDS,
                    q_padding: row_idx == 0 && round < NUM_WORDS_TO_ABSORB,
                    q_padding_last: row_idx == 0 && round == NUM_WORDS_TO_ABSORB - 1,
                    round_cst,
                    is_final: is_final_block && round == NUM_ROUNDS && row_idx == 0,
                    length: round_lengths[round],
                    data_rlc: round_data_rlcs[round][row_idx],
                    hash_rlc,
                    cell_values: regions[round].rows[row_idx].clone(),
                });
            }
        }
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
    trace!("hash: {:x?}", &(hash_bytes[0..4].concat()));
    trace!("data rlc: {:x?}", data_rlc);
}

/// ...
pub fn multi_keccak<F: Field>(
    bytes: &[Vec<u8>],
    challenges: Challenges<Value<F>>,
    capacity: Option<usize>,
) -> Result<Vec<KeccakRow<F>>, Error> {
    log::info!("multi_keccak assign with capacity: {:?}", capacity);
    let mut rows: Vec<KeccakRow<F>> = Vec::new();
    if let Some(capacity) = capacity {
        rows.reserve((1 + capacity * (NUM_ROUNDS + 1)) * get_num_rows_per_round());
    }
    // Dummy first row so that the initial data is absorbed
    // The initial data doesn't really matter, `is_final` just needs to be disabled.
    for idx in 0..get_num_rows_per_round() {
        rows.push(KeccakRow {
            q_enable: idx == 0,
            q_round: false,
            q_absorb: idx == 0,
            q_round_last: false,
            q_padding: false,
            q_padding_last: false,
            round_cst: F::zero(),
            is_final: false,
            length: 0usize,
            data_rlc: Value::known(F::zero()),
            hash_rlc: Value::known(F::zero()),
            cell_values: Vec::new(),
        });
    }

    // Dedup actual keccaks
    /*
    let inputs_len: usize = bytes.iter().map(|k| k.len()).sum();
    let inputs_num = bytes.len();
    for (idx, bytes) in bytes.iter().enumerate() {
        debug!("{}th keccak is of len {}", idx, bytes.len());
    }
    let bytes: Vec<_> = bytes.iter().unique().collect();
    let inputs_len2: usize = bytes.iter().map(|k| k.len()).sum();
    let inputs_num2 = bytes.len();
    debug!("after dedup inputs, input num {inputs_num}->{inputs_num2}, input total len {inputs_len}->{inputs_len2}");
    */

    // TODO: optimize the `extend` using Iter?
    let real_rows: Vec<_> = bytes
        .par_iter()
        .flat_map_iter(|bytes| keccak_rows(bytes, challenges))
        .collect();
    rows.extend(real_rows.into_iter());
    debug!("keccak rows len without padding: {}", rows.len());
    if let Some(capacity) = capacity {
        let rows_for_empty = keccak_rows(&[], challenges);
        // Pad with no data hashes to the expected capacity
        while rows.len() < (1 + capacity * (NUM_ROUNDS + 1)) * get_num_rows_per_round() {
            rows.extend(rows_for_empty.iter().cloned())
        }
        // Check that we are not over capacity
        if rows.len() > (1 + capacity * (NUM_ROUNDS + 1)) * get_num_rows_per_round() {
            return Err(Error::BoundsFailure);
        }
    }
    debug!("keccak witgen done");
    Ok(rows)
}
