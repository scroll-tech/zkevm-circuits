//! The keccak circuit implementation.
mod cell_manager;
/// Keccak packed multi
pub mod keccak_packed_multi;
mod param;
mod table;
#[cfg(test)]
mod test;
/// Util
mod util;

use std::marker::PhantomData;
pub use KeccakCircuitConfig as KeccakConfig;

use self::{cell_manager::*, keccak_packed_multi::*, param::*, table::*, util::*};
use crate::{
    evm_circuit::util::constraint_builder::BaseConstraintBuilder,
    table::KeccakTable,
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};
use eth_types::Field;
use gadgets::util::{and, not, select, sum, Expr};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, TableColumn, VirtualCells},
    poly::Rotation,
};
use log::info;

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};

/// KeccakConfig
#[derive(Clone, Debug)]
pub struct KeccakCircuitConfig<F> {
    q_enable: Column<Fixed>,
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

/// Circuit configuration arguments
pub struct KeccakCircuitConfigArgs<F: Field> {
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// Challenges randomness
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for KeccakCircuitConfig<F> {
    type ConfigArgs = KeccakCircuitConfigArgs<F>;

    /// Return a new KeccakCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            keccak_table,
            challenges,
        }: Self::ConfigArgs,
    ) -> Self {
        assert!(
            get_num_rows_per_round() > NUM_BYTES_PER_WORD,
            "KeccakCircuit requires KECCAK_ROWS>=9"
        );
        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_round = meta.fixed_column();
        let q_absorb = meta.fixed_column();
        let q_round_last = meta.fixed_column();
        let q_padding = meta.fixed_column();
        let q_padding_last = meta.fixed_column();
        let round_cst = meta.fixed_column();

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

        // Process inputs.
        // "Absorb" happens at the first round. However, the input is witnessed and
        // processed over the first 17 rounds. Each round converts a word into 8
        // bytes.
        cell_manager.start_region();
        let mut lookup_counter = 0;
        // Potential optimization: could do multiple bytes per lookup
        let packed_parts = split::expr(
            meta,
            &mut cell_manager,
            &mut cb,
            absorb_data.expr(),
            0,
            NUM_BYTES_PER_WORD,
            false,
            None,
        );
        cell_manager.start_region();
        let input_bytes = transform::expr(
            "input unpack",
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
        for _ in input_bytes.iter() {
            is_paddings.push(cell_manager.query_cell(meta));
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
            let rlc = compose_rlc::expr(&hash_bytes_le, challenges.evm_word());
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
            let data_rlcs: Vec<_> = (0..NUM_BYTES_PER_WORD + 1)
                .map(|i| meta.query_advice(data_rlc, Rotation(i as i32)))
                .collect();
            assert_eq!(data_rlcs.len(), input_bytes.len() + 1);

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

                let mut new_data_rlc = data_rlcs[NUM_BYTES_PER_WORD].expr();

                // At the start of a hash, start at 0. Otherwise, continue from the previous
                // value.
                let data_rlc_zero_or_prev =
                    data_rlc_prev.clone() * not::expr(start_new_hash_prev.expr());
                cb.require_equal(
                    "initial data rlc",
                    data_rlc_zero_or_prev,
                    new_data_rlc.clone(),
                );

                // Add the word `input_bytes` to `data_rlc`. It has a variable length
                // represented by `is_paddings`, which requires intermediate
                // cells to keep the degree low.
                for (idx, (byte, is_padding)) in
                    input_bytes.iter().zip(is_paddings.iter()).enumerate()
                {
                    new_data_rlc = select::expr(
                        is_padding.expr(),
                        new_data_rlc.clone(),
                        new_data_rlc.clone() * challenges.keccak_input() + byte.expr.clone(),
                    );
                    let data_rlc_after_this_byte = data_rlcs[NUM_BYTES_PER_WORD - (idx + 1)].expr();
                    cb.require_equal(
                        "intermediate data rlc",
                        data_rlc_after_this_byte.clone(),
                        new_data_rlc,
                    );
                    new_data_rlc = data_rlc_after_this_byte;
                }
                // At this point, `data_rlcs[0]` includes the new input word. It
                // will be copied into the next round, or it is
                // the final `input_rlc` in the lookup table.
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
                        data_rlcs[0].clone(),
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

        KeccakCircuitConfig {
            q_enable,
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
}

impl<F: Field> KeccakCircuitConfig<F> {
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &[KeccakRow<F>],
    ) -> Result<(), Error> {
        let mut is_first_time = true;
        layouter.assign_region(
            || "assign keccak rows",
            |mut region| {
                if is_first_time {
                    is_first_time = false;
                    let offset = witness.len() - 1;
                    self.set_row(&mut region, offset, &witness[offset])?;
                    return Ok(());
                }
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
                Value::known(F::from(row.is_final)),
                row.data_rlc,
                Value::known(F::from(row.length as u64)),
                row.hash_rlc,
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

    pub(crate) fn load_aux_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
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

/// KeccakCircuit
#[derive(Default, Clone, Debug)]
pub struct KeccakCircuit<F: Field> {
    inputs: Vec<Vec<u8>>,
    num_rows: Option<usize>,
    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for KeccakCircuit<F> {
    type Config = KeccakCircuitConfig<F>;

    /// The `block.circuits_params.keccak_padding` parmeter, when enabled, sets
    /// up the circuit to support a fixed number of permutations/keccak_f's,
    /// independently of the permutations required by `inputs`.
    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(
            block.circuits_params.keccak_padding,
            block.keccak_inputs.clone(),
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let rows_per_chunk = (NUM_ROUNDS + 1) * get_num_rows_per_round();
        (
            block
                .keccak_inputs
                .iter()
                .map(|bytes| (bytes.len() as f64 / 136.0).ceil() as usize * rows_per_chunk)
                .sum(),
            block.circuits_params.keccak_padding.unwrap_or_default(),
        )
    }

    /// Make the assignments to the KeccakCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.load_aux_tables(layouter)?;
        let witness = self.generate_witness(*challenges);
        config.assign(layouter, witness.as_slice())
    }
}

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
impl<F: Field> Circuit<F> for KeccakCircuit<F> {
    type Config = (KeccakCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let config = {
            let challenges = challenges.exprs(meta);
            KeccakCircuitConfig::new(
                meta,
                KeccakCircuitConfigArgs {
                    keccak_table,
                    challenges,
                },
            )
        };
        (config, challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<F: Field> KeccakCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(num_rows: Option<usize>, inputs: Vec<Vec<u8>>) -> Self {
        KeccakCircuit {
            inputs,
            num_rows,
            _marker: PhantomData,
        }
    }

    /// The number of keccak_f's that can be done in this circuit
    pub fn capacity(&self) -> Option<usize> {
        // Subtract two for unusable rows
        self.num_rows
            .map(|num_rows| num_rows / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2)
    }

    /// Sets the witness using the data to be hashed
    pub(crate) fn generate_witness(&self, challenges: Challenges<Value<F>>) -> Vec<KeccakRow<F>> {
        multi_keccak(self.inputs.as_slice(), challenges, self.capacity())
            .expect("Too many inputs for given capacity")
    }
}
