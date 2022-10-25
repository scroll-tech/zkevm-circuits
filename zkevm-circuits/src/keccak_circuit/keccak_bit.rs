use super::util::{
    ABSORB_WIDTH_PER_ROW, ABSORB_WIDTH_PER_ROW_BYTES, KECCAK_WIDTH_IN_BITS, NUM_ROUNDS, ROUND_CST,
    ROUND_CST_BIT_POS, THETA_C_WIDTH,
};
use crate::{
    evm_circuit::util::{constraint_builder::BaseConstraintBuilder, not, rlc},
    keccak_circuit::util::{
        compose_rlc, get_absorb_positions, into_bits, pack_with_base, to_bytes, NUM_BITS_PER_WORD,
        NUM_WORDS_TO_ABSORB, RATE, RATE_IN_BITS, RHO_MATRIX,
    },
    table::KeccakTable,
    util::Expr,
};
use eth_types::Field;
use gadgets::util::{and, select, sum, xor};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, TableColumn,
        VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use log::{debug, info};
use std::{env::var, marker::PhantomData, vec};

const MAX_DEGREE: usize = 5;
const MAX_INPUT_THETA_LOOKUP: u64 = 5;

fn get_degree() -> usize {
    var("DEGREE")
        .unwrap_or_else(|_| "8".to_string())
        .parse()
        .expect("Cannot parse DEGREE env var as usize")
}

fn get_num_bits_per_theta_lookup() -> usize {
    let degree = get_degree() as u32;
    let mut num_bits = 1;
    while (MAX_INPUT_THETA_LOOKUP + 1).pow(num_bits + 1) <= 2u64.pow(degree) {
        num_bits += 1;
    }
    num_bits as usize
}

/// ..
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeccakRow<F> {
    q_padding: bool,
    q_padding_last: bool,
    state: [u8; KECCAK_WIDTH_IN_BITS],
    theta_c: [u8; THETA_C_WIDTH],
    input: [u8; ABSORB_WIDTH_PER_ROW],
    is_paddings: [bool; ABSORB_WIDTH_PER_ROW_BYTES],
    data_rlcs: [F; ABSORB_WIDTH_PER_ROW_BYTES],
    is_final: bool,
    length: usize,
    data_rlc: F,
    hash_rlc: F,
}

/// KeccakBitConfig
#[derive(Clone, Debug)]
pub struct KeccakBitConfig<F> {
    q_enable: Column<Fixed>,
    q_first: Column<Fixed>,
    q_round: Column<Fixed>,
    q_absorb: Column<Fixed>,
    q_padding: Column<Fixed>,
    q_padding_last: Column<Fixed>,
    /// The columns for other circuits to lookup Keccak hash results
    pub keccak_table: KeccakTable,
    state: [Column<Advice>; KECCAK_WIDTH_IN_BITS],
    theta_c: [Column<Advice>; THETA_C_WIDTH],
    input: [Column<Advice>; ABSORB_WIDTH_PER_ROW],
    is_paddings: [Column<Advice>; ABSORB_WIDTH_PER_ROW_BYTES],
    data_rlcs: [Column<Advice>; ABSORB_WIDTH_PER_ROW_BYTES],
    round_cst: [Column<Fixed>; ROUND_CST_BIT_POS.len()],
    theta_c_table: Vec<TableColumn>,
    _marker: PhantomData<F>,
}

/// KeccakBitCircuit
#[derive(Default)]
pub struct KeccakBitCircuit<F: Field> {
    witness: Vec<KeccakRow<F>>,
    size: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> KeccakBitCircuit<F> {
    fn r() -> F {
        F::from(123456)
    }
}

impl<F: Field> Circuit<F> for KeccakBitCircuit<F> {
    type Config = KeccakBitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        KeccakBitConfig::configure(meta, Expression::Constant(KeccakBitCircuit::r()))
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

impl<F: Field> KeccakBitCircuit<F> {
    /// Creates a new circuit instance
    pub fn new(size: usize) -> Self {
        KeccakBitCircuit {
            witness: Vec::new(),
            size,
            _marker: PhantomData,
        }
    }

    /// The number of keccak_f's that can be done in this circuit
    pub fn capacity(&self) -> usize {
        // Subtract one for unusable rows
        self.size / (NUM_ROUNDS + 1) - 1
    }

    /// Sets the witness using the data to be hashed
    pub fn generate_witness(&mut self, inputs: &[Vec<u8>]) {
        self.witness = multi_keccak(inputs, KeccakBitCircuit::r());
    }
}

impl<F: Field> KeccakBitConfig<F> {
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>, r: Expression<F>) -> Self {
        let num_bits_per_theta_lookup = get_num_bits_per_theta_lookup();
        info!("num_bits_per_theta_lookup: {}", num_bits_per_theta_lookup);

        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_round = meta.fixed_column();
        let q_absorb = meta.fixed_column();
        let q_padding = meta.fixed_column();
        let q_padding_last = meta.fixed_column();

        let keccak_table = KeccakTable::construct(meta);
        let is_final = keccak_table.is_enabled;
        let length = keccak_table.input_len;
        let data_rlc = keccak_table.input_rlc;
        let hash_rlc = keccak_table.output_rlc;

        let state = array_init::array_init(|_| meta.advice_column());
        let theta_c = array_init::array_init(|_| meta.advice_column());
        let input = array_init::array_init(|_| meta.advice_column());
        let is_paddings = array_init::array_init(|_| meta.advice_column());
        let data_rlcs = array_init::array_init(|_| meta.advice_column());
        let round_cst = array_init::array_init(|_| meta.fixed_column());

        let mut theta_c_table = Vec::new();
        for _ in 0..1 + num_bits_per_theta_lookup {
            theta_c_table.push(meta.lookup_table_column());
        }

        let start_new_hash = |meta: &mut VirtualCells<F>, rot| {
            // A new hash is started when the previous hash is done or on the first row
            meta.query_fixed(q_first, rot) + meta.query_advice(is_final, rot)
        };

        // State bits
        let mut s = vec![vec![vec![0u64.expr(); NUM_BITS_PER_WORD]; 5]; 5];
        let mut s_next = vec![vec![vec![0u64.expr(); NUM_BITS_PER_WORD]; 5]; 5];
        meta.create_gate("Query state bits", |meta| {
            let mut counter = 0;
            for i in 0..5 {
                for j in 0..5 {
                    for k in 0..64 {
                        s[i][j][k] = meta.query_advice(state[counter], Rotation::cur());
                        s_next[i][j][k] = meta.query_advice(state[counter], Rotation::next());
                        counter += 1;
                    }
                }
            }
            vec![0u64.expr()]
        });
        // Theta c bits
        let mut c = vec![vec![0u64.expr(); NUM_BITS_PER_WORD]; 5];
        meta.create_gate("Query Theta c bits", |meta| {
            let mut counter = 0;
            for c in c.iter_mut() {
                for c in c.iter_mut() {
                    *c = meta.query_advice(theta_c[counter], Rotation::cur());
                    counter += 1;
                }
            }
            vec![0u64.expr()]
        });
        // Input bits
        let mut i = vec![0u64.expr(); NUM_BITS_PER_WORD];
        let mut i_next = vec![vec![0u64.expr(); NUM_BITS_PER_WORD]; NUM_WORDS_TO_ABSORB];
        meta.create_gate("Query absorb inputs", |meta| {
            for k in 0..NUM_BITS_PER_WORD {
                i[k] = meta.query_advice(input[k], Rotation::cur());
            }
            for (i, i_next) in i_next.iter_mut().enumerate() {
                for (k, i_next) in i_next.iter_mut().enumerate() {
                    *i_next = meta.query_advice(input[k], Rotation((i + 1) as i32));
                }
            }
            vec![0u64.expr()]
        });

        // Theta lookups
        let mut theta = Vec::new();
        for (i, c) in c.iter().enumerate() {
            let pi = (5 + i - 1) % 5;
            let ni = (i + 1) % 5;
            for (k, c) in c.iter().enumerate() {
                let pk = (NUM_BITS_PER_WORD + k - 1) % NUM_BITS_PER_WORD;
                let bit = xor::expr(s[pi][0][k].clone(), s[pi][1][k].clone())
                    + xor::expr(s[pi][2][k].clone(), s[pi][3][k].clone())
                    + xor::expr(s[pi][4][k].clone(), s[ni][0][pk].clone())
                    + xor::expr(s[ni][1][pk].clone(), s[ni][2][pk].clone())
                    + xor::expr(s[ni][3][pk].clone(), s[ni][4][pk].clone());
                theta.push((c.clone(), bit));
            }
        }
        let mut lookup_counter = 0;
        for chunk in theta.chunks(num_bits_per_theta_lookup) {
            meta.lookup("Theta c", |_| {
                let mut factor = 1u64;
                let mut input = 0u64.expr();
                let mut tables = Vec::new();
                for (idx, (bit, expr)) in chunk.iter().enumerate() {
                    input = input + expr.clone() * factor.expr();
                    factor *= MAX_INPUT_THETA_LOOKUP;
                    tables.push((bit.clone(), theta_c_table[1 + idx]));
                }
                tables.push((input, theta_c_table[0]));
                tables
            });
            lookup_counter += 1;
        }
        info!("Lookups: {}", lookup_counter);

        meta.create_gate("input checks", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // Input bits boolean
            for i in &i {
                cb.require_boolean("boolean state bit", i.clone());
            }
            // is_final boolean
            cb.require_boolean(
                "boolean is_final",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // Enforce fixed values on the first row
        meta.create_gate("first row", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // is_final needs to be false
            cb.require_zero(
                "is_final needs to be disabled on the first row",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.gate(meta.query_fixed(q_first, Rotation::cur()))
        });

        // The round constraints
        meta.create_gate("round", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let mut s = s.clone();

            // Theta
            let mut os = vec![vec![vec![0u64.expr(); NUM_BITS_PER_WORD]; 5]; 5];
            for i in 0..5 {
                for j in 0..5 {
                    for k in 0..NUM_BITS_PER_WORD {
                        os[i][j][k] = xor::expr(s[i][j][k].clone(), c[i][k].clone());
                    }
                }
            }
            s = os.clone();

            // Rho/Pi
            for (i, s) in s.iter().enumerate() {
                for (j, s) in s.iter().enumerate() {
                    for k in 0..NUM_BITS_PER_WORD {
                        os[j][(2 * i + 3 * j) % 5][k] = s
                            [(NUM_BITS_PER_WORD + k - RHO_MATRIX[i][j]) % NUM_BITS_PER_WORD]
                            .clone();
                    }
                }
            }
            s = os.clone();

            // Chi/Iota
            let mut iota_counter = 0;
            for i in 0..5 {
                for j in 0..5 {
                    for k in 0..NUM_BITS_PER_WORD {
                        if i == 0 && j == 0 && ROUND_CST_BIT_POS.contains(&k) {
                            cb.require_equal(
                                "round state transition with round constant",
                                not::expr(s[(i + 1) % 5][j][k].clone())
                                    * s[(i + 2) % 5][j][k].clone(),
                                xor::expr(
                                    xor::expr(s[i][j][k].clone(), s_next[i][j][k].clone()),
                                    meta.query_fixed(round_cst[iota_counter], Rotation::cur()),
                                ),
                            );
                            iota_counter += 1;
                        } else {
                            cb.require_equal(
                                "round state transition",
                                not::expr(s[(i + 1) % 5][j][k].clone())
                                    * s[(i + 2) % 5][j][k].clone(),
                                xor::expr(s[i][j][k].clone(), s_next[i][j][k].clone()),
                            );
                        }
                    }
                }
            }

            cb.gate(meta.query_fixed(q_round, Rotation::cur()))
        });

        // Absorb
        meta.create_gate("absorb", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let continue_hash = not::expr(start_new_hash(meta, Rotation::cur()));
            let absorb_positions = get_absorb_positions();
            let mut input_slice = 0;
            for j in 0..5 {
                for i in 0..5 {
                    if absorb_positions.contains(&(i, j)) {
                        for k in 0..NUM_BITS_PER_WORD {
                            cb.require_equal(
                                "absorb bit",
                                xor::expr(
                                    s[i][j][k].clone() * continue_hash.clone(),
                                    i_next[input_slice][k].clone(),
                                ),
                                s_next[i][j][k].clone(),
                            );
                        }
                        input_slice += 1;
                    } else {
                        for k in 0..NUM_BITS_PER_WORD {
                            cb.require_equal(
                                "absorb copy",
                                s[i][j][k].clone() * continue_hash.clone(),
                                s_next[i][j][k].clone(),
                            );
                        }
                    }
                }
            }
            cb.gate(meta.query_fixed(q_absorb, Rotation::cur()))
        });

        // Squeeze
        meta.create_gate("squeeze", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            // Squeeze out the hash
            let hash_bytes_le = s
                .into_iter()
                .take(4)
                .flat_map(|a| to_bytes::expr(&a[0]))
                .rev()
                .collect::<Vec<_>>();
            let rlc = compose_rlc::expr(&hash_bytes_le, r.clone());
            cb.condition(start_new_hash(meta, Rotation::cur()), |cb| {
                cb.require_equal(
                    "hash rlc check",
                    rlc,
                    meta.query_advice(hash_rlc, Rotation::cur()),
                );
            });
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // Enforce logic for when this block is the last block for a hash
        meta.create_gate("is final", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let last_is_padding_in_block = meta.query_advice(
                *is_paddings.last().unwrap(),
                Rotation(-((NUM_ROUNDS + 1 - NUM_WORDS_TO_ABSORB) as i32)),
            );
            cb.require_equal(
                "is_final needs to be the same as the last is_padding in the block",
                meta.query_advice(is_final, Rotation::cur()),
                last_is_padding_in_block.expr(),
            );
            // All absorb rows except the first row
            cb.gate(
                meta.query_fixed(q_absorb, Rotation::cur())
                    - meta.query_fixed(q_first, Rotation::cur()),
            )
        });

        // Create bytes from input bits
        let mut input_bytes = Vec::new();
        meta.create_gate("create input bytes", |meta| {
            let input_bits = input
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect::<Vec<_>>();
            input_bytes = to_bytes::expr(&input_bits);
            vec![0u64.expr()]
        });

        // Padding
        // May be cleaner to do this padding logic in the byte conversion lookup but
        // currently easier to do it like this.
        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);
            let prev_is_padding = meta.query_advice(*is_paddings.last().unwrap(), Rotation::prev());
            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let q_padding_last = meta.query_fixed(q_padding_last, Rotation::cur());
            // All padding selectors need to be boolean
            for is_padding in is_paddings.iter() {
                let is_padding = meta.query_advice(*is_padding, Rotation::cur());
                cb.condition(meta.query_fixed(q_enable, Rotation::cur()), |cb| {
                    cb.require_boolean("is_padding boolean", is_padding);
                });
            }
            // This last padding selector will be used on the first round row so needs to be
            // zero
            cb.condition(meta.query_fixed(q_absorb, Rotation::cur()), |cb| {
                cb.require_zero(
                    "last is_padding should be zero on absorb rows",
                    meta.query_advice(*is_paddings.last().unwrap(), Rotation::cur()),
                );
            });
            // Now for each padding selector
            for idx in 0..is_paddings.len() {
                // Previous padding selector can be on the previous row
                let is_padding_prev = if idx == 0 {
                    prev_is_padding.expr()
                } else {
                    meta.query_advice(is_paddings[idx - 1], Rotation::cur())
                };
                let is_padding = meta.query_advice(is_paddings[idx], Rotation::cur());
                let is_first_padding = is_padding.clone() - is_padding_prev.clone();

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
                            (q_padding.expr() - q_padding_last.expr()),
                            is_padding.expr(),
                        ]),
                        |cb| {
                            // Input bytes need to be zero, or one if this is the first padding byte
                            cb.require_equal(
                                "padding start/intermediate byte last byte",
                                input_bytes[idx].clone(),
                                is_first_padding.expr(),
                            );
                        },
                    );
                    // Padding start/end byte, only on the last padding row
                    cb.condition(
                        and::expr([q_padding_last.expr(), is_padding.expr()]),
                        |cb| {
                            // The input byte needs to be 128, unless it's also the first padding
                            // byte then it's 129
                            cb.require_equal(
                                "padding start/end byte",
                                input_bytes[idx].clone(),
                                is_first_padding.expr() + 128.expr(),
                            );
                        },
                    );
                } else {
                    // Padding start/intermediate byte
                    cb.condition(and::expr([q_padding.expr(), is_padding.expr()]), |cb| {
                        // Input bytes need to be zero, or one if this is the first padding byte
                        cb.require_equal(
                            "padding start/intermediate byte",
                            input_bytes[idx].clone(),
                            is_first_padding.expr(),
                        );
                    });
                }
            }

            cb.gate(1.expr())
        });

        // Length and input data rlc
        meta.create_gate("length and data rlc", |meta| {
            let mut cb = BaseConstraintBuilder::new(MAX_DEGREE);

            let q_padding = meta.query_fixed(q_padding, Rotation::cur());
            let start_new_hash_prev = start_new_hash(meta, Rotation::prev());
            let length_prev = meta.query_advice(length, Rotation::prev());
            let length = meta.query_advice(length, Rotation::cur());
            let data_rlc_prev = meta.query_advice(data_rlc, Rotation::prev());
            let data_rlc = meta.query_advice(data_rlc, Rotation::cur());

            // Update the length/data_rlc on rows where we absorb data
            cb.condition(q_padding.expr(), |cb| {
                // Length increases by the number of bytes that aren't padding
                // In a new block we have to start from 0 if the previous block was the final
                // one
                cb.require_equal(
                    "update length",
                    length.clone(),
                    length_prev.clone() * not::expr(start_new_hash_prev.expr())
                        + sum::expr(is_paddings.iter().map(|is_padding| {
                            not::expr(meta.query_advice(*is_padding, Rotation::cur()))
                        })),
                );

                // Use intermediate cells to keep the degree low
                let mut new_data_rlc =
                    data_rlc_prev.clone() * not::expr(start_new_hash_prev.expr());
                cb.require_equal(
                    "initial data rlc",
                    meta.query_advice(data_rlcs[0], Rotation::cur()),
                    new_data_rlc,
                );
                new_data_rlc = meta.query_advice(data_rlcs[0], Rotation::cur());
                for (idx, (byte, is_padding)) in
                    input_bytes.iter().zip(is_paddings.iter()).enumerate()
                {
                    new_data_rlc = select::expr(
                        meta.query_advice(*is_padding, Rotation::cur()),
                        new_data_rlc.clone(),
                        new_data_rlc.clone() * r.clone() + byte.clone(),
                    );
                    if idx < data_rlcs.len() - 1 {
                        let next_data_rlc = meta.query_advice(data_rlcs[idx + 1], Rotation::cur());
                        cb.require_equal(
                            "intermediate data rlc",
                            next_data_rlc.clone(),
                            new_data_rlc,
                        );
                        new_data_rlc = next_data_rlc;
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

        info!("degree: {}", meta.degree());

        KeccakBitConfig {
            q_enable,
            q_first,
            q_round,
            q_absorb,
            q_padding,
            q_padding_last,
            keccak_table,
            state,
            theta_c,
            input,
            is_paddings,
            data_rlcs,
            round_cst,
            theta_c_table,
            _marker: PhantomData,
        }
    }
    /// Sets the witness using the data to be hashed
    pub fn assign_from_witness(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: &[Vec<u8>],
        r: F,
    ) -> Result<(), Error> {
        let witness = multi_keccak(inputs, r);
        self.assign(layouter, &witness)
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        witness: &[KeccakRow<F>],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign keccak rounds",
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
        let round = (offset + NUM_ROUNDS) % (NUM_ROUNDS + 1);

        // Fixed selectors
        for (name, column, value) in &[
            ("q_enable", self.q_enable, F::from(true)),
            ("q_first", self.q_first, F::from(offset == 0)),
            ("q_round", self.q_round, F::from(round != NUM_ROUNDS)),
            ("q_absorb", self.q_absorb, F::from(round == NUM_ROUNDS)),
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
            ],
        )?;

        // State bits
        for (idx, (bit, column)) in row.state.iter().zip(self.state.iter()).enumerate() {
            region.assign_advice(
                || format!("assign state bit {} {}", idx, offset),
                *column,
                offset,
                || Value::known(F::from(*bit as u64)),
            )?;
        }

        // Theta c bits
        for (idx, (bit, column)) in row.theta_c.iter().zip(self.theta_c.iter()).enumerate() {
            region.assign_advice(
                || format!("assign theta c bit {} {}", idx, offset),
                *column,
                offset,
                || Value::known(F::from(*bit as u64)),
            )?;
        }

        // Absorb c bits
        for (idx, (bit, column)) in row.input.iter().zip(self.input.iter()).enumerate() {
            region.assign_advice(
                || format!("assign absorb bits {} {}", idx, offset),
                *column,
                offset,
                || Value::known(F::from(*bit as u64)),
            )?;
        }

        // Padding selectors
        for (idx, (is_padding, column)) in row
            .is_paddings
            .iter()
            .zip(self.is_paddings.iter())
            .enumerate()
        {
            region.assign_advice(
                || format!("assign padding selector {} {}", idx, offset),
                *column,
                offset,
                || Value::known(F::from(*is_padding as u64)),
            )?;
        }

        // Intermediate data rlcs
        for (idx, (data_rlc, column)) in row.data_rlcs.iter().zip(self.data_rlcs.iter()).enumerate()
        {
            region.assign_advice(
                || format!("assign padding selector {} {}", idx, offset),
                *column,
                offset,
                || Value::known(*data_rlc),
            )?;
        }

        // Round constant columns
        for (pos, column) in ROUND_CST_BIT_POS.iter().zip(self.round_cst.iter()) {
            region.assign_fixed(
                || format!("assign round constant bit {} {}", *pos, offset),
                *column,
                offset,
                || Value::known(F::from(((ROUND_CST[round] >> *pos) & 1) as u64)),
            )?;
        }

        Ok(())
    }

    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let num_bits_per_theta_lookup = get_num_bits_per_theta_lookup();
        layouter.assign_table(
            || "theta c table",
            |mut table| {
                for (offset, perm) in (0..num_bits_per_theta_lookup)
                    .map(|_| 0..=MAX_INPUT_THETA_LOOKUP)
                    .multi_cartesian_product()
                    .enumerate()
                {
                    let mut compressed_value = 0u64;
                    let mut factor = 1u64;
                    for (idx, input) in perm.iter().enumerate() {
                        compressed_value += input * factor;
                        factor *= MAX_INPUT_THETA_LOOKUP;

                        table.assign_cell(
                            || "theta c output",
                            self.theta_c_table[idx + 1],
                            offset,
                            || Value::known(F::from(*input & 1)),
                        )?;
                    }

                    table.assign_cell(
                        || "theta c input",
                        self.theta_c_table[0],
                        offset,
                        || Value::known(F::from(compressed_value)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

fn keccak<F: Field>(rows: &mut Vec<KeccakRow<F>>, bytes: &[u8], r: F) {
    let mut bits = into_bits(bytes);
    let mut s = [[[0u8; NUM_BITS_PER_WORD]; 5]; 5];
    let absorb_positions = get_absorb_positions();
    let num_bytes_in_last_block = bytes.len() % RATE;

    // Padding
    bits.push(1);
    while (bits.len() + 1) % RATE_IN_BITS != 0 {
        bits.push(0);
    }
    bits.push(1);

    let mut length = 0usize;
    let mut data_rlc = F::zero();
    let chunks = bits.chunks(RATE_IN_BITS);
    let num_chunks = chunks.len();
    for (idx, chunk) in chunks.enumerate() {
        // Last block for this keccak hash
        let is_final_block = idx == num_chunks - 1;

        // Absorb
        let mut counter = 0;
        for &(i, j) in &absorb_positions {
            for k in 0..NUM_BITS_PER_WORD {
                s[i][j][k] ^= chunk[counter];
                counter += 1;
            }
        }

        let mut counter = 0;
        for (round, round_cst) in ROUND_CST.iter().enumerate() {
            let mut input = [0u8; NUM_BITS_PER_WORD];
            if counter < RATE_IN_BITS {
                for bit in input.iter_mut() {
                    *bit = chunk[counter];
                    counter += 1;
                }
            }

            // Theta c
            let mut c = [[0u8; NUM_BITS_PER_WORD]; 5];
            for (i, c) in c.iter_mut().enumerate() {
                let pi = (5 + i - 1) % 5;
                let ni = (i + 1) % 5;
                for (k, c) in c.iter_mut().enumerate() {
                    let pk = (NUM_BITS_PER_WORD + k - 1) % NUM_BITS_PER_WORD;
                    *c = s[pi][0][k]
                        ^ s[pi][1][k]
                        ^ s[pi][2][k]
                        ^ s[pi][3][k]
                        ^ s[pi][4][k]
                        ^ s[ni][1][pk]
                        ^ s[ni][0][pk]
                        ^ s[ni][2][pk]
                        ^ s[ni][3][pk]
                        ^ s[ni][4][pk];
                }
            }

            // Flatten bits
            let mut counter = 0;
            let mut state = [0u8; KECCAK_WIDTH_IN_BITS];
            for s in s {
                for s in s {
                    for s in s {
                        state[counter] = s;
                        counter += 1;
                    }
                }
            }

            // Flatten bits
            let mut counter = 0;
            let mut theta_c = [0u8; THETA_C_WIDTH];
            for c in c {
                for c in c {
                    theta_c[counter] = c;
                    counter += 1;
                }
            }

            // Padding/Length/Data rlc
            let mut is_paddings = [false; ABSORB_WIDTH_PER_ROW_BYTES];
            let mut data_rlcs = [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES];
            if round < NUM_WORDS_TO_ABSORB {
                for (padding_idx, is_padding) in is_paddings.iter_mut().enumerate() {
                    let byte_idx = round * 8 + padding_idx;
                    *is_padding = if is_final_block && byte_idx >= num_bytes_in_last_block {
                        true
                    } else {
                        length += 1;
                        false
                    };
                }

                data_rlcs[0] = data_rlc;
                for (idx, (byte_bits, padding)) in
                    input.chunks(8).zip(is_paddings.iter()).enumerate()
                {
                    if !*padding {
                        let byte_value: F = pack_with_base(byte_bits, 2);
                        data_rlc = data_rlc * r + byte_value;
                    }
                    if idx < data_rlcs.len() - 1 {
                        data_rlcs[idx + 1] = data_rlc;
                    }
                }
            }

            // Last row for this keccak hash
            let is_final = is_final_block && round == NUM_ROUNDS;

            // Squeeze
            let hash_rlc = if is_final {
                let hash_bytes_le = s
                    .into_iter()
                    .take(4)
                    .flat_map(|a| to_bytes::value(&a[0]))
                    .rev()
                    .collect::<Vec<_>>();
                rlc::value(&hash_bytes_le, r)
            } else {
                F::zero()
            };

            rows.push(KeccakRow {
                q_padding: round < NUM_WORDS_TO_ABSORB,
                q_padding_last: round == NUM_WORDS_TO_ABSORB - 1,
                state,
                theta_c,
                input,
                is_paddings,
                data_rlcs,
                is_final,
                length,
                data_rlc,
                hash_rlc,
            });

            if round < NUM_ROUNDS {
                // Theta
                for i in 0..5 {
                    for j in 0..5 {
                        for k in 0..NUM_BITS_PER_WORD {
                            s[i][j][k] ^= c[i][k];
                        }
                    }
                }

                // Rho/Pi
                let mut os = s;
                for (i, s) in s.iter().enumerate() {
                    for (j, s) in s.iter().enumerate() {
                        for k in 0..NUM_BITS_PER_WORD {
                            os[j][(2 * i + 3 * j) % 5][k] =
                                s[(NUM_BITS_PER_WORD + k - RHO_MATRIX[i][j]) % NUM_BITS_PER_WORD]
                        }
                    }
                }
                s = os;

                // Chi
                let mut os = s;
                for i in 0..5 {
                    for j in 0..5 {
                        for k in 0..NUM_BITS_PER_WORD {
                            os[i][j][k] =
                                s[i][j][k] ^ ((1 - s[(i + 1) % 5][j][k]) * s[(i + 2) % 5][j][k]);
                        }
                    }
                }
                s = os;

                // Iota
                for k in ROUND_CST_BIT_POS {
                    s[0][0][k] ^= ((round_cst >> k) & 1) as u8;
                }
            }
        }
    }
    let hash_bytes = s
        .into_iter()
        .take(4)
        .map(|a| to_bytes::value(&a[0]))
        .take(4)
        .concat();
    debug!("hash: {:x?}", &hash_bytes);
    debug!("data rlc: {:x?}", data_rlc);
}

/// ...
pub fn multi_keccak<F: Field>(bytes: &[Vec<u8>], r: F) -> Vec<KeccakRow<F>> {
    // Dummy first row so that the initial data can be absorbed
    // The initial data doesn't really matter, `is_final` just needs to be disabled.
    let mut rows: Vec<KeccakRow<F>> = vec![KeccakRow {
        q_padding: false,
        q_padding_last: false,
        state: [0u8; KECCAK_WIDTH_IN_BITS],
        theta_c: [0u8; THETA_C_WIDTH],
        input: [0u8; ABSORB_WIDTH_PER_ROW],
        is_paddings: [false; ABSORB_WIDTH_PER_ROW_BYTES],
        data_rlcs: [F::zero(); ABSORB_WIDTH_PER_ROW_BYTES],
        is_final: false,
        length: 0usize,
        data_rlc: F::zero(),
        hash_rlc: F::zero(),
    }];
    // Actual keccaks
    for bytes in bytes {
        keccak(&mut rows, bytes, r);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    fn verify<F: Field>(k: u32, inputs: Vec<Vec<u8>>, success: bool) {
        let mut circuit = KeccakBitCircuit::new(2usize.pow(k));
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
    fn bit_keccak_simple() {
        let k = 8;
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
