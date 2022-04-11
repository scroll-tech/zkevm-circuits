use crate::{
    evm_circuit::{
        table::BytecodeFieldTag,
        util::{
            and, constraint_builder::BaseConstraintBuilder, not, or, select,
            RandomLinearCombination,
        },
    },
    gadget::{
        evm_word::encode,
        is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
    poly::Rotation,
};
use keccak256::plain::Keccak;
use std::{convert::TryInto, vec};

use super::param::{KECCAK_WIDTH, PUSH_TABLE_WIDTH};

/// Public data for the bytecode
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BytecodeRow<F: Field> {
    hash: F,
    tag: F,
    index: F,
    is_code: F,
    value: F,
}

/// Unrolled bytecode
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct UnrolledBytecode<F: Field> {
    bytes: Vec<u8>,
    rows: Vec<BytecodeRow<F>>,
}

#[derive(Clone, Debug)]
pub struct Config<F> {
    r: F,
    minimum_rows: usize,
    q_enable: Selector,
    q_first: Column<Fixed>,
    q_last: Selector,
    hash: Column<Advice>,
    tag: Column<Advice>,
    index: Column<Advice>,
    is_code: Column<Advice>,
    value: Column<Advice>,
    push_rindex: Column<Advice>,
    hash_rlc: Column<Advice>,
    hash_length: Column<Advice>,
    byte_push_size: Column<Advice>,
    is_final: Column<Advice>,
    padding: Column<Advice>,
    push_rindex_inv: Column<Advice>,
    push_rindex_is_zero: IsZeroConfig<F>,
    length_inv: Column<Advice>,
    length_is_zero: IsZeroConfig<F>,
    push_table: [Column<Fixed>; PUSH_TABLE_WIDTH],
    keccak_table: [Column<Advice>; KECCAK_WIDTH],
}

impl<F: Field> Config<F> {
    pub(crate) fn configure(meta: &mut ConstraintSystem<F>, r: F) -> Self {
        let q_enable = meta.complex_selector();
        let q_first = meta.fixed_column();
        let q_last = meta.selector();
        let hash = meta.advice_column();
        let tag = meta.advice_column();
        let index = meta.advice_column();
        let is_code = meta.advice_column();
        let value = meta.advice_column();
        let push_rindex = meta.advice_column();
        let hash_rlc = meta.advice_column();
        let hash_length = meta.advice_column();
        let byte_push_size = meta.advice_column();
        let is_final = meta.advice_column();
        let padding = meta.advice_column();
        let push_rindex_inv = meta.advice_column();
        let length_inv = meta.advice_column();
        let push_table = array_init::array_init(|_| meta.fixed_column());
        let keccak_table = array_init::array_init(|_| meta.advice_column());

        // A byte is an opcode when `push_rindex == 0` on the previous row,
        // else it's push data.
        let push_rindex_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                // Conditions:
                // - Not on the first row
                meta.query_selector(q_enable)
                    * not::expr(meta.query_fixed(q_first, Rotation::cur()))
            },
            |meta| meta.query_advice(push_rindex, Rotation::prev()),
            push_rindex_inv,
        );

        // Does the current row have bytecode field tag == Length?
        let is_row_tag_length = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                not::expr(meta.query_advice(padding, Rotation::cur())),
                not::expr(meta.query_advice(tag, Rotation::cur())),
            ])
        };

        // Does the current row have bytecode field tag == Byte?
        let is_row_tag_byte = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                not::expr(meta.query_advice(padding, Rotation::cur())),
                meta.query_advice(tag, Rotation::cur()),
            ])
        };

        // For a row tagged Length, is the length (value) zero?
        let length_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable) * is_row_tag_length(meta),
            |meta| meta.query_advice(value, Rotation::cur()),
            length_inv,
        );

        let q_continue = |meta: &mut VirtualCells<F>| {
            // When
            // - Not on the first row
            // - The previous row did not contain the last byte
            and::expr(vec![
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
                not::expr(meta.query_advice(is_final, Rotation::prev())),
            ])
        };

        meta.create_gate("continue", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // Did the previous row have bytecode field tag == Length?
            let is_prev_row_tag_length = |meta: &mut VirtualCells<F>| {
                and::expr(vec![
                    not::expr(meta.query_fixed(q_first, Rotation::cur())),
                    not::expr(meta.query_advice(padding, Rotation::prev())),
                    not::expr(meta.query_advice(tag, Rotation::prev())),
                ])
            };

            cb.require_equal(
                "if prev_row.tag == Length: index == 0 else index == index + 1",
                meta.query_advice(index, Rotation::cur()),
                select::expr(
                    is_prev_row_tag_length(meta),
                    0.expr(),
                    meta.query_advice(index, Rotation::prev()) + 1.expr(),
                ),
            );
            cb.require_equal(
                "is_code := push_rindex_prev == 0",
                meta.query_advice(is_code, Rotation::cur()),
                select::expr(
                    is_prev_row_tag_length(meta),
                    1.expr(),
                    push_rindex_is_zero.clone().is_zero_expression,
                ),
            );
            cb.require_equal(
                "hash_rlc := hash_rlc_prev * r + byte",
                meta.query_advice(hash_rlc, Rotation::cur()),
                meta.query_advice(hash_rlc, Rotation::prev()) * r
                    + meta.query_advice(value, Rotation::cur()),
            );
            cb.require_equal(
                "hash needs to remain the same",
                meta.query_advice(hash, Rotation::cur()),
                meta.query_advice(hash, Rotation::prev()),
            );
            cb.require_equal(
                "hash_length needs to remain the same",
                meta.query_advice(hash_length, Rotation::cur()),
                meta.query_advice(hash_length, Rotation::prev()),
            );
            cb.require_equal(
                "padding needs to remain the same",
                meta.query_advice(padding, Rotation::cur()),
                meta.query_advice(padding, Rotation::prev()),
            );

            // Conditions:
            // - Continuing
            cb.gate(and::expr(vec![
                meta.query_selector(q_enable),
                q_continue(meta),
            ]))
        });

        meta.create_gate("start of bytecode", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "next_row.tag == (tag.Length or tag.Padding) if length == 0 else tag.Byte",
                meta.query_advice(tag, Rotation::next()),
                select::expr(
                    length_is_zero.clone().is_zero_expression,
                    select::expr(
                        meta.query_advice(padding, Rotation::next()),
                        BytecodeFieldTag::Padding.expr(),
                        BytecodeFieldTag::Length.expr(),
                    ),
                    BytecodeFieldTag::Byte.expr(),
                ),
            );
            cb.require_equal(
                "if row.tag == tag.Length: value == row.hash_length",
                meta.query_advice(value, Rotation::cur()),
                meta.query_advice(hash_length, Rotation::cur()),
            );
            cb.condition(length_is_zero.clone().is_zero_expression, |cb| {
                cb.require_equal(
                    "if length == 0: hash == RLC(EMPTY_HASH, randomness)",
                    meta.query_advice(hash, Rotation::cur()),
                    Expression::Constant(keccak(&[], r)),
                );
            });
            // Conditions:
            // - Not Continuing
            // - This is the start of a new bytecode
            cb.gate(and::expr(vec![
                meta.query_selector(q_enable),
                is_row_tag_length(meta),
                not::expr(q_continue(meta)),
            ]))
        });

        meta.create_gate("start of padding", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "row needs to be marked as padding",
                meta.query_advice(padding, Rotation::cur()),
                1.expr(),
            );
            // Conditions:
            // - Not Continuing
            // - This is not the start of a new bytecode
            cb.gate(and::expr(vec![
                meta.query_selector(q_enable),
                not::expr(is_row_tag_length(meta)),
                not::expr(q_continue(meta)),
            ]))
        });

        meta.create_gate("length needs to be correct", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.condition(1.expr() - length_is_zero.clone().is_zero_expression, |cb| {
                cb.require_equal(
                    "index + 1 needs to equal hash_length",
                    meta.query_advice(index, Rotation::cur()) + 1.expr(),
                    meta.query_advice(hash_length, Rotation::cur()),
                );
            });
            // Conditions:
            // - On the row with the last byte (`is_final == 1`)
            // - Of bytecode with length > 0
            // - Not padding
            cb.gate(and::expr(vec![
                meta.query_selector(q_enable),
                meta.query_advice(is_final, Rotation::cur()),
                not::expr(meta.query_advice(padding, Rotation::cur())),
            ]))
        });

        meta.create_gate("always", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_boolean(
                "is_final needs to be boolean",
                meta.query_advice(is_final, Rotation::cur()),
            );
            cb.require_boolean(
                "padding needs to be boolean",
                meta.query_advice(padding, Rotation::cur()),
            );
            cb.condition(is_row_tag_byte(meta), |cb| {
                cb.require_equal(
                    "push_rindex := is_code ? byte_push_size : push_rindex_prev - 1",
                    meta.query_advice(push_rindex, Rotation::cur()),
                    select::expr(
                        meta.query_advice(is_code, Rotation::cur()),
                        meta.query_advice(byte_push_size, Rotation::cur()),
                        meta.query_advice(push_rindex, Rotation::prev()) - 1.expr(),
                    ),
                );
            });
            // Conditions: Always
            cb.gate(meta.query_selector(q_enable))
        });

        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_boolean(
                "padding can only go 0 -> 1 once",
                meta.query_advice(padding, Rotation::cur())
                    - meta.query_advice(padding, Rotation::prev()),
            );
            // Conditions:
            // - Not on the first row
            cb.gate(and::expr(vec![
                meta.query_selector(q_enable),
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
            ]))
        });

        // The hash is checked on the latest row because only then have
        // we accumulated all the bytes. We also have to go through the bytes
        // in a forward manner because that's the only way we can know which
        // bytes are op codes and which are push data.
        meta.create_gate("last row", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "padding needs to be enabled OR the last row needs to be the last byte",
                or::expr(vec![
                    meta.query_advice(padding, Rotation::cur()),
                    meta.query_advice(is_final, Rotation::cur()),
                ]),
                1.expr(),
            );
            // Conditions:
            // - On the last row
            cb.gate(meta.query_selector(q_last))
        });

        // Lookup how many bytes the current opcode pushes
        // (also indirectly range checks `byte` to be in [0, 255])
        meta.lookup_any("Range bytes", |meta| {
            // Conditions: If the current row is is tagged Byte
            let q_enable = meta.query_selector(q_enable) * is_row_tag_byte(meta);
            let lookup_columns = vec![value, byte_push_size];
            let mut constraints = vec![];
            for i in 0..PUSH_TABLE_WIDTH {
                constraints.push((
                    q_enable.clone() * meta.query_advice(lookup_columns[i], Rotation::cur()),
                    meta.query_fixed(push_table[i], Rotation::cur()),
                ))
            }
            constraints
        });

        // keccak lookup
        meta.lookup_any("keccak", |meta| {
            // Conditions:
            // - On the row with the last byte (`is_final == 1`)
            // - Not padding
            let enable = and::expr(vec![
                meta.query_advice(is_final, Rotation::cur()),
                not::expr(meta.query_advice(padding, Rotation::cur())),
            ]);
            let lookup_columns = vec![hash_rlc, hash_length, hash];
            let mut constraints = vec![];
            for i in 0..KECCAK_WIDTH {
                constraints.push((
                    enable.clone() * meta.query_advice(lookup_columns[i], Rotation::cur()),
                    meta.query_advice(keccak_table[i], Rotation::cur()),
                ))
            }
            constraints
        });

        Config {
            r,
            minimum_rows: meta.minimum_rows(),
            q_enable,
            q_first,
            q_last,
            hash,
            tag,
            index,
            is_code,
            value,
            push_rindex,
            hash_rlc,
            hash_length,
            byte_push_size,
            is_final,
            padding,
            push_rindex_inv,
            push_rindex_is_zero,
            length_inv,
            length_is_zero,
            push_table,
            keccak_table,
        }
    }

    pub(crate) fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        size: usize,
        witness: &[UnrolledBytecode<F>],
    ) {
        let push_rindex_is_zero_chip = IsZeroChip::construct(self.push_rindex_is_zero.clone());
        let length_is_zero_chip = IsZeroChip::construct(self.length_is_zero.clone());

        // Subtract the unusable rows from the size
        let last_row_offset = size - self.minimum_rows + 1;

        layouter
            .assign_region(
                || "assign bytecode",
                |mut region| {
                    let mut offset = 0;
                    let mut push_rindex_prev = 0;

                    for bytecode in witness.iter() {
                        // Run over all the bytes
                        let mut push_rindex = 0;
                        let mut byte_push_size = 0;
                        let mut hash_rlc = F::zero();
                        let hash_length = F::from(bytecode.bytes.len() as u64);
                        for (idx, row) in bytecode.rows.iter().enumerate() {
                            // Track which byte is an opcode and which is push
                            // data
                            let is_code = push_rindex == 0;
                            if idx > 0 {
                                byte_push_size = get_push_size(row.value.get_lower_128() as u8);
                                push_rindex = if is_code {
                                    byte_push_size
                                } else {
                                    push_rindex - 1
                                };
                                hash_rlc = hash_rlc * self.r + row.value;
                            }

                            // Set the data for this row
                            self.set_row(
                                &mut region,
                                &push_rindex_is_zero_chip,
                                &length_is_zero_chip,
                                offset,
                                true,
                                offset == last_row_offset,
                                row.hash,
                                row.tag,
                                row.index,
                                row.is_code,
                                row.value,
                                push_rindex,
                                hash_rlc,
                                hash_length,
                                F::from(byte_push_size as u64),
                                idx == bytecode.bytes.len(),
                                false,
                                F::from(push_rindex_prev),
                            )?;
                            push_rindex_prev = push_rindex;
                            offset += 1;
                        }
                    }

                    // Padding
                    for idx in offset..size {
                        self.set_row(
                            &mut region,
                            &push_rindex_is_zero_chip,
                            &length_is_zero_chip,
                            idx,
                            idx < size,
                            idx == last_row_offset,
                            F::zero(),
                            F::from(BytecodeFieldTag::Padding as u64),
                            F::zero(),
                            F::one(),
                            F::zero(),
                            0,
                            F::zero(),
                            F::zero(),
                            F::zero(),
                            true,
                            true,
                            F::from(push_rindex_prev),
                        )?;
                        push_rindex_prev = 0;
                    }

                    Ok(())
                },
            )
            .ok();
    }

    #[allow(clippy::too_many_arguments)]
    fn set_row(
        &self,
        region: &mut Region<'_, F>,
        push_rindex_is_zero_chip: &IsZeroChip<F>,
        length_is_zero_chip: &IsZeroChip<F>,
        offset: usize,
        enable: bool,
        last: bool,
        hash: F,
        tag: F,
        index: F,
        is_code: F,
        value: F,
        push_rindex: u64,
        hash_rlc: F,
        hash_length: F,
        byte_push_size: F,
        is_final: bool,
        padding: bool,
        push_rindex_prev: F,
    ) -> Result<(), Error> {
        // q_enable
        if enable {
            self.q_enable.enable(region, offset)?;
        }

        // q_first
        region.assign_fixed(
            || format!("assign q_first {}", offset),
            self.q_first,
            offset,
            || Ok(F::from((offset == 0) as u64)),
        )?;

        // q_last
        if last {
            self.q_last.enable(region, offset)?;
        }

        // Advices
        for (name, column, value) in &[
            ("hash", self.hash, hash),
            ("tag", self.tag, tag),
            ("index", self.index, index),
            ("is_code", self.is_code, is_code),
            ("value", self.value, value),
            ("push_rindex", self.push_rindex, F::from(push_rindex)),
            ("hash_rlc", self.hash_rlc, hash_rlc),
            ("hash_length", self.hash_length, hash_length),
            ("byte_push_size", self.byte_push_size, byte_push_size),
            ("is_final", self.is_final, F::from(is_final as u64)),
            ("padding", self.padding, F::from(padding as u64)),
        ] {
            region.assign_advice(
                || format!("assign {} {}", name, offset),
                *column,
                offset,
                || Ok(*value),
            )?;
        }

        // push_rindex_is_zero_chip
        push_rindex_is_zero_chip.assign(region, offset, Some(push_rindex_prev))?;

        // length_is_zero chip
        length_is_zero_chip.assign(region, offset, Some(hash_length))?;

        Ok(())
    }

    pub(crate) fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        bytecodes: &[UnrolledBytecode<F>],
    ) -> Result<(), Error> {
        // push table: BYTE -> NUM_PUSHED:
        // [0, OpcodeId::PUSH1[ -> 0
        // [OpcodeId::PUSH1, OpcodeId::PUSH32] -> [1..32]
        // ]OpcodeId::PUSH32, 256[ -> 0
        layouter.assign_region(
            || "push table",
            |mut region| {
                for byte in 0usize..256 {
                    let push_size = get_push_size(byte as u8);
                    for (name, column, value) in &[
                        ("byte", self.push_table[0], byte as u64),
                        ("push_size", self.push_table[1], push_size),
                    ] {
                        region.assign_fixed(
                            || format!("Push table assign {} {}", name, byte),
                            *column,
                            byte,
                            || Ok(F::from(*value)),
                        )?;
                    }
                }
                Ok(())
            },
        )?;

        // keccak table
        layouter.assign_region(
            || "keccak table",
            |mut region| {
                for (offset, bytecode) in bytecodes.iter().map(|v| v.bytes.clone()).enumerate() {
                    let hash: F = keccak(&bytecode[..], self.r);
                    let rlc: F = linear_combine(bytecode.clone(), self.r);
                    let size = F::from(bytecode.len() as u64);
                    for (name, column, value) in &[
                        ("rlc", self.keccak_table[0], rlc),
                        ("size", self.keccak_table[1], size),
                        ("hash", self.keccak_table[2], hash),
                    ] {
                        region.assign_advice(
                            || format!("Keccak table assign {} {}", name, offset),
                            *column,
                            offset,
                            || Ok(*value),
                        )?;
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}

fn unroll<F: Field>(bytes: Vec<u8>, r: F) -> UnrolledBytecode<F> {
    let hash = keccak(&bytes[..], r);
    let mut rows = vec![BytecodeRow::<F> {
        hash,
        tag: F::from(BytecodeFieldTag::Length as u64),
        index: F::zero(),
        is_code: F::zero(),
        value: F::from(bytes.len() as u64),
    }];
    // Run over all the bytes
    let mut push_rindex = 0;
    for (index, byte) in bytes.iter().enumerate() {
        // Track which byte is an opcode and which is push data
        let is_code = push_rindex == 0;
        push_rindex = if is_code {
            get_push_size(*byte)
        } else {
            push_rindex - 1
        };

        rows.push(BytecodeRow::<F> {
            hash,
            tag: F::from(BytecodeFieldTag::Byte as u64),
            index: F::from(index as u64),
            is_code: F::from(is_code as u64),
            value: F::from(*byte as u64),
        });
    }
    UnrolledBytecode { bytes, rows }
}

fn is_push(byte: u8) -> bool {
    OpcodeId::PUSH1.as_u8() <= byte && byte <= OpcodeId::PUSH32.as_u8()
}

fn get_push_size(byte: u8) -> u64 {
    if is_push(byte) {
        byte as u64 - OpcodeId::PUSH1.as_u64() + 1
    } else {
        0u64
    }
}

fn keccak<F: Field>(msg: &[u8], r: F) -> F {
    let mut keccak = Keccak::default();
    keccak.update(msg);
    RandomLinearCombination::<F, 32>::random_linear_combine(keccak.digest().try_into().unwrap(), r)
}

fn into_words(message: &[u8]) -> Vec<u64> {
    let words_total = message.len() / 8;
    let mut words: Vec<u64> = vec![0; words_total];

    for i in 0..words_total {
        let mut word_bits: [u8; 8] = Default::default();
        word_bits.copy_from_slice(&message[i * 8..i * 8 + 8]);
        words[i] = u64::from_le_bytes(word_bits);
    }

    words
}

fn linear_combine<F: Field>(bytes: Vec<u8>, r: F) -> F {
    encode(bytes.into_iter(), r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{Bytecode, Word};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use pairing::bn256::Fr;

    #[derive(Default)]
    struct MyCircuit<F: Field> {
        bytecodes: Vec<UnrolledBytecode<F>>,
        size: usize,
    }

    impl<F: Field> MyCircuit<F> {
        fn r() -> F {
            F::from(123456)
        }
    }

    impl<F: Field> Circuit<F> for MyCircuit<F> {
        type Config = Config<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            Config::configure(meta, MyCircuit::r())
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.load(&mut layouter, &self.bytecodes)?;
            config.assign(layouter, self.size, &self.bytecodes);
            Ok(())
        }
    }

    fn verify<F: Field>(k: u32, bytecodes: Vec<UnrolledBytecode<F>>, success: bool) {
        let circuit = MyCircuit::<F> {
            bytecodes,
            size: 2usize.pow(k),
        };

        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        let err = prover.verify();
        let print_failures = true;
        if err.is_err() && print_failures {
            for e in err.err().iter() {
                for s in e.iter() {
                    println!("{}", s);
                }
            }
        }
        let err = prover.verify();
        assert_eq!(err.is_ok(), success);
    }

    /// Verify unrolling code
    #[test]
    fn bytecode_unrolling() {
        let k = 10;
        let r = MyCircuit::r();
        let mut rows = vec![];
        let mut bytecode = Bytecode::default();
        // First add all non-push bytes, which should all be seen as code
        for byte in 0u8..=255u8 {
            if !is_push(byte) {
                bytecode.write(byte);
                rows.push(BytecodeRow {
                    hash: Fr::zero(),
                    tag: Fr::from(BytecodeFieldTag::Byte as u64),
                    index: Fr::from(rows.len() as u64),
                    is_code: Fr::from(true as u64),
                    value: Fr::from(byte as u64),
                });
            }
        }
        // Now add the different push ops
        for n in 1..=32 {
            let data_byte = OpcodeId::PUSH32.as_u8();
            bytecode.push(n, Word::from_little_endian(&vec![data_byte; n][..]));
            rows.push(BytecodeRow {
                hash: Fr::zero(),
                tag: Fr::from(BytecodeFieldTag::Byte as u64),
                index: Fr::from(rows.len() as u64),
                is_code: Fr::from(true as u64),
                value: Fr::from(OpcodeId::PUSH1.as_u64() + ((n - 1) as u64)),
            });
            for _ in 0..n {
                rows.push(BytecodeRow {
                    hash: Fr::zero(),
                    tag: Fr::from(BytecodeFieldTag::Byte as u64),
                    index: Fr::from(rows.len() as u64),
                    is_code: Fr::from(false as u64),
                    value: Fr::from(data_byte as u64),
                });
            }
        }
        // Set the hash of the complete bytecode in the rows
        let hash = keccak(&bytecode.to_vec()[..], r);
        for row in rows.iter_mut() {
            row.hash = hash;
        }
        rows.insert(
            0,
            BytecodeRow {
                hash,
                tag: Fr::from(BytecodeFieldTag::Length as u64),
                index: Fr::zero(),
                is_code: Fr::zero(),
                value: Fr::from(bytecode.to_vec().len() as u64),
            },
        );
        // Unroll the bytecode
        let unrolled = unroll(bytecode.to_vec(), r);
        // Check if the bytecode was unrolled correctly
        assert_eq!(
            UnrolledBytecode {
                bytes: bytecode.to_vec(),
                rows,
            },
            unrolled,
        );
        // Verify the unrolling in the circuit
        verify::<Fr>(k, vec![unrolled], true);
    }

    /// Tests a fully empty circuit
    #[test]
    fn bytecode_empty() {
        let k = 9;
        let r = MyCircuit::r();
        verify::<Fr>(k, vec![unroll(vec![], r)], true);
    }

    #[test]
    fn bytecode_simple() {
        let k = 9;
        let r = MyCircuit::r();
        let bytecodes = vec![
            unroll(vec![7u8], r),
            unroll(vec![6u8], r),
            unroll(vec![5u8], r),
        ];
        verify::<Fr>(k, bytecodes, true);
    }

    /// Tests a fully full circuit
    #[test]
    fn bytecode_full() {
        let k = 9;
        let r = MyCircuit::r();
        verify::<Fr>(k, vec![unroll(vec![7u8; 2usize.pow(k) - 7], r)], true);
    }

    /// Tests a circuit with incomplete bytecode
    #[test]
    fn bytecode_incomplete() {
        let k = 9;
        let r = MyCircuit::r();
        verify::<Fr>(k, vec![unroll(vec![7u8; 2usize.pow(k) + 1], r)], false);
    }

    /// Tests multiple bytecodes in a single circuit
    #[test]
    fn bytecode_push() {
        let k = 9;
        let r = MyCircuit::r();
        verify::<Fr>(
            k,
            vec![
                unroll(vec![], r),
                unroll(vec![OpcodeId::PUSH32.as_u8()], r),
                unroll(vec![OpcodeId::PUSH32.as_u8(), OpcodeId::ADD.as_u8()], r),
                unroll(vec![OpcodeId::ADD.as_u8(), OpcodeId::PUSH32.as_u8()], r),
                unroll(
                    vec![
                        OpcodeId::ADD.as_u8(),
                        OpcodeId::PUSH32.as_u8(),
                        OpcodeId::ADD.as_u8(),
                    ],
                    r,
                ),
            ],
            true,
        );
    }

    /// Test invalid hash data
    #[test]
    fn bytecode_invalid_hash_data() {
        let k = 9;
        let r = MyCircuit::r();
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode, r);
        verify::<Fr>(k, vec![unrolled.clone()], true);
        // Change the hash on the first position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[0].hash += Fr::from(1u64);
            verify::<Fr>(k, vec![invalid], false);
        }
        // Change the hash on another position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[4].hash += Fr::from(1u64);
            verify::<Fr>(k, vec![invalid], false);
        }
        // Change all the hashes so it doesn't match the keccak lookup hash
        {
            let mut invalid = unrolled;
            for row in invalid.rows.iter_mut() {
                row.hash = Fr::one();
            }
            verify::<Fr>(k, vec![invalid], false);
        }
    }

    /// Test invalid index
    #[test]
    #[ignore]
    fn bytecode_invalid_index() {
        let k = 9;
        let r = MyCircuit::r();
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode, r);
        verify::<Fr>(k, vec![unrolled.clone()], true);
        // Start the index at 1
        {
            let mut invalid = unrolled.clone();
            for row in invalid.rows.iter_mut() {
                row.index += Fr::one();
            }
            verify::<Fr>(k, vec![invalid], false);
        }
        // Don't increment an index once
        {
            let mut invalid = unrolled;
            invalid.rows.last_mut().unwrap().index -= Fr::one();
            verify::<Fr>(k, vec![invalid], false);
        }
    }

    /// Test invalid byte data
    #[test]
    fn bytecode_invalid_byte_data() {
        let k = 9;
        let r = MyCircuit::r();
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode, r);
        verify::<Fr>(k, vec![unrolled.clone()], true);
        // Change the first byte
        {
            let mut invalid = unrolled.clone();
            invalid.rows[1].value = Fr::from(9u64);
            verify::<Fr>(k, vec![invalid], false);
        }
        // Change a byte on another position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[5].value = Fr::from(6u64);
            verify::<Fr>(k, vec![invalid], false);
        }
        // Set a byte value out of range
        {
            let mut invalid = unrolled;
            invalid.rows[3].value = Fr::from(256u64);
            verify::<Fr>(k, vec![invalid], false);
        }
    }

    /// Test invalid is_code data
    #[test]
    fn bytecode_invalid_is_code() {
        let k = 9;
        let r = MyCircuit::r();
        let bytecode = vec![
            OpcodeId::ADD.as_u8(),
            OpcodeId::PUSH1.as_u8(),
            OpcodeId::PUSH1.as_u8(),
            OpcodeId::SUB.as_u8(),
            OpcodeId::PUSH7.as_u8(),
            OpcodeId::ADD.as_u8(),
            OpcodeId::PUSH6.as_u8(),
        ];
        let unrolled = unroll(bytecode, r);
        verify::<Fr>(k, vec![unrolled.clone()], true);
        // Mark the 3rd byte as code (is push data from the first PUSH1)
        {
            let mut invalid = unrolled.clone();
            invalid.rows[3].is_code = Fr::one();
            verify::<Fr>(k, vec![invalid], false);
        }
        // Mark the 4rd byte as data (is code)
        {
            let mut invalid = unrolled.clone();
            invalid.rows[4].is_code = Fr::zero();
            verify::<Fr>(k, vec![invalid], false);
        }
        // Mark the 7th byte as code (is data for the PUSH7)
        {
            let mut invalid = unrolled;
            invalid.rows[7].is_code = Fr::one();
            verify::<Fr>(k, vec![invalid], false);
        }
    }
}
