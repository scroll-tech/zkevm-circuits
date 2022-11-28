use crate::{
    evm_circuit::util::{
        and, constraint_builder::BaseConstraintBuilder, not, or, select, RandomLinearCombination,
    },
    table::{BytecodeFieldTag, BytecodeTable, KeccakTable},
    util::{Challenges, Expr},
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, Word};
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, Selector,
        VirtualCells,
    },
    poly::Rotation,
};
use itertools::zip;
use keccak256::plain::Keccak;
use std::vec;

use super::param::PUSH_TABLE_WIDTH;
/// Public data for the bytecode
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct BytecodeRow<F: Field> {
    code_hash: Word,
    tag: F,
    index: F,
    is_code: F,
    value: F,
}

/// Unrolled bytecode
#[derive(Clone, Debug, PartialEq)]
pub struct UnrolledBytecode<F: Field> {
    pub(crate) bytes: Vec<u8>,
    rows: Vec<BytecodeRow<F>>,
}

#[derive(Clone, Debug)]
/// Bytecode circuit configuration
pub struct Config<F> {
    minimum_rows: usize,
    q_enable: Column<Fixed>,
    q_first: Column<Fixed>,
    q_last: Selector,
    bytecode_table: BytecodeTable,
    push_rindex: Column<Advice>,
    hash_input_rlc: Column<Advice>,
    code_length: Column<Advice>,
    byte_push_size: Column<Advice>,
    is_final: Column<Advice>,
    padding: Column<Advice>,
    push_rindex_inv: Column<Advice>,
    push_rindex_is_zero: IsZeroConfig<F>,
    length_inv: Column<Advice>,
    length_is_zero: IsZeroConfig<F>,
    push_table: [Column<Fixed>; PUSH_TABLE_WIDTH],
    pub(crate) keccak_table: KeccakTable,
}

impl<F: Field> Config<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        bytecode_table: BytecodeTable,
        keccak_table: KeccakTable,
        challenges: Challenges<Expression<F>>,
    ) -> Self {
        let q_enable = meta.fixed_column();
        let q_first = meta.fixed_column();
        let q_last = meta.selector();
        let value = bytecode_table.value;
        let push_rindex = meta.advice_column();
        let hash_input_rlc = meta.advice_column_in(SecondPhase);
        let code_length = meta.advice_column();
        let byte_push_size = meta.advice_column();
        let is_final = meta.advice_column();
        let padding = meta.advice_column();
        let push_rindex_inv = meta.advice_column();
        let length_inv = meta.advice_column();
        let push_table = array_init::array_init(|_| meta.fixed_column());

        // A byte is an opcode when `push_rindex == 0` on the previous row,
        // else it's push data.
        let push_rindex_is_zero = IsZeroChip::configure(
            meta,
            |meta| {
                // Conditions:
                // - Not on the first row
                meta.query_fixed(q_enable, Rotation::cur())
                    * not::expr(meta.query_fixed(q_first, Rotation::cur()))
            },
            |meta| meta.query_advice(push_rindex, Rotation::prev()),
            push_rindex_inv,
        );

        // Does the current row have bytecode field tag == Length?
        let is_row_tag_length = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                not::expr(meta.query_advice(padding, Rotation::cur())),
                not::expr(meta.query_advice(bytecode_table.tag, Rotation::cur())),
            ])
        };

        // Does the current row have bytecode field tag == Byte?
        let is_row_tag_byte = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                not::expr(meta.query_advice(padding, Rotation::cur())),
                meta.query_advice(bytecode_table.tag, Rotation::cur()),
            ])
        };

        // For a row tagged Length, is the length (value) zero?
        let length_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_fixed(q_enable, Rotation::cur()) * is_row_tag_length(meta),
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
                    not::expr(meta.query_advice(bytecode_table.tag, Rotation::prev())),
                ])
            };

            cb.require_equal(
                "if prev_row.tag == Length: index == 0 else index == index + 1",
                meta.query_advice(bytecode_table.index, Rotation::cur()),
                select::expr(
                    is_prev_row_tag_length(meta),
                    0.expr(),
                    meta.query_advice(bytecode_table.index, Rotation::prev()) + 1.expr(),
                ),
            );
            cb.require_equal(
                "is_code := push_rindex_prev == 0",
                meta.query_advice(bytecode_table.is_code, Rotation::cur()),
                select::expr(
                    is_prev_row_tag_length(meta),
                    1.expr(),
                    push_rindex_is_zero.clone().is_zero_expression,
                ),
            );
            cb.require_equal(
                "hash_input_rlc := hash_input_rlc_prev * challenges.keccak_input + byte",
                meta.query_advice(hash_input_rlc, Rotation::cur()),
                meta.query_advice(hash_input_rlc, Rotation::prev()) * challenges.keccak_input()
                    + meta.query_advice(value, Rotation::cur()),
            );
            cb.require_equal(
                "code_hash needs to remain the same",
                meta.query_advice(bytecode_table.code_hash, Rotation::cur()),
                meta.query_advice(bytecode_table.code_hash, Rotation::prev()),
            );
            cb.require_equal(
                "code_length needs to remain the same",
                meta.query_advice(code_length, Rotation::cur()),
                meta.query_advice(code_length, Rotation::prev()),
            );
            cb.require_equal(
                "padding needs to remain the same",
                meta.query_advice(padding, Rotation::cur()),
                meta.query_advice(padding, Rotation::prev()),
            );

            // Conditions:
            // - Continuing
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                q_continue(meta),
            ]))
        });

        meta.create_gate("start of bytecode", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.require_equal(
                "next_row.tag == (tag.Length or tag.Padding) if length == 0 else tag.Byte",
                meta.query_advice(bytecode_table.tag, Rotation::next()),
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
                "if row.tag == tag.Length: value == row.code_length",
                meta.query_advice(value, Rotation::cur()),
                meta.query_advice(code_length, Rotation::cur()),
            );
            // FIXME: Since randomness is only known at synthesis time, the RLC of empty
            // code_hash is not constant.  Consider doing a lookup to the empty code_hash
            // value? cb.condition(length_is_zero.clone().is_zero_expression,
            // |cb| {     cb.require_equal(
            //         "if length == 0: code_hash == RLC(EMPTY_HASH, randomness)",
            //         meta.query_advice(bytecode_table.code_hash, Rotation::cur()),
            //         Expression::Constant(keccak(&[], randomness)),
            //     );
            // });

            // Conditions:
            // - Not Continuing
            // - This is the start of a new bytecode
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
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
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(is_row_tag_length(meta)),
                not::expr(q_continue(meta)),
            ]))
        });

        meta.create_gate("length needs to be correct", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.condition(1.expr() - length_is_zero.clone().is_zero_expression, |cb| {
                cb.require_equal(
                    "index + 1 needs to equal code_length",
                    meta.query_advice(bytecode_table.index, Rotation::cur()) + 1.expr(),
                    meta.query_advice(code_length, Rotation::cur()),
                );
            });
            // Conditions:
            // - On the row with the last byte (`is_final == 1`)
            // - Of bytecode with length > 0
            // - Not padding
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
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
                        meta.query_advice(bytecode_table.is_code, Rotation::cur()),
                        meta.query_advice(byte_push_size, Rotation::cur()),
                        meta.query_advice(push_rindex, Rotation::prev()) - 1.expr(),
                    ),
                );
            });
            // Conditions: Always
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
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
                meta.query_fixed(q_enable, Rotation::cur()),
                not::expr(meta.query_fixed(q_first, Rotation::cur())),
            ]))
        });

        // The code_hash is checked on the latest row because only then have
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
            // Conditions: Always
            let q_enable = meta.query_fixed(q_enable, Rotation::cur()) * is_row_tag_byte(meta);
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
            let lookup_input_columns = vec![hash_input_rlc, code_length, bytecode_table.code_hash];
            let lookup_table_columns = vec![
                keccak_table.input_rlc,
                keccak_table.input_len,
                keccak_table.output_rlc,
            ];
            let mut constraints = vec![(
                enable.clone(),
                meta.query_advice(keccak_table.is_enabled, Rotation::cur()),
            )];
            for (input_column, table_column) in zip(lookup_input_columns, lookup_table_columns) {
                constraints.push((
                    enable.clone() * meta.query_advice(input_column, Rotation::cur()),
                    meta.query_advice(table_column, Rotation::cur()),
                ))
            }
            constraints
        });

        Config {
            minimum_rows: meta.minimum_rows(),
            q_enable,
            q_first,
            q_last,
            bytecode_table,
            push_rindex,
            hash_input_rlc,
            code_length,
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
        layouter: &mut impl Layouter<F>,
        size: usize,
        witness: &[UnrolledBytecode<F>],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        self.assign_internal(layouter, size, witness, challenges, true)
    }

    pub(crate) fn assign_internal(
        &self,
        layouter: &mut impl Layouter<F>,
        size: usize,
        witness: &[UnrolledBytecode<F>],
        challenges: &Challenges<Value<F>>,
        fail_fast: bool,
    ) -> Result<(), Error> {
        let push_rindex_is_zero_chip = IsZeroChip::construct(self.push_rindex_is_zero.clone());
        let length_is_zero_chip = IsZeroChip::construct(self.length_is_zero.clone());

        // Subtract the unusable rows from the size
        assert!(size > self.minimum_rows);
        let last_row_offset = size - self.minimum_rows + 1;

        layouter.assign_region(
            || "assign bytecode",
            |mut region| {
                let mut offset = 0;
                let mut push_rindex_prev = 0;
                for bytecode in witness.iter() {
                    // Run over all the bytes
                    let mut push_rindex = 0;
                    let mut byte_push_size = 0;
                    let mut hash_input_rlc = challenges.keccak_input().map(|_| F::zero());
                    let code_length = F::from(bytecode.bytes.len() as u64);
                    for (idx, row) in bytecode.rows.iter().enumerate() {
                        if fail_fast && offset > last_row_offset {
                            log::error!(
                                "Bytecode Circuit: offset={} > last_row_offset={}",
                                offset,
                                last_row_offset
                            );
                            return Err(Error::Synthesis);
                        }

                        let code_hash = challenges.evm_word().map(|challenge| {
                            RandomLinearCombination::<F, 32>::random_linear_combine(
                                row.code_hash.to_le_bytes(),
                                challenge,
                            )
                        });

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
                            hash_input_rlc.as_mut().zip(challenges.keccak_input()).map(
                                |(hash_input_rlc, challenge)| {
                                    *hash_input_rlc = *hash_input_rlc * challenge + row.value
                                },
                            );
                        }

                        // Set the data for this row
                        if offset <= last_row_offset {
                            self.set_row(
                                &mut region,
                                &push_rindex_is_zero_chip,
                                &length_is_zero_chip,
                                offset,
                                true,
                                offset == last_row_offset,
                                code_hash,
                                row.tag,
                                row.index,
                                row.is_code,
                                row.value,
                                push_rindex,
                                hash_input_rlc,
                                code_length,
                                F::from(byte_push_size as u64),
                                idx == bytecode.bytes.len(),
                                false,
                                F::from(push_rindex_prev),
                            )?;
                            push_rindex_prev = push_rindex;
                            offset += 1;
                        }
                    }
                }

                // Padding
                for idx in offset..=last_row_offset {
                    self.set_row(
                        &mut region,
                        &push_rindex_is_zero_chip,
                        &length_is_zero_chip,
                        idx,
                        idx < last_row_offset,
                        idx == last_row_offset,
                        Value::known(F::zero()),
                        F::from(BytecodeFieldTag::Padding as u64),
                        F::zero(),
                        F::one(),
                        F::zero(),
                        0,
                        Value::known(F::zero()),
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
        code_hash: Value<F>,
        tag: F,
        index: F,
        is_code: F,
        value: F,
        push_rindex: u64,
        hash_input_rlc: Value<F>,
        code_length: F,
        byte_push_size: F,
        is_final: bool,
        padding: bool,
        push_rindex_prev: F,
    ) -> Result<(), Error> {
        // q_enable
        region.assign_fixed(
            || format!("assign q_enable {}", offset),
            self.q_enable,
            offset,
            || Value::known(F::from(enable as u64)),
        )?;

        // q_first
        region.assign_fixed(
            || format!("assign q_first {}", offset),
            self.q_first,
            offset,
            || Value::known(F::from((offset == 0) as u64)),
        )?;

        // q_last
        if last {
            self.q_last.enable(region, offset)?;
        }

        // Advices
        for (name, column, value) in [
            ("tag", self.bytecode_table.tag, tag),
            ("index", self.bytecode_table.index, index),
            ("is_code", self.bytecode_table.is_code, is_code),
            ("value", self.bytecode_table.value, value),
            ("push_rindex", self.push_rindex, F::from(push_rindex)),
            ("code_length", self.code_length, code_length),
            ("byte_push_size", self.byte_push_size, byte_push_size),
            ("is_final", self.is_final, F::from(is_final as u64)),
            ("padding", self.padding, F::from(padding as u64)),
        ] {
            region.assign_advice(
                || format!("assign {} {}", name, offset),
                column,
                offset,
                || Value::known(value),
            )?;
        }
        for (name, column, value) in [
            ("code_hash", self.bytecode_table.code_hash, code_hash),
            ("hash_input_rlc", self.hash_input_rlc, hash_input_rlc),
        ] {
            region.assign_advice(
                || format!("assign {} {}", name, offset),
                column,
                offset,
                || value,
            )?;
        }

        // push_rindex_is_zero_chip
        push_rindex_is_zero_chip.assign(region, offset, Value::known(push_rindex_prev))?;

        // length_is_zero chip
        length_is_zero_chip.assign(region, offset, Value::known(code_length))?;

        Ok(())
    }

    /// load fixed tables
    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        // push table: BYTE -> NUM_PUSHED:
        // [0, OpcodeId::PUSH1] -> 0
        // [OpcodeId::PUSH1, OpcodeId::PUSH32] -> [1..32]
        // [OpcodeId::PUSH32, 256] -> 0
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
                            || Value::known(F::from(*value)),
                        )?;
                    }
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}

/// Get unrolled bytecode from raw bytes
pub fn unroll<F: Field>(bytes: Vec<u8>) -> UnrolledBytecode<F> {
    let code_hash = keccak(&bytes[..]);
    let mut rows = vec![BytecodeRow::<F> {
        code_hash,
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
            code_hash,
            tag: F::from(BytecodeFieldTag::Byte as u64),
            index: F::from(index as u64),
            is_code: F::from(is_code as u64),
            value: F::from(*byte as u64),
        });
    }
    UnrolledBytecode { bytes, rows }
}

fn is_push(byte: u8) -> bool {
    OpcodeId::from(byte).is_push()
}

fn get_push_size(byte: u8) -> u64 {
    if is_push(byte) {
        byte as u64 - OpcodeId::PUSH1.as_u64() + 1
    } else {
        0u64
    }
}

fn keccak(msg: &[u8]) -> Word {
    let mut keccak = Keccak::default();
    keccak.update(msg);
    Word::from_big_endian(keccak.digest().as_slice())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode_circuit::dev::test_bytecode_circuit_unrolled;
    use eth_types::Bytecode;
    use halo2_proofs::halo2curves::bn256::Fr;

    fn get_randomness<F: Field>() -> F {
        F::from(123456)
    }

    /// Verify unrolling code
    #[test]
    fn bytecode_unrolling() {
        let k = 10;
        let mut rows = vec![];
        let mut bytecode = Bytecode::default();
        // First add all non-push bytes, which should all be seen as code
        for byte in 0u8..=255u8 {
            if !is_push(byte) {
                bytecode.write(byte, true);
                rows.push(BytecodeRow {
                    code_hash: Word::zero(),
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
            bytecode.push(
                n,
                Word::from_little_endian(&vec![data_byte; n as usize][..]),
            );
            rows.push(BytecodeRow {
                code_hash: Word::zero(),
                tag: Fr::from(BytecodeFieldTag::Byte as u64),
                index: Fr::from(rows.len() as u64),
                is_code: Fr::from(true as u64),
                value: Fr::from(OpcodeId::PUSH1.as_u64() + ((n - 1) as u64)),
            });
            for _ in 0..n {
                rows.push(BytecodeRow {
                    code_hash: Word::zero(),
                    tag: Fr::from(BytecodeFieldTag::Byte as u64),
                    index: Fr::from(rows.len() as u64),
                    is_code: Fr::from(false as u64),
                    value: Fr::from(data_byte as u64),
                });
            }
        }
        // Set the code_hash of the complete bytecode in the rows
        let code_hash = keccak(&bytecode.to_vec()[..]);
        for row in rows.iter_mut() {
            row.code_hash = code_hash;
        }
        rows.insert(
            0,
            BytecodeRow {
                code_hash,
                tag: Fr::from(BytecodeFieldTag::Length as u64),
                index: Fr::zero(),
                is_code: Fr::zero(),
                value: Fr::from(bytecode.to_vec().len() as u64),
            },
        );
        // Unroll the bytecode
        let unrolled = unroll(bytecode.to_vec());
        // Check if the bytecode was unrolled correctly
        assert_eq!(
            UnrolledBytecode {
                bytes: bytecode.to_vec(),
                rows,
            },
            unrolled,
        );
        // Verify the unrolling in the circuit
        test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled], true);
    }

    /// Tests a fully empty circuit
    #[test]
    fn bytecode_empty() {
        let k = 9;
        test_bytecode_circuit_unrolled::<Fr>(k, vec![unroll(vec![])], true);
    }

    #[test]
    fn bytecode_simple() {
        let k = 9;
        let bytecodes = vec![unroll(vec![7u8]), unroll(vec![6u8]), unroll(vec![5u8])];
        test_bytecode_circuit_unrolled::<Fr>(k, bytecodes, true);
    }

    /// Tests a fully full circuit
    #[test]
    fn bytecode_full() {
        let k = 9;
        test_bytecode_circuit_unrolled::<Fr>(k, vec![unroll(vec![7u8; 2usize.pow(k) - 7])], true);
    }

    /// Tests a circuit with incomplete bytecode
    #[ignore = "keccak rows larger than bytecode rows"]
    #[test]
    fn bytecode_incomplete() {
        let k = 12;
        test_bytecode_circuit_unrolled::<Fr>(
            k - 3,
            vec![unroll(vec![7u8; 2usize.pow(k) + 1])],
            false,
        );
    }

    /// Tests multiple bytecodes in a single circuit
    #[test]
    fn bytecode_push() {
        let k = 9;
        test_bytecode_circuit_unrolled::<Fr>(
            k,
            vec![
                unroll(vec![]),
                unroll(vec![OpcodeId::PUSH32.as_u8()]),
                unroll(vec![OpcodeId::PUSH32.as_u8(), OpcodeId::ADD.as_u8()]),
                unroll(vec![OpcodeId::ADD.as_u8(), OpcodeId::PUSH32.as_u8()]),
                unroll(vec![
                    OpcodeId::ADD.as_u8(),
                    OpcodeId::PUSH32.as_u8(),
                    OpcodeId::ADD.as_u8(),
                ]),
            ],
            true,
        );
    }

    /// Test invalid code_hash data
    #[test]
    fn bytecode_invalid_hash_data() {
        let k = 9;
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode);
        test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
        // Change the code_hash on the first position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[0].code_hash += Word::one();
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
        // Change the code_hash on another position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[4].code_hash += Word::one();
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
        // Change all the hashes so it doesn't match the keccak lookup code_hash
        {
            let mut invalid = unrolled;
            for row in invalid.rows.iter_mut() {
                row.code_hash = Word::one();
            }
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
    }

    /// Test invalid index
    #[test]
    #[ignore]
    fn bytecode_invalid_index() {
        let k = 9;
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode);
        test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
        // Start the index at 1
        {
            let mut invalid = unrolled.clone();
            for row in invalid.rows.iter_mut() {
                row.index += Fr::one();
            }
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
        // Don't increment an index once
        {
            let mut invalid = unrolled;
            invalid.rows.last_mut().unwrap().index -= Fr::one();
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
    }

    /// Test invalid byte data
    #[test]
    fn bytecode_invalid_byte_data() {
        let k = 9;
        let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
        let unrolled = unroll(bytecode);
        test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
        // Change the first byte
        {
            let mut invalid = unrolled.clone();
            invalid.rows[1].value = Fr::from(9u64);
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
        // Change a byte on another position
        {
            let mut invalid = unrolled.clone();
            invalid.rows[5].value = Fr::from(6u64);
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
        // Set a byte value out of range
        {
            let mut invalid = unrolled;
            invalid.rows[3].value = Fr::from(256u64);
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
    }

    /// Test invalid is_code data
    #[test]
    fn bytecode_invalid_is_code() {
        let k = 9;
        let bytecode = vec![
            OpcodeId::ADD.as_u8(),
            OpcodeId::PUSH1.as_u8(),
            OpcodeId::PUSH1.as_u8(),
            OpcodeId::SUB.as_u8(),
            OpcodeId::PUSH7.as_u8(),
            OpcodeId::ADD.as_u8(),
            OpcodeId::PUSH6.as_u8(),
        ];
        let unrolled = unroll(bytecode);
        test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
        // Mark the 3rd byte as code (is push data from the first PUSH1)
        {
            let mut invalid = unrolled.clone();
            invalid.rows[3].is_code = Fr::one();
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
        // Mark the 4rd byte as data (is code)
        {
            let mut invalid = unrolled.clone();
            invalid.rows[4].is_code = Fr::zero();
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
        // Mark the 7th byte as code (is data for the PUSH7)
        {
            let mut invalid = unrolled;
            invalid.rows[7].is_code = Fr::one();
            test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
        }
    }
}
