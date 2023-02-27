use crate::{
    evm_circuit::util::{and, constraint_builder::BaseConstraintBuilder, not, or, rlc, select},
    table::{BytecodeFieldTag, KeccakTable, PoseidonTable},
    util::{Challenges, Expr, SubCircuitConfig},
};
use eth_types::Field;
use gadgets::is_zero::IsZeroChip;
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, VirtualCells},
    poly::Rotation,
};
use keccak256::EMPTY_HASH_LE;
use log::trace;
use std::vec;

use super::super::bytecode_unroller::{BytecodeRow, UnrolledBytecode};
use super::{BytecodeCircuitConfig, BytecodeCircuitConfigArgs};

/// specify byte in field for encoding bytecode
pub const HASHBLOCK_BYTES_IN_FIELD: usize = 16;

#[derive(Clone, Debug)]
/// Bytecode circuit (for hash block) configuration
/// basically the BytecodeCircuit include two parts:
/// a) marking and proving bytcodetable for bytecodes
/// b) mapping the bytes to keccaktable
/// and we re-useing the a) part and put additional
/// controlling cols to enable lookup from poseidon table
pub struct ToHashBlockCircuitConfig<F, const BYTES_IN_FIELD: usize> {
    base_conf: BytecodeCircuitConfig<F>,
    control_length: Column<Advice>,
    field_input: Column<Advice>,
    bytes_in_field_index: Column<Advice>,
    bytes_in_field_inv: Column<Advice>,
    is_field_border: Column<Advice>,
    padding_shift: Column<Advice>,
    field_index: Column<Advice>,
    field_index_inv: Column<Advice>,
    // External table
    pub(crate) poseidon_table: PoseidonTable,
    pub(crate) keccak_table: KeccakTable,
}

impl<F: Field, const BYTES_IN_FIELD: usize> ToHashBlockCircuitConfig<F, BYTES_IN_FIELD> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        base_conf: BytecodeCircuitConfig<F>,
        poseidon_table: PoseidonTable,
    ) -> Self {
        let base_conf_cl = base_conf.clone();
        let bytecode_table = base_conf.bytecode_table;
        // TODO: does this col still used for storing poseidon hash?
        // let code_hash = bytecode_table.code_hash;

        let q_enable = base_conf.q_enable; //from 0 to last avaliable row

        let control_length = meta.advice_column();
        let field_input = meta.advice_column();
        let bytes_in_field_index = meta.advice_column();
        let bytes_in_field_inv = meta.advice_column();
        let is_field_border = meta.advice_column();
        let padding_shift = meta.advice_column();
        let field_index = meta.advice_column();
        let field_index_inv = meta.advice_column();

        // some composited selectors are grepped from base
        // Does the current row have bytecode field tag == Byte?
        let is_row_tag_byte =
            |meta: &mut VirtualCells<F>| meta.query_advice(bytecode_table.tag, Rotation::cur());

        // Does the current row have bytecode field tag == Length (Now header)?
        let is_row_tag_length = |meta: &mut VirtualCells<F>| {
            not::expr(meta.query_advice(bytecode_table.tag, Rotation::cur()))
        };

        // Does the current row is final of a bytecode
        let is_byte_to_header = |meta: &mut VirtualCells<F>| {
            and::expr(vec![
                meta.query_advice(bytecode_table.tag, Rotation::cur()),
                not::expr(meta.query_advice(bytecode_table.tag, Rotation::next())),
            ])
        };

        meta.create_gate("always", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_field_border",
                meta.query_advice(is_field_border, Rotation::cur()),
            );

            // Conditions:
            // - always
            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        // current byte_in_field index is not the last one: i.e BYTES_IN_FIELD
        let q_byte_in_field_not_last = |meta: &mut VirtualCells<F>| {
            (BYTES_IN_FIELD.expr() - meta.query_advice(bytes_in_field_index, Rotation::cur()))
                * meta.query_advice(bytes_in_field_inv, Rotation::cur())
        };

        // current field index is not the last one of the input: i.e
        // PoseidonTable::INPUT_WIDTH
        let q_field_not_last = |meta: &mut VirtualCells<F>| {
            (PoseidonTable::INPUT_WIDTH.expr() - meta.query_advice(field_index, Rotation::cur()))
                * meta.query_advice(field_index_inv, Rotation::cur())
        };

        meta.create_gate("field byte cycling", |meta| {
            let mut cb = BaseConstraintBuilder::default();
            cb.condition(BYTES_IN_FIELD.expr() - meta.query_advice(bytes_in_field_index, Rotation::cur()), |cb|{
                cb.require_equal("q_byte_in_field_not_last = 1 except for BYTES_IN_FIELD",
                    1.expr(),
                    q_byte_in_field_not_last(meta),
                )
            });

            cb.require_equal("is_field_border := !q_byte_in_field_not_last or is_byte_to_header",
                meta.query_advice(is_field_border, Rotation::cur()),
                or::expr(vec![
                    not::expr(q_byte_in_field_not_last(meta)),
                    is_byte_to_header(meta),
                ]),
            );

            cb.require_equal(
                "byte_in_field_index := 1 if is_field_border_prev else (byte_in_field_index_prev + 1)",
                meta.query_advice(bytes_in_field_index, Rotation::cur()),
                select::expr(
                    meta.query_advice(is_field_border, Rotation::prev()),
                    1.expr(),
                    meta.query_advice(bytes_in_field_index, Rotation::prev()) + 1.expr(),
                )
            );

            let shifted_byte = meta.query_advice(bytecode_table.value, Rotation::cur()) *
                meta.query_advice(padding_shift, Rotation::cur());

            cb.require_equal(
                "field_input = byte * padding_shift if is_field_border_prev else field_input_prev + byte * padding_shift",
                meta.query_advice(field_input, Rotation::cur()),
                select::expr(
                    meta.query_advice(is_field_border, Rotation::prev()),
                    shifted_byte.clone(),
                    meta.query_advice(field_input, Rotation::prev()) + shifted_byte
                ),
            );

            cb.condition(not::expr(meta.query_advice(is_field_border, Rotation::prev())), |cb|{

                cb.require_equal(
                    "if field_continue (not is_field_border_prev) padding_shift := padding_shift_prev / 256",
                    meta.query_advice(padding_shift, Rotation::cur()) * 256.expr(),
                    meta.query_advice(padding_shift, Rotation::prev()),
                );
            });

            cb.condition(not::expr(q_byte_in_field_not_last(meta)), |cb|{

                cb.require_equal(
                    "if !q_byte_in_field_not_last padding_shift := 1",
                    meta.query_advice(padding_shift, Rotation::cur()),
                    1.expr(),
                );
            });

            // Conditions:
            // - Byte tag
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                is_row_tag_byte(meta),
            ]))
        });

        meta.create_gate("field input cycling", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.condition(PoseidonTable::INPUT_WIDTH.expr() - meta.query_advice(field_index, Rotation::cur()), |cb|{
                cb.require_equal("q_field_not_last = 1 except for PoseidonTable::INPUT_WIDTH",
                    1.expr(),
                    q_field_not_last(meta),
                )
            });

            let q_input_continue =
                (PoseidonTable::INPUT_WIDTH.expr() - meta.query_advice(field_index, Rotation::prev()))
                * meta.query_advice(field_index_inv, Rotation::prev());

            let q_input_border_last = and::expr([
                meta.query_advice(is_field_border, Rotation::prev()),
                not::expr(q_input_continue),
            ]);

            cb.require_equal(
                "control_length := base.length - bytecode_table.index if q_input_border_last else control_length_prev",
                meta.query_advice(control_length, Rotation::cur()),
                select::expr(
                    q_input_border_last.clone(),
                    meta.query_advice(base_conf.length, Rotation::cur()) -
                    meta.query_advice(bytecode_table.index, Rotation::cur()),
                    meta.query_advice(control_length, Rotation::prev())
                ),
            );

            cb.condition(q_input_border_last.clone(), |cb|{
                cb.require_equal(
                    "field_index = 1 on q_input_border_last",
                    1.expr(),
                    meta.query_advice(field_index, Rotation::cur())
                )
            });

            cb.condition(not::expr(q_input_border_last), |cb|{
                cb.require_equal(
                    "field_index := if is_field_border_last then field_index_prev + 1 else field_index_prev",
                    meta.query_advice(field_index, Rotation::cur()),
                    select::expr(
                        meta.query_advice(is_field_border, Rotation::prev()),
                        meta.query_advice(field_index, Rotation::prev()) + 1.expr(),
                        meta.query_advice(field_index, Rotation::prev()),
                    ),
                )
            });

            // Conditions:
            // - Byte tag
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                is_row_tag_byte(meta),
            ]))
        });

        meta.create_gate("start of bytecode", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "enforce not is_field_border",
                meta.query_advice(is_field_border, Rotation::cur()),
            );

            // enforce the next bytes_in_field_index is 1
            cb.require_zero(
                "enforce bytes_in_field_index is 0",
                meta.query_advice(bytes_in_field_index, Rotation::cur()),
            );

            // enforce the next field_index is 1
            cb.require_equal(
                "enforce field_index is 1",
                1.expr(),
                meta.query_advice(field_index, Rotation::cur()),
            );

            // the next field_index is code_length (the starting of ctrl_length)
            cb.require_equal(
                "control_length := base.length - bytecode_table.index",
                meta.query_advice(control_length, Rotation::cur()),
                meta.query_advice(base_conf.length, Rotation::cur())
                    - meta.query_advice(bytecode_table.index, Rotation::cur()),
            );

            // Conditions:
            // - Length (Now Header) tag
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                is_row_tag_length(meta),
            ]))
        });

        /* not need
        meta.create_gate("padding", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "enforce not is_field_border",
                meta.query_advice(is_field_border, Rotation::cur()),
            );
            // Conditions:
            // - Padding
            cb.gate(and::expr(vec![
                meta.query_fixed(q_enable, Rotation::cur()),
                meta.query_advice(base_conf.padding, Rotation::cur()),
            ]))
        });
         */

        #[cfg(feature = "codehash")]
        let lookup_columns = [/* code_hash, */ field_input, control_length];
        #[cfg(feature = "codehash")]
        let pick_hash_tbl_cols = |inp_i: usize| {
            let cols =
                <PoseidonTable as crate::table::LookupTable<F>>::advice_columns(&poseidon_table);
            [/* cols[0], */ cols[inp_i + 1], cols[cols.len() - 2]]
        };

        // we use a special selection exp for only 2 indexs
        #[cfg(feature = "codehash")]
        let field_selector = |meta: &mut VirtualCells<F>| {
            let field_index = meta.query_advice(field_index, Rotation::cur()) - 1.expr();
            [1.expr() - field_index.clone(), field_index]
        };

        // poseidon lookup:
        //  * PoseidonTable::INPUT_WIDTH lookups for each input field
        //  * PoseidonTable::INPUT_WIDTH -1 lookups for the padded zero input
        //  so we have 2*PoseidonTable::INPUT_WIDTH -1 lookups

        #[cfg(feature = "codehash")]
        for i in 0..PoseidonTable::INPUT_WIDTH {
            meta.lookup_any("poseidon input", |meta| {
                // Conditions:
                // - On the row at **field border** (`is_field_border == 1`)
                // - the field_index match current i
                let enable = and::expr(vec![
                    meta.query_advice(is_field_border, Rotation::cur()),
                    field_selector(meta)[i].clone(),
                ]);
                let mut constraints = Vec::new(); /*vec![(
                                                      enable.clone(),
                                                      meta.query_advice(keccak_table.is_enabled, Rotation::cur()),
                                                  )];*/
                for (l_col, tbl_col) in lookup_columns.into_iter().zip(pick_hash_tbl_cols(i)) {
                    constraints.push((
                        enable.clone() * meta.query_advice(l_col, Rotation::cur()),
                        meta.query_advice(tbl_col, Rotation::cur()),
                    ))
                }
                constraints
            });
        }

        //the canonical form should be `for i in 1..PoseidonTable::INPUT_WIDTH{...}`
        #[cfg(feature = "codehash")]
        meta.lookup_any("poseidon input padding zero for final", |meta| {
            // Conditions:
            // - On the row with the last byte (`is_byte_to_header == 1`)
            // - Not padding
            // - the (0 begin) field_index is 1 (for we have only 2 input field)
            let enable = and::expr(vec![
                is_byte_to_header(meta),
                2.expr() - meta.query_advice(field_index, Rotation::cur()),
            ]);
            let mut constraints = Vec::new();
            for (l_exp, tbl_col) in [
                //                meta.query_advice(code_hash, Rotation::cur()),
                0.expr(),
                meta.query_advice(control_length, Rotation::cur()),
            ]
            .into_iter()
            .zip(pick_hash_tbl_cols(1))
            {
                constraints.push((
                    enable.clone() * l_exp,
                    meta.query_advice(tbl_col, Rotation::cur()),
                ))
            }
            constraints
        });

        // re-export keccak table in extended config
        let keccak_table = base_conf.keccak_table.clone();
        Self {
            base_conf: base_conf_cl,
            control_length,
            field_input,
            bytes_in_field_index,
            bytes_in_field_inv,
            is_field_border,
            padding_shift,
            field_index,
            field_index_inv,
            poseidon_table,
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
        let base_conf = &self.base_conf;
        let push_data_left_is_zero_chip =
            IsZeroChip::construct(base_conf.push_data_left_is_zero.clone());

        // Subtract the unusable rows from the size
        assert!(size > base_conf.minimum_rows);
        let last_row_offset = size - base_conf.minimum_rows + 1;

        trace!(
            "size: {}, minimum_rows: {}, last_row_offset:{}",
            size,
            base_conf.minimum_rows,
            last_row_offset
        );

        let empty_hash = challenges
            .evm_word()
            .map(|challenge| rlc::value(EMPTY_HASH_LE.as_ref(), challenge));

        layouter.assign_region(
            || "assign bytecode with poseidon hash extension",
            |mut region| {
                let mut offset = 0;
                let mut row_input = F::zero();
                for bytecode in witness.iter() {
                    let bytecode_offset_begin = offset;
                    base_conf.assign_bytecode(
                        &mut region,
                        bytecode,
                        challenges,
                        &push_data_left_is_zero_chip,
                        empty_hash,
                        &mut offset,
                        last_row_offset,
                        fail_fast,
                    )?;

                    for (idx, row) in bytecode.rows.iter().enumerate() {
                        // if the base_conf's assignment not fail fast,
                        // we also avoid the failure of "NotEnoughRowsAvailable"
                        // in prover creation (so bytecode_incomplete test could pass)
                        let offset = bytecode_offset_begin + idx;
                        if offset <= last_row_offset {
                            row_input = self.assign_extended_row(
                                &mut region,
                                offset,
                                row,
                                row_input,
                                bytecode.bytes.len(),
                            )?;
                        }
                    }
                }

                // Padding
                for idx in offset..=last_row_offset {
                    base_conf.set_padding_row(
                        &mut region,
                        &push_data_left_is_zero_chip,
                        empty_hash,
                        idx,
                        last_row_offset,
                    )?;
                    self.set_header_row(&mut region, 0, idx)?;
                }
                Ok(())
            },
        )
    }

    /// Assign a header row (at padding or start line of each bytecodes)
    fn set_header_row(
        &self,
        region: &mut Region<F>,
        code_length: usize,
        offset: usize,
    ) -> Result<(), Error> {
        for (name, column) in [
            ("control length header", self.control_length),
            ("field input header", self.field_input),
            ("bytes in field header", self.bytes_in_field_index),
            ("bytes in field inv header", self.bytes_in_field_inv),
            ("field border header", self.is_field_border),
            ("padding shift header", self.padding_shift),
            ("field index header", self.field_index),
            ("field index inv header", self.field_index_inv),
        ] {
            region.assign_advice(
                || format!("assign {name} {offset}"),
                column,
                offset,
                || Value::known(F::zero()),
            )?;
        }

        for (name, column, val) in [
            (
                "control length header",
                self.control_length,
                F::from(code_length as u64),
            ),
            (
                "padding shift header",
                self.padding_shift,
                F::from(256 as u64).pow_vartime([BYTES_IN_FIELD as u64]),
            ),
            ("field index header", self.field_index, F::one()),
        ] {
            region.assign_advice(
                || format!("assign {name} {offset}"),
                column,
                offset,
                || Value::known(val),
            )?;
        }

        Ok(())
    }

    /// Assign a row, all of the value is determinded by current bytes progress
    /// and the hash width
    fn assign_extended_row(
        &self,
        region: &mut Region<F>,
        offset: usize,
        row: &BytecodeRow<F>,
        input_prev: F,
        code_length: usize,
    ) -> Result<F, Error> {
        let code_index = row.index.get_lower_128() as usize;
        let tag = row.tag.get_lower_32();
        let row_input = match tag {
            i if i == BytecodeFieldTag::Byte as u32 => {
                let block_size = BYTES_IN_FIELD * PoseidonTable::INPUT_WIDTH;

                let prog_block = code_index / block_size;
                let control_length = code_length - prog_block * block_size;
                let bytes_in_field_index = (code_index + 1) % BYTES_IN_FIELD;
                let field_border = bytes_in_field_index == 0;
                let bytes_in_field_index = if field_border {
                    BYTES_IN_FIELD
                } else {
                    bytes_in_field_index
                };
                let bytes_in_field_index_inv_f =
                    F::from((BYTES_IN_FIELD - bytes_in_field_index) as u64)
                        .invert()
                        .unwrap_or(F::zero());
                let padding_shift_f = F::from(256 as u64)
                    .pow_vartime([(BYTES_IN_FIELD - bytes_in_field_index) as u64]);
                let input_f = row.value * padding_shift_f + input_prev;
                // relax field_border for code end
                let field_border = field_border || code_index + 1 == code_length;

                let field_index = (code_index % block_size) / BYTES_IN_FIELD + 1;
                let field_index_inv_f = F::from((PoseidonTable::INPUT_WIDTH - field_index) as u64)
                    .invert()
                    .unwrap_or(F::zero());

                trace!(
                    "bytecode_extend.set_row({}): cl:{} inp:{:?} bif:{} br:{} pd:{:x} fi:{}",
                    offset,
                    control_length,
                    input_f,
                    bytes_in_field_index,
                    field_border,
                    padding_shift_f.get_lower_128(),
                    field_index,
                );

                for (tip, column, val) in [
                    (
                        "control length",
                        self.control_length,
                        F::from(control_length as u64),
                    ),
                    ("field input", self.field_input, input_f),
                    (
                        "bytes in field",
                        self.bytes_in_field_index,
                        F::from(bytes_in_field_index as u64),
                    ),
                    (
                        "bytes in field inv",
                        self.bytes_in_field_inv,
                        bytes_in_field_index_inv_f,
                    ),
                    (
                        "field border",
                        self.is_field_border,
                        F::from(field_border as u64),
                    ),
                    ("padding shift", self.padding_shift, padding_shift_f),
                    ("field index", self.field_index, F::from(field_index as u64)),
                    ("field index inv", self.field_index_inv, field_index_inv_f),
                ] {
                    region.assign_advice(
                        || format!("assign {} {}", tip, offset),
                        column,
                        offset,
                        || Value::known(val),
                    )?;
                }

                if field_border {
                    F::zero()
                } else {
                    input_f
                }
            }
            i if i == BytecodeFieldTag::Header as u32 => {
                trace!("bytecode_extend.set_header_row({offset}): cl:{code_length}",);
                self.set_header_row(region, code_length, offset)?;
                F::zero()
            }
            _ => unreachable!("unexpected tag number"),
        };

        Ok(row_input)
    }

    /// re-export load fixed tables
    pub(crate) fn load_aux_tables(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.base_conf.load_aux_tables(layouter)
    }
}

/// Circuit configuration arguments
pub struct ToHashBlockBytecodeCircuitConfigArgs<F: Field> {
    /// arg for base config
    pub base_args: BytecodeCircuitConfigArgs<F>,
    /// BytecodeTable
    pub poseidon_table: PoseidonTable,
}

impl<F: Field> SubCircuitConfig<F> for ToHashBlockCircuitConfig<F, HASHBLOCK_BYTES_IN_FIELD> {
    type ConfigArgs = ToHashBlockBytecodeCircuitConfigArgs<F>;

    /// Return a new BytecodeCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            base_args,
            poseidon_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let base_conf = BytecodeCircuitConfig::new(meta, base_args);
        Self::configure(meta, base_conf, poseidon_table)
    }
}

/// Get unrolled hash inputs as inputs to hash circuit
pub fn unroll_to_hash_input<F: Field, const BYTES_IN_FIELD: usize, const INPUT_LEN: usize>(
    code: impl ExactSizeIterator<Item = u8>,
) -> Vec<[F; INPUT_LEN]> {
    use eth_types::U256;

    let fl_cnt = code.len() / BYTES_IN_FIELD;
    let fl_cnt = if code.len() % BYTES_IN_FIELD != 0 {
        fl_cnt + 1
    } else {
        fl_cnt
    };

    let (msgs, _) = code
        .chain(std::iter::repeat(0))
        .take(fl_cnt * BYTES_IN_FIELD)
        .fold((Vec::new(), Vec::new()), |(mut msgs, mut cache), bt| {
            cache.push(bt);
            if cache.len() == BYTES_IN_FIELD {
                let mut buf: [u8; 64] = [0; 64];
                U256::from_big_endian(&cache).to_little_endian(&mut buf[0..32]);
                msgs.push(F::from_bytes_wide(&buf));
                cache.clear();
            }
            (msgs, cache)
        });

    let input_cnt = msgs.len() / INPUT_LEN;
    let input_cnt = if msgs.len() % INPUT_LEN != 0 {
        input_cnt + 1
    } else {
        input_cnt
    };
    if input_cnt == 0 {
        return Vec::new();
    }

    let (mut inputs, last) = msgs
        .into_iter()
        .chain(std::iter::repeat(F::zero()))
        .take(input_cnt * INPUT_LEN)
        .fold(
            (Vec::new(), [None; INPUT_LEN]),
            |(mut msgs, mut v_arr), f| {
                if let Some(v) = v_arr.iter_mut().find(|v| v.is_none()) {
                    v.replace(f);
                    (msgs, v_arr)
                } else {
                    msgs.push(v_arr.map(|v| v.unwrap()));
                    let mut v_arr = [None; INPUT_LEN];
                    v_arr[0].replace(f);
                    (msgs, v_arr)
                }
            },
        );

    inputs.push(last.map(|v| v.unwrap()));
    inputs
}

/// test module
#[cfg(any(feature = "test", test))]
#[cfg(test)]
pub mod tests {
    use super::*;
    //use super::super::tests::get_randomness;
    //use crate::{bytecode_circuit::dev::test_bytecode_circuit_unrolled,
    // util::DEFAULT_RAND}; use eth_types::Bytecode;
    use halo2_proofs::halo2curves::bn256::Fr;

    #[test]
    fn bytecode_unrolling_to_input() {
        let bt = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let out = unroll_to_hash_input::<Fr, 4, 2>(bt.iter().copied().take(6));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][0], Fr::from(0x01020304));
        assert_eq!(out[0][1], Fr::from(0x05060000));

        let out = unroll_to_hash_input::<Fr, 3, 2>(bt.iter().copied().take(9));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][0], Fr::from(0x010203));
        assert_eq!(out[0][1], Fr::from(0x040506));
        assert_eq!(out[1][0], Fr::from(0x070809));
        assert_eq!(out[1][1], Fr::zero());

        let out = unroll_to_hash_input::<Fr, 3, 2>(bt.iter().copied().take(12));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][0], Fr::from(0x010203));
        assert_eq!(out[0][1], Fr::from(0x040506));
        assert_eq!(out[1][0], Fr::from(0x070809));
        assert_eq!(out[1][1], Fr::from(0x0A0B0C));

        let out = unroll_to_hash_input::<Fr, 3, 3>(bt.iter().copied().take(12));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][0], Fr::from(0x010203));
        assert_eq!(out[0][1], Fr::from(0x040506));
        assert_eq!(out[0][2], Fr::from(0x070809));
        assert_eq!(out[1][0], Fr::from(0x0A0B0C));
        assert_eq!(out[1][1], Fr::zero());
        assert_eq!(out[1][2], Fr::zero());

        let out = unroll_to_hash_input::<Fr, 3, 3>(bt.iter().copied().take(14));
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][0], Fr::from(0x010203));
        assert_eq!(out[0][1], Fr::from(0x040506));
        assert_eq!(out[0][2], Fr::from(0x070809));
        assert_eq!(out[1][0], Fr::from(0x0A0B0C));
        assert_eq!(out[1][1], Fr::from(0x0D0E00));
        assert_eq!(out[1][2], Fr::zero());
    }
}
