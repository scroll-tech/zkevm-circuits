use gadgets::util::{and, not, select, Expr};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{
        Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, VirtualCells,
    },
    poly::Rotation,
};
use itertools::Itertools;
use tables::SeqInstTable;
use witgen::{SequenceExec, SequenceExecInfo, SequenceInfo, ZstdTag};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    util::Field,
};

use super::tables;
use crate::aggregation::{decoder::witgen, util::BooleanAdvice};

/// TODO: This is in fact part of the `BlockConfig` in
/// Decoder, we can use BlockConfig if it is decoupled
/// from Decoder module later

#[derive(Clone)]
pub struct SequenceConfig {
    // the enabled flag
    q_enabled: Column<Fixed>,
    // the `is_block` flag in `BlockConfig`
    flag: Column<Advice>,
    // the index of block which the literal section is in
    block_index: Column<Advice>,
    // Number of sequences decoded from the sequences section header in the block.
    num_sequences: Column<Advice>,
}

impl SequenceConfig {
    #[cfg(test)]
    pub fn mock_assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        seq_cfg: &SequenceInfo,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "seq cfg mock",
            |mut region| {
                let mut offset = 0usize;

                for col in [self.flag, self.block_index, self.num_sequences] {
                    region.assign_advice(
                        || "flush for non lookup",
                        col,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }

                offset += 1;
                for (col, val) in [
                    (self.flag, F::one()),
                    (self.block_index, F::from(seq_cfg.block_idx as u64)),
                    (self.num_sequences, F::from(seq_cfg.num_sequences as u64)),
                ] {
                    region.assign_advice(
                        || "flush mock table",
                        col,
                        offset,
                        || Value::known(val),
                    )?;
                }
                region.assign_fixed(
                    || "enable mock table",
                    self.q_enabled,
                    offset,
                    || Value::known(F::one()),
                )?;
                Ok(())
            },
        )
    }

    /// construct table for rows: [enabled, blk_index, num_seq]
    pub fn construct(cols: [Column<Any>; 4]) -> Self {
        Self {
            q_enabled: cols[0].try_into().unwrap(),
            flag: cols[1].try_into().unwrap(),
            block_index: cols[2].try_into().unwrap(),
            num_sequences: cols[3].try_into().unwrap(),
        }
    }

    /// export the exps for literal copying lookup: [tag, blk_ind, byte_ind, char, padding]
    pub fn lookup_tbl<F: Field>(&self, meta: &mut VirtualCells<'_, F>) -> [Expression<F>; 4] {
        [
            meta.query_fixed(self.q_enabled, Rotation::cur()),
            meta.query_advice(self.flag, Rotation::cur()),
            meta.query_advice(self.block_index, Rotation::cur()),
            meta.query_advice(self.num_sequences, Rotation::cur()),
        ]
    }
}

/// The literal table which execution circuit expect to lookup from
#[derive(Clone)]
pub struct LiteralTable {
    // the enabled flag
    q_enabled: Column<Fixed>,
    // the tag for current row in literal section
    tag: Column<Advice>,
    // the index of block which the literal section is in
    block_index: Column<Advice>,
    // the 1-indexed byte of byte of literal section's raw bytes
    byte_index: Column<Advice>,
    // the corresponding char of current index
    char: Column<Advice>,
    // the flag IN NEXT ROW is set to 1 indicate it is
    // the last byte in current section
    last_flag: Column<Advice>,
    // the flag should be 0 for a valid lookup row
    padding_flag: Column<Advice>,
}

impl LiteralTable {
    #[cfg(test)]
    pub fn mock_assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        block_id: u64,
        literals: &[u64],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "literal tbl mock",
            |mut region| {
                let mut offset = 0usize;

                for col in [
                    self.tag,
                    self.block_index,
                    self.byte_index,
                    self.char,
                    self.last_flag,
                    self.padding_flag,
                ] {
                    region.assign_advice(
                        || "flush for non lookup",
                        col,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;
                // TODO: ensure the index in literal table is 0 or 1 indexed
                for (i, char) in literals.iter().copied().enumerate() {
                    region.assign_fixed(
                        || "enable mock table",
                        self.q_enabled,
                        offset,
                        || Value::known(F::one()),
                    )?;
                    for (col, val) in [
                        (self.tag, F::from(ZstdTag::ZstdBlockLiteralsRawBytes as u64)),
                        (self.block_index, F::from(block_id)),
                        (self.byte_index, F::from(i as u64 + 1)),
                        (self.char, F::from(char)),
                        (self.last_flag, F::zero()),
                        (self.padding_flag, F::zero()),
                    ] {
                        region.assign_advice(
                            || "flush mock table",
                            col,
                            offset,
                            || Value::known(val),
                        )?;
                    }
                    offset += 1;
                }

                for col in [self.byte_index, self.char, self.padding_flag] {
                    region.assign_advice(
                        || "flush dummy row for border",
                        col,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                region.assign_advice(
                    || "set dummy border",
                    self.tag,
                    offset,
                    || Value::known(F::from(ZstdTag::ZstdBlockLiteralsRawBytes as u64)),
                )?;
                region.assign_advice(
                    || "set dummy border",
                    self.block_index,
                    offset,
                    || Value::known(F::from(block_id + 1)),
                )?;
                region.assign_advice(
                    || "set dummy border",
                    self.last_flag,
                    offset,
                    || Value::known(F::one()),
                )?;

                Ok(())
            },
        )
    }

    /// construct table for rows: [q_enable, tag, blk_index, byte_index, char, last, padding]
    pub fn construct(cols: [Column<Any>; 7]) -> Self {
        Self {
            q_enabled: cols[0].try_into().unwrap(),
            tag: cols[1].try_into().unwrap(),
            block_index: cols[2].try_into().unwrap(),
            byte_index: cols[3].try_into().unwrap(),
            char: cols[4].try_into().unwrap(),
            last_flag: cols[5].try_into().unwrap(),
            padding_flag: cols[6].try_into().unwrap(),
        }
    }

    /// export the exps for literal copying lookup: [tag, blk_ind, byte_ind, char, padding]
    pub fn lookup_tbl_for_lit_cp<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
    ) -> [Expression<F>; 6] {
        [
            meta.query_fixed(self.q_enabled, Rotation::cur()),
            meta.query_advice(self.tag, Rotation::cur()),
            meta.query_advice(self.block_index, Rotation::cur()),
            meta.query_advice(self.byte_index, Rotation::cur()),
            meta.query_advice(self.char, Rotation::cur()),
            meta.query_advice(self.padding_flag, Rotation::cur()),
        ]
    }

    /// export the exps for literal size lookup: [tag, blk_ind, byte_ind, flag, padding]
    pub fn lookup_tbl_for_lit_size<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>,
    ) -> [Expression<F>; 6] {
        [
            meta.query_fixed(self.q_enabled, Rotation::cur()),
            meta.query_advice(self.tag, Rotation::cur()),
            meta.query_advice(self.block_index, Rotation::cur()),
            meta.query_advice(self.byte_index, Rotation::cur()),
            meta.query_advice(self.last_flag, Rotation::next()),
            meta.query_advice(self.padding_flag, Rotation::cur()),
        ]
    }
}

/// SeqExecConfig handling the sequences in each block and output the
/// decompressed bytes
#[derive(Clone, Debug)]
pub struct SeqExecConfig<F: Field> {
    // active flag, one active row parse
    q_enabled: Column<Fixed>,
    // 1-index for each block, keep the same for each row
    // until all sequenced has been handled
    block_index: Column<Advice>,
    // the 1-indexed seq number (1..=n_seq) for each
    // sequence.
    seq_index: Column<Advice>,
    // the decoded length of output byte so it is start
    // from 1 for the first output char
    decoded_len: Column<Advice>,
    // the decoded byte under current index
    decoded_byte: Column<Advice>,
    // the rlc of decoded output byte
    decoded_rlc: Column<Advice>,
    /// An incremental accumulator of the number of bytes decoded so far.
    // decoded_len_acc: Column<Advice>,

    // the flag indicate current seq is the special one
    // (copying the rest bytes in literal section)
    s_last_lit_cp_phase: BooleanAdvice,
    // the flag indicate the execution is under
    // "literal copying" phase
    s_lit_cp_phase: BooleanAdvice,
    // the flag indicate the execution is under
    // back reference phase
    s_back_ref_phase: BooleanAdvice,
    // the copied index in literal section
    literal_pos: Column<Advice>,
    // the back-ref pos
    backref_offset: Column<Advice>,
    // counting the progress of back ref bytes
    backref_progress: Column<Advice>,
    _marker: std::marker::PhantomData<F>,
}

type ExportedCell<F> = AssignedCell<F, F>;

impl<F: Field> SeqExecConfig<F> {
    /// Construct the sequence instruction table
    /// the maxium rotation is prev(2), next(1)
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        challenges: Expression<F>,
        literal_table: &LiteralTable,
        inst_table: &SeqInstTable<F>,
        seq_config: &SequenceConfig,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let block_index = meta.advice_column();
        let seq_index = meta.advice_column();
        let decoded_len = meta.advice_column();
        let decoded_byte = meta.advice_column();
        let decoded_rlc = meta.advice_column_in(SecondPhase);
        let s_last_lit_cp_phase =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enabled, Rotation::cur()));
        let s_lit_cp_phase =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enabled, Rotation::cur()));
        let s_back_ref_phase =
            BooleanAdvice::construct(meta, |meta| meta.query_fixed(q_enabled, Rotation::cur()));
        let backref_offset = meta.advice_column();
        let backref_progress = meta.advice_column();
        let literal_pos = meta.advice_column();

        // need to constraint the final block index so
        // we ensure all blocks has been handled
        meta.enable_equality(block_index);
        // need to export the final rlc and len
        meta.enable_equality(decoded_rlc);
        // the flag indicate current row is the beginning of
        // a new block
        meta.enable_equality(decoded_len);

        // the flag indicate the execution has ended and rows
        // are filled by padding data
        let mut is_inst_begin = 0.expr();
        // the flag exp indicate current row is the beginning
        // of a new instruction, it is also the beginning of
        // a literal copying
        let mut is_block_begin = 0.expr();

        let mut is_padding = 0.expr();

        meta.create_gate("borders", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // boolean constraint that index is increment
            cb.require_boolean("instruction border is boolean", is_inst_begin.expr());

            is_block_begin = meta.query_advice(block_index, Rotation::cur())
                - meta.query_advice(block_index, Rotation::prev());

            cb.require_boolean("block border is boolean", is_block_begin.expr());

            is_inst_begin = select::expr(
                is_block_begin.expr(),
                1.expr(),
                meta.query_advice(seq_index, Rotation::cur())
                    - meta.query_advice(seq_index, Rotation::prev()),
            );

            cb.require_boolean("inst border is boolean", is_inst_begin.expr());

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("phases", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let s_lit_cp_phase_next = s_lit_cp_phase.expr_at(meta, Rotation::next());
            let s_back_ref_phase_next = s_back_ref_phase.expr_at(meta, Rotation::next());
            let s_lit_cp_phase_prev = s_lit_cp_phase.expr_at(meta, Rotation::prev());
            let s_back_ref_phase_prev = s_back_ref_phase.expr_at(meta, Rotation::prev());
            let s_lit_cp_phase = s_lit_cp_phase.expr_at(meta, Rotation::cur());
            let s_back_ref_phase = s_back_ref_phase.expr_at(meta, Rotation::cur());

            is_padding = 1.expr() - s_lit_cp_phase.expr() - s_back_ref_phase.expr();
            // constraint padding is boolean, so cp/back_ref phase is excluded
            // i.e. two phases can not be enabled at the same time
            cb.require_boolean("padding is boolean", is_padding.expr());

            cb.condition(
                and::expr([
                    not::expr(is_inst_begin.expr()),
                    not::expr(s_lit_cp_phase_prev.expr()),
                ]),
                |cb| {
                    cb.require_equal(
                        "inside a inst, cp phase keep 0 once it changed to 0",
                        s_lit_cp_phase.expr(),
                        0.expr(),
                    );
                },
            );

            cb.condition(
                and::expr([
                    not::expr(is_inst_begin.expr()),
                    s_back_ref_phase_prev.expr(),
                ]),
                |cb| {
                    cb.require_equal(
                        "inside a inst, backref phase keep 1 once it changed to 1",
                        s_back_ref_phase_prev.expr(),
                        1.expr(),
                    );
                },
            );

            let is_padding_next =
                1.expr() - s_lit_cp_phase_next.expr() - s_back_ref_phase_next.expr();
            cb.condition(is_padding.expr(), |cb| {
                cb.require_equal(
                    "padding never change once actived",
                    is_padding_next.expr(),
                    is_padding.expr(),
                );
            });

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        debug_assert!(meta.degree() <= 9);
        meta.create_gate("last literal cp phase", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let s_last_lit_cp_phase_prev = s_last_lit_cp_phase.expr_at(meta, Rotation::prev());
            let s_last_lit_cp_phase = s_last_lit_cp_phase.expr_at(meta, Rotation::cur());

            cb.condition(
                and::expr([
                    s_last_lit_cp_phase.expr(),
                    not::expr(s_last_lit_cp_phase_prev.expr()),
                ]),
                |cb| {
                    cb.require_equal(
                        "phase can only be actived in inst border",
                        is_inst_begin.expr(),
                        1.expr(),
                    );
                },
            );

            cb.condition(
                and::expr([
                    s_last_lit_cp_phase_prev.expr(),
                    not::expr(is_block_begin.expr()),
                ]),
                |cb| {
                    cb.require_equal(
                        "phase must keep actived until block end",
                        s_last_lit_cp_phase_prev.expr(),
                        s_last_lit_cp_phase.expr(),
                    );
                },
            );

            cb.condition(s_last_lit_cp_phase.expr(), |cb| {
                cb.require_equal(
                    "lit cp must actived if last lit cp is actived",
                    s_lit_cp_phase.expr_at(meta, Rotation::cur()),
                    1.expr(),
                );
            });

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        debug_assert!(meta.degree() <= 9);
        meta.create_gate("phase pos", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let literal_pos_prev = meta.query_advice(literal_pos, Rotation::prev());
            let literal_pos = meta.query_advice(literal_pos, Rotation::cur());
            let s_lit_cp_phase = s_lit_cp_phase.expr_at(meta, Rotation::cur());

            cb.require_equal(
                "lit cp is increment in one block",
                select::expr(
                    is_block_begin.expr(),
                    // so we start at 1 if first row is lit cp
                    // or 0 if not
                    s_lit_cp_phase.expr(),
                    literal_pos_prev.expr() + s_lit_cp_phase.expr(),
                ),
                literal_pos.expr(),
            );

            let backref_progress_prev = meta.query_advice(backref_progress, Rotation::prev());
            let backref_progress = meta.query_advice(backref_progress, Rotation::cur());

            let s_back_ref_phase = s_back_ref_phase.expr_at(meta, Rotation::cur());

            cb.require_equal(
                "backref progress is increment in one inst",
                select::expr(
                    is_inst_begin.expr(),
                    // so we start at 1 if first row is lit cp
                    // or 0 if not
                    s_back_ref_phase.expr(),
                    backref_progress_prev.expr() + s_back_ref_phase.expr(),
                ),
                backref_progress.expr(),
            );

            let backref_offset_prev = meta.query_advice(backref_offset, Rotation::prev());
            let backref_offset = meta.query_advice(backref_offset, Rotation::cur());

            cb.condition(not::expr(is_inst_begin.expr()), |cb| {
                cb.require_equal(
                    "backref offset kee the same in one inst",
                    backref_offset.expr(),
                    backref_offset_prev.expr(),
                )
            });

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("output and paddings", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            let decoded_len_prev = meta.query_advice(decoded_len, Rotation::prev());
            let decoded_rlc_prev = meta.query_advice(decoded_rlc, Rotation::prev());
            let decoded_len = meta.query_advice(decoded_len, Rotation::cur());
            let decoded_rlc = meta.query_advice(decoded_rlc, Rotation::cur());
            let decoded_byte = meta.query_advice(decoded_byte, Rotation::cur());

            cb.require_equal(
                "decoded len increase 1 in next row until paddings",
                select::expr(
                    is_padding.expr(),
                    decoded_len_prev.expr(),
                    decoded_len_prev.expr() + 1.expr(),
                ),
                decoded_len.expr(),
            );
            cb.condition(is_padding.expr(), |cb| {
                cb.require_zero("while padding, byte is always zero", decoded_byte.expr())
            });

            cb.require_equal(
                "rlc accumulate",
                decoded_rlc_prev.expr()
                    * select::expr(
                        decoded_len.expr() - decoded_len_prev.expr(),
                        challenges,
                        1.expr(),
                    )
                    + decoded_byte.expr(),
                decoded_rlc.expr(),
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        meta.lookup_any("the instruction from inst table", |meta| {
            let q_enabled = meta.query_fixed(q_enabled, Rotation::prev());

            let block_index = meta.query_advice(block_index, Rotation::prev());
            let seq_index = meta.query_advice(seq_index, Rotation::prev());
            let not_last_lit_cp = not::expr(s_last_lit_cp_phase.expr_at(meta, Rotation::prev()));
            let literal_pos_at_inst_end = meta.query_advice(literal_pos, Rotation::prev());
            let backref_offset_at_inst_end = meta.query_advice(backref_offset, Rotation::prev());
            let backref_len_at_inst_end = meta.query_advice(backref_progress, Rotation::prev());

            inst_table
                .instructions()
                .into_iter()
                .zip([
                    block_index,
                    seq_index,
                    backref_offset_at_inst_end,
                    literal_pos_at_inst_end,
                    backref_len_at_inst_end,
                ])
                .map(|(lookup_col, src_expr)| {
                    let lookup_expr = meta.query_advice(lookup_col, Rotation::cur());
                    let src_expr =
                        src_expr * is_inst_begin.expr() * not_last_lit_cp.expr() * q_enabled.expr();
                    assert!(src_expr.degree() <= 5);
                    (src_expr, lookup_expr)
                })
                .collect()
        });

        debug_assert!(meta.degree() <= 9);
        meta.lookup_any("lit cp char", |meta| {
            let enabled = meta.query_fixed(q_enabled, Rotation::cur())
                * s_lit_cp_phase.expr_at(meta, Rotation::cur());

            let block_index = meta.query_advice(block_index, Rotation::cur());
            let literal_pos = meta.query_advice(literal_pos, Rotation::cur());
            let cp_byte = meta.query_advice(decoded_byte, Rotation::cur());

            let tbl_exprs = literal_table.lookup_tbl_for_lit_cp(meta);
            tbl_exprs
                .into_iter()
                .zip_eq([
                    1.expr(),
                    ZstdTag::ZstdBlockLiteralsRawBytes.expr(),
                    block_index,
                    literal_pos,
                    cp_byte,
                    0.expr(),
                ])
                .map(|(lookup_expr, src_expr)| (src_expr * enabled.expr(), lookup_expr))
                .collect()
        });

        debug_assert!(meta.degree() <= 9);
        meta.lookup_any("back ref char", |meta| {
            let enabled = meta.query_fixed(q_enabled, Rotation::cur());

            let backref_pos = meta.query_advice(backref_offset, Rotation::cur());
            let cp_byte = meta.query_advice(decoded_byte, Rotation::cur());
            let decode_pos = meta.query_advice(decoded_len, Rotation::cur());
            let ref_pos = decode_pos.expr() - backref_pos.expr();

            let tbl_exprs = [enabled.expr(), decode_pos.expr(), cp_byte.expr()];
            tbl_exprs
                .into_iter()
                .zip([1.expr(), ref_pos, cp_byte])
                .map(|(lookup_expr, src_expr)| {
                    (
                        src_expr * enabled.expr() * s_back_ref_phase.expr_at(meta, Rotation::cur()),
                        lookup_expr,
                    )
                })
                .collect()
        });

        debug_assert!(meta.degree() <= 9);
        meta.lookup_any("actual literal byte", |meta| {
            let q_enabled = meta.query_fixed(q_enabled, Rotation::prev());
            let block_index = meta.query_advice(block_index, Rotation::prev());
            let literal_pos_at_block_end = meta.query_advice(literal_pos, Rotation::prev());

            let tbl_exprs = literal_table.lookup_tbl_for_lit_size(meta);
            tbl_exprs
                .into_iter()
                .zip_eq([
                    1.expr(),
                    ZstdTag::ZstdBlockLiteralsRawBytes.expr(),
                    block_index,
                    literal_pos_at_block_end,
                    1.expr(),
                    0.expr(),
                ])
                .map(|(lookup_expr, src_expr)| {
                    (
                        src_expr * is_block_begin.expr() * q_enabled.expr(),
                        lookup_expr,
                    )
                })
                .collect()
        });

        debug_assert!(meta.degree() <= 9);
        meta.lookup_any("instruction counts", |meta| {
            let q_enabled = meta.query_fixed(q_enabled, Rotation::prev());
            let block_index = meta.query_advice(block_index, Rotation::prev());
            let seq_index_at_block_end = meta.query_advice(seq_index, Rotation::prev())
                // if we have a additional literal copying phase, we 
                // in fact has one extra instruction
                - s_last_lit_cp_phase.expr_at(meta, Rotation::prev());

            seq_config
                .lookup_tbl(meta)
                .into_iter()
                .zip_eq([1.expr(), 1.expr(), block_index, seq_index_at_block_end])
                .map(|(lookup_expr, src_expr)| {
                    (
                        src_expr * is_block_begin.expr() * q_enabled.expr(),
                        lookup_expr,
                    )
                })
                .collect()
        });

        debug_assert!(meta.degree() <= 9);
        Self {
            q_enabled,
            block_index,
            seq_index,
            decoded_len,
            decoded_byte,
            decoded_rlc,
            s_last_lit_cp_phase,
            s_lit_cp_phase,
            s_back_ref_phase,
            backref_progress,
            literal_pos,
            backref_offset,
            _marker: Default::default(),
        }
    }

    /// fill the rest region with padding rows
    pub fn paddings(
        &self,
        region: &mut Region<F>,
        offset: usize,
        till_offset: usize,
        decoded_len: usize,
        decoded_rlc: Value<F>,
        padded_block_ind: u64,
    ) -> Result<(ExportedCell<F>, ExportedCell<F>), Error> {
        for offset in offset..=till_offset {
            // flush one more row for rotation next()
            if offset != till_offset {
                region.assign_fixed(
                    || "enable padding row",
                    self.q_enabled,
                    offset,
                    || Value::known(F::one()),
                )?;
            }

            for (col, val) in [
                (self.block_index, Value::known(F::from(padded_block_ind))),
                (self.decoded_len, Value::known(F::from(decoded_len as u64))),
                (self.decoded_rlc, decoded_rlc),
            ] {
                region.assign_advice(|| "set padding rows", col, offset, || val)?;
            }

            for col in [
                self.decoded_byte,
                self.s_last_lit_cp_phase.column,
                self.s_lit_cp_phase.column,
                self.s_back_ref_phase.column,
                self.backref_offset,
                self.backref_progress,
                self.literal_pos,
                self.seq_index,
            ] {
                region.assign_advice(
                    || "flush padding rows",
                    col,
                    offset,
                    || Value::known(F::zero()),
                )?;
            }
        }

        let len_export = region.assign_advice(
            || "export len",
            self.decoded_len,
            till_offset,
            || Value::known(F::from(decoded_len as u64)),
        )?;

        let rlc_export = region.assign_advice(
            || "export rlc",
            self.decoded_rlc,
            till_offset,
            || decoded_rlc,
        )?;

        Ok((len_export, rlc_export))
    }

    /// assign a single block from current offset / byte decompression
    /// progress and return the offset / progress below the last used row
    #[allow(clippy::too_many_arguments)]
    pub fn assign_block<'a>(
        &self,
        region: &mut Region<F>,
        chng: Value<F>,
        mut offset: usize,
        mut decoded_len: usize,
        mut decoded_rlc: Value<F>,
        seq_info: &SequenceInfo,
        seq_exec_infos: impl Iterator<Item = &'a SequenceExec>,
        literals: &[u64],
        // all of the decompressed bytes, not only current block
        decompressed_bytes: &[u8],
    ) -> Result<(usize, usize, Value<F>), Error> {
        let block_ind = seq_info.block_idx;
        let mut cur_literal_cp = 0usize;
        let mut inst_begin_offset = offset;
        let mut cur_inst: Option<usize> = None;

        for SequenceExec(inst_ind, exec_info) in seq_exec_infos {
            let inst_ind = *inst_ind + 1;
            if let Some(old_ind) = cur_inst.replace(inst_ind) {
                if old_ind != inst_ind {
                    inst_begin_offset = offset;
                }
            }

            let base_rows = [
                (self.block_index, F::from(block_ind as u64)),
                (self.seq_index, F::from(inst_ind as u64)),
                (
                    self.s_last_lit_cp_phase.column,
                    if inst_ind > seq_info.num_sequences {
                        F::one()
                    } else {
                        F::zero()
                    },
                ),
            ];

            let (is_literal, r) = match exec_info {
                SequenceExecInfo::LiteralCopy(r) => {
                    assert_eq!(cur_literal_cp, r.start);
                    cur_literal_cp = r.end;
                    (true, r.clone())
                }
                SequenceExecInfo::BackRef(r) => (false, r.clone()),
            };

            for (i, pos) in r.clone().enumerate() {
                decoded_len += 1;
                let out_byte = F::from(if is_literal {
                    literals[pos]
                } else {
                    decompressed_bytes[pos] as u64
                });
                decoded_rlc = decoded_rlc * chng + Value::known(out_byte);

                region.assign_advice(
                    || "set output region",
                    self.decoded_rlc,
                    offset,
                    || decoded_rlc,
                )?;

                // all of the "pos" is 1-index for lookup since the
                // bytes_output is 1-indexed
                let pos = pos + 1;
                let ref_offset = if is_literal {
                    None
                } else {
                    Some(decoded_len - pos)
                };
                // for back-ref part, we refill the backref_pos in the whole
                // instruction
                if !is_literal && i == 0 {
                    //println!("fill-back match offset {} in {}..{}", ref_offset.unwrap(),
                    // inst_begin_offset, offset);
                    for back_offset in inst_begin_offset..offset {
                        region.assign_advice(
                            || "set output region",
                            self.backref_offset,
                            back_offset,
                            || Value::known(F::from(ref_offset.expect("backref set") as u64)),
                        )?;
                    }
                }

                let decodes = [
                    (self.decoded_len, F::from(decoded_len as u64)),
                    (self.decoded_byte, out_byte),
                    (
                        self.backref_offset,
                        F::from(ref_offset.unwrap_or_default() as u64),
                    ),
                ];

                for (col, val) in base_rows.into_iter().chain(decodes).chain(if is_literal {
                    [
                        (self.s_lit_cp_phase.column, F::one()),
                        (self.s_back_ref_phase.column, F::zero()),
                        (self.literal_pos, F::from(pos as u64)),
                        (self.backref_progress, F::zero()),
                    ]
                } else {
                    [
                        (self.s_lit_cp_phase.column, F::zero()),
                        (self.s_back_ref_phase.column, F::one()),
                        (self.literal_pos, F::from(cur_literal_cp as u64)),
                        (self.backref_progress, F::from(i as u64 + 1)),
                    ]
                }) {
                    region.assign_advice(
                        || "set output region",
                        col,
                        offset,
                        || Value::known(val),
                    )?;
                }

                region.assign_fixed(
                    || "enable row",
                    self.q_enabled,
                    offset,
                    || Value::known(F::one()),
                )?;
                offset += 1;
            }
        }

        debug_assert_eq!(cur_literal_cp, literals.len());

        Ok((offset, decoded_len, decoded_rlc))
    }

    /// assign the top row
    pub fn init_top_row(
        &self,
        region: &mut Region<F>,
        from_offset: Option<usize>,
    ) -> Result<usize, Error> {
        let offset = from_offset.unwrap_or_default();

        for col in [
            self.decoded_byte,
            self.decoded_len,
            self.decoded_rlc,
            self.block_index,
            self.seq_index,
            self.s_back_ref_phase.column,
            self.s_lit_cp_phase.column,
            self.backref_offset,
            self.literal_pos,
            self.backref_progress,
        ] {
            region.assign_advice(|| "top row fluash", col, offset, || Value::known(F::zero()))?;
        }

        for (col, val) in [
            (self.decoded_len, F::zero()),
            (self.decoded_rlc, F::zero()),
            (self.block_index, F::zero()),
        ] {
            region.assign_advice_from_constant(|| "top row constraint", col, offset, val)?;
        }

        region.assign_advice_from_constant(
            || "blk index begin constraint",
            self.block_index,
            offset + 1,
            F::one(),
        )?;

        Ok(offset + 1)
    }

    /// assign with multiple blocks and export the cell at
    /// final row (specified by `eanbled_rows`) for
    /// (decoded_len, decoded_rlc)
    pub fn assign<'a>(
        &self,
        layouter: &mut impl Layouter<F>,
        chng: Value<F>,
        // per-block inputs: (literal, seq_info, seq_exec_trace)
        per_blk_inputs: impl IntoIterator<Item = (&'a [u64], &'a SequenceInfo, &'a [SequenceExec])>
            + Clone,
        // all of the decompressed bytes, not only current block
        decompressed_bytes: &[u8],
        enabled_rows: usize,
    ) -> Result<(ExportedCell<F>, ExportedCell<F>), Error> {
        layouter.assign_region(
            || "output region",
            |mut region| {
                let mut offset = self.init_top_row(&mut region, None)?;
                let mut decoded_len = 0usize;
                let mut decoded_rlc = Value::known(F::zero());
                let mut blk_ind = 0;
                for (literals, seq_info, exec_trace) in per_blk_inputs.clone() {
                    blk_ind = seq_info.block_idx;
                    (offset, decoded_len, decoded_rlc) = self.assign_block(
                        &mut region,
                        chng,
                        offset,
                        decoded_len,
                        decoded_rlc,
                        seq_info,
                        exec_trace.iter(),
                        literals,
                        decompressed_bytes,
                    )?;
                }

                self.paddings(
                    &mut region,
                    offset,
                    enabled_rows,
                    decoded_len,
                    decoded_rlc,
                    blk_ind as u64 + 1,
                )
            },
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn mock_assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        index_mock: [Option<F>; 2],    //block_ind, seq_ind
        decode_mock: [Option<F>; 2],   //decode_le, decode_byte,
        phase_mock: [Option<bool>; 3], //last_phase, cp_phase, backref_phase
        pos_mock: [Option<F>; 3],      //literal, offset, ref_len
    ) -> Result<(), Error> {
        for (mock_val, col) in index_mock
            .into_iter()
            .zip([self.block_index, self.seq_index])
        {
            if let Some(val) = mock_val {
                region.assign_advice(|| "mock index", col, offset, || Value::known(val))?;
            }
        }

        for (mock_val, col) in decode_mock
            .into_iter()
            .zip([self.decoded_len, self.decoded_byte])
        {
            if let Some(val) = mock_val {
                region.assign_advice(|| "mock decode", col, offset, || Value::known(val))?;
            }
        }
        if let Some(val) = decode_mock[1] {
            region.assign_advice(
                || "mock decode rlc",
                self.decoded_rlc,
                offset,
                || Value::known(val),
            )?;
        }

        for (mock_val, col) in
            pos_mock
                .into_iter()
                .zip([self.literal_pos, self.backref_offset, self.backref_progress])
        {
            if let Some(val) = mock_val {
                region.assign_advice(|| "mock position", col, offset, || Value::known(val))?;
            }
        }

        for (mock_val, bool_adv) in phase_mock.into_iter().zip([
            self.s_last_lit_cp_phase,
            self.s_lit_cp_phase,
            self.s_back_ref_phase,
        ]) {
            if let Some(val) = mock_val {
                let val = Value::known(if val { F::one() } else { F::zero() });
                region.assign_advice(|| "phase mock", bool_adv.column, offset, || val)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };
    use witgen::AddressTableRow;

    #[allow(dead_code)]
    #[derive(Clone, Copy, Debug)]
    enum MockEntry {
        Index([Option<Fr>; 2]),
        Decode([Option<Fr>; 2]),
        Phase([Option<bool>; 3]),
        Position([Option<Fr>; 3]),
    }

    #[derive(Clone, Debug, Default)]
    struct SeqExecMock {
        literals: Vec<u8>,
        seq_conf: SequenceInfo,
        insts: Vec<AddressTableRow>,
        exec_trace: Vec<SequenceExec>,
        mocks: Vec<(usize, MockEntry)>,
        literal_mocks: Option<Vec<u8>>,
    }

    impl SeqExecMock {
        // use the code in witgen to generate exec trace
        pub fn mock_generate(
            block_idx: usize,
            literals: Vec<u8>,
            insts: Vec<AddressTableRow>,
            outputs: &mut Vec<u8>,
        ) -> Self {
            let seq_conf = SequenceInfo {
                block_idx,
                num_sequences: insts.len(),
                ..Default::default()
            };

            let mut exec_trace = Vec::new();

            let mut current_literal_pos: usize = 0;
            for inst in &insts {
                let new_literal_pos = current_literal_pos + (inst.literal_length as usize);
                if new_literal_pos > current_literal_pos {
                    let r = current_literal_pos..new_literal_pos;
                    exec_trace.push(SequenceExec(
                        inst.instruction_idx as usize,
                        SequenceExecInfo::LiteralCopy(r.clone()),
                    ));
                    outputs.extend_from_slice(&literals[r]);
                }

                let match_pos = outputs.len() - (inst.actual_offset as usize);
                if inst.match_length > 0 {
                    let r = match_pos..(inst.match_length as usize + match_pos);
                    exec_trace.push(SequenceExec(
                        inst.instruction_idx as usize,
                        SequenceExecInfo::BackRef(r.clone()),
                    ));
                    for ref_pos in r {
                        outputs.push(outputs[ref_pos]);
                    }
                }
                current_literal_pos = new_literal_pos;
            }

            // Add remaining literal bytes
            if current_literal_pos < literals.len() {
                let r = current_literal_pos..literals.len();
                exec_trace.push(SequenceExec(
                    seq_conf.num_sequences,
                    SequenceExecInfo::LiteralCopy(r.clone()),
                ));
                outputs.extend_from_slice(&literals[r]);
            }

            Self {
                literals,
                seq_conf,
                insts,
                exec_trace,
                ..Default::default()
            }
        }
    }

    #[derive(Clone)]
    struct SeqExecMockConfig {
        config: SeqExecConfig<Fr>,
        inst_tbl: SeqInstTable<Fr>,
        literal_tbl: LiteralTable,
        seq_cfg: SequenceConfig,
        //chng_mock: MockChallenges,
    }

    #[derive(Clone, Default)]
    struct SeqExecMockCircuit {
        traces: Vec<SeqExecMock>,
        padding_mocks: Vec<(usize, MockEntry)>,
        all_padding_mocks: Vec<MockEntry>,
        output: Vec<u8>,
    }

    impl Circuit<Fr> for SeqExecMockCircuit {
        type Config = SeqExecMockConfig;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            let const_col = meta.fixed_column();
            meta.enable_constant(const_col);

            let literal_tbl = LiteralTable::construct([
                meta.fixed_column().into(),
                meta.advice_column().into(),
                meta.advice_column().into(),
                meta.advice_column().into(),
                meta.advice_column().into(),
                meta.advice_column().into(),
                meta.advice_column().into(),
            ]);

            let seq_cfg = SequenceConfig::construct([
                meta.fixed_column().into(),
                meta.advice_column().into(),
                meta.advice_column().into(),
                meta.advice_column().into(),
            ]);

            let inst_tbl = SeqInstTable::configure(meta);

            let chng = 0.expr();

            let config = SeqExecConfig::configure(meta, chng, &literal_tbl, &inst_tbl, &seq_cfg);

            Self::Config {
                config,
                literal_tbl,
                inst_tbl,
                seq_cfg,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            for blk_trace in &self.traces {
                config
                    .seq_cfg
                    .mock_assign(&mut layouter, &blk_trace.seq_conf)?;

                let literals = blk_trace
                    .literal_mocks
                    .as_ref()
                    .unwrap_or(&blk_trace.literals);

                config.literal_tbl.mock_assign(
                    &mut layouter,
                    blk_trace.seq_conf.block_idx as u64,
                    literals
                        .iter()
                        .copied()
                        .map(|b| b as u64)
                        .collect::<Vec<_>>()
                        .as_slice(),
                )?;
            }

            let chng_val = Value::known(Fr::zero());
            let assigned_rows = layouter.assign_region(
                || "mock exec output region",
                |mut region| {
                    let config = &config.config;

                    let mut offset = config.init_top_row(&mut region, None)?;

                    let mut decoded_len = 0usize;
                    let mut decoded_rlc = Value::known(Fr::zero());
                    let mut blk_ind = 0;

                    let fill_mock_row =
                        |region: &mut Region<Fr>, offset: usize, entry: &MockEntry| match entry {
                            MockEntry::Decode(mock) => config.mock_assign(
                                region,
                                offset,
                                [None, None],
                                *mock,
                                [None, None, None],
                                [None, None, None],
                            ),
                            MockEntry::Index(mock) => config.mock_assign(
                                region,
                                offset,
                                *mock,
                                [None, None],
                                [None, None, None],
                                [None, None, None],
                            ),
                            MockEntry::Phase(mock) => config.mock_assign(
                                region,
                                offset,
                                [None, None],
                                [None, None],
                                *mock,
                                [None, None, None],
                            ),
                            MockEntry::Position(mock) => config.mock_assign(
                                region,
                                offset,
                                [None, None],
                                [None, None],
                                [None, None, None],
                                *mock,
                            ),
                        };

                    for tr in &self.traces {
                        let literals = tr
                            .literals
                            .iter()
                            .copied()
                            .map(|b| b as u64)
                            .collect::<Vec<_>>();
                        let seq_info = &tr.seq_conf;
                        let exec_trace = &tr.exec_trace;
                        blk_ind = seq_info.block_idx;
                        let begin_offset = offset;
                        (offset, decoded_len, decoded_rlc) = config.assign_block(
                            &mut region,
                            chng_val,
                            offset,
                            decoded_len,
                            decoded_rlc,
                            seq_info,
                            exec_trace.iter(),
                            &literals,
                            &self.output,
                        )?;

                        for (mock_offset, entry) in &tr.mocks {
                            assert!(mock_offset + begin_offset < offset);
                            fill_mock_row(&mut region, begin_offset + mock_offset, entry)?;
                        }
                    }

                    let end_offset = offset + 10;
                    config.paddings(
                        &mut region,
                        offset,
                        end_offset,
                        decoded_len,
                        decoded_rlc,
                        blk_ind as u64 + 1,
                    )?;
                    for (offset, entry) in (offset..end_offset)
                        .flat_map(|i| self.all_padding_mocks.iter().map(move |entry| (i, entry)))
                    {
                        fill_mock_row(&mut region, offset, entry)?;
                    }

                    for (mock_offset, entry) in &self.padding_mocks {
                        fill_mock_row(&mut region, offset + mock_offset, entry)?;
                    }

                    Ok(end_offset)
                },
            )?;

            config.inst_tbl.assign(
                &mut layouter,
                self.traces.iter().map(|tr| tr.insts.iter()),
                assigned_rows,
            )?;

            Ok(())
        }
    }

    #[test]
    fn seq_exec_literal_only() {
        // no instructions, we only copy literals to output
        let mut output = Vec::new();
        let traces = vec![SeqExecMock::mock_generate(
            1,
            Vec::from("abcd".as_bytes()),
            Vec::new(),
            &mut output,
        )];

        let circuit = SeqExecMockCircuit {
            traces,
            output,
            ..Default::default()
        };

        assert_eq!(circuit.output, Vec::from("abcd".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }

    #[test]
    fn seq_exec_simple() {
        let mut output = Vec::new();
        let traces = vec![SeqExecMock::mock_generate(
            1,
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [3, 0, 4, 5, 6, 1],
            ]),
            &mut output,
        )];
        let circuit = SeqExecMockCircuit {
            traces,
            output,
            ..Default::default()
        };

        assert_eq!(circuit.output, Vec::from("abcddeabcdeabf".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }

    // #[test]
    // fn seq_exec_no_literal() {
    //
    //     let mut output = Vec::new();
    //     let traces = vec![
    //         SeqExecMock::mock_generate(
    //             1,
    //             Vec::from("abcdef".as_bytes()),
    //             AddressTableRow::mock_samples_full([
    //                 [1, 4, 1, 1, 4, 8],
    //                 [9, 1, 3, 6, 1, 4],
    //                 [3, 0, 4, 5, 6, 1],
    //             ]),
    //             &mut output,
    //         ),
    //         SeqExecMock::mock_generate(
    //             2,
    //             Vec::new(),
    //             AddressTableRow::mock_samples_full([
    //                 [17, 0, 3, 14, 5, 6],
    //                 [7, 0, 2, 4, 14, 5],
    //             ]),
    //             &mut output,
    //         )
    //     ];
    //     let circuit = SeqExecMockCircuit {traces, output};

    //     assert_eq!(circuit.output, Vec::from("abcddeabcdeabfabcfa".as_bytes()));

    //     let k = 12;
    //     let mock_prover =
    //         MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
    //     mock_prover.verify().unwrap();
    // }

    #[test]
    fn seq_exec_common() {
        let mut output = Vec::new();
        let traces = vec![
            SeqExecMock::mock_generate(
                1,
                Vec::from("abcdef".as_bytes()),
                AddressTableRow::mock_samples_full([
                    [1, 4, 1, 1, 4, 8],
                    [9, 1, 3, 6, 1, 4],
                    [3, 0, 4, 5, 6, 1],
                ]),
                &mut output,
            ),
            SeqExecMock::mock_generate(
                2,
                Vec::from("g".as_bytes()),
                AddressTableRow::mock_samples_full([[17, 0, 3, 14, 5, 6], [8, 1, 2, 5, 14, 5]]),
                &mut output,
            ),
        ];
        let circuit = SeqExecMockCircuit {
            traces,
            output,
            ..Default::default()
        };

        assert_eq!(circuit.output, Vec::from("abcddeabcdeabfabcgfa".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }

    #[test]
    fn seq_exec_rle_like() {
        let mut output = Vec::new();
        let traces = vec![SeqExecMock::mock_generate(
            1,
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [5, 0, 6, 2, 6, 1], // an RLE like inst, match len exceed match offset
            ]),
            &mut output,
        )];
        let circuit = SeqExecMockCircuit {
            traces,
            output,
            ..Default::default()
        };

        assert_eq!(circuit.output, Vec::from("abcddeabcbcbcbcf".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }

    #[test]
    fn seq_exec_no_tail_cp() {
        let mut output = Vec::new();
        let traces = vec![SeqExecMock::mock_generate(
            1,
            Vec::from("abcde".as_bytes()),
            AddressTableRow::mock_samples_full([[1, 4, 1, 1, 4, 8], [9, 1, 3, 6, 1, 4]]),
            &mut output,
        )];
        let circuit = SeqExecMockCircuit {
            traces,
            output,
            ..Default::default()
        };

        assert_eq!(circuit.output, Vec::from("abcddeabc".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }

    #[test]
    fn seq_exec_neg_literal_unmatch() {
        let mut output = Vec::new();
        let base_trace_blk1 = SeqExecMock::mock_generate(
            1,
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [3, 0, 4, 5, 6, 1],
            ]),
            &mut output,
        );
        let base_trace_blk2 = SeqExecMock::mock_generate(
            2,
            Vec::from("g".as_bytes()),
            AddressTableRow::mock_samples_full([[17, 0, 3, 14, 5, 6], [8, 1, 2, 5, 14, 5]]),
            &mut output,
        );

        assert_eq!(output, Vec::from("abcddeabcdeabfabcgfa".as_bytes()));

        let mut literal_unmatch_blk = base_trace_blk1.clone();
        literal_unmatch_blk.literal_mocks = Some(Vec::from("abcdefg".as_bytes()));
        let lit_unmatch_circuit_1 = SeqExecMockCircuit {
            traces: vec![literal_unmatch_blk, base_trace_blk2.clone()],
            output: output.clone(),
            ..Default::default()
        };
        let mut literal_unmatch_blk = base_trace_blk1.clone();
        literal_unmatch_blk.literal_mocks = Some(Vec::from("abddef".as_bytes()));
        let lit_unmatch_circuit_2 = SeqExecMockCircuit {
            traces: vec![literal_unmatch_blk, base_trace_blk2.clone()],
            output: output.clone(),
            ..Default::default()
        };
        let mut literal_unmatch_blk1 = base_trace_blk1.clone();
        literal_unmatch_blk1.literal_mocks = Some(Vec::from("abcde".as_bytes()));
        let mut literal_unmatch_blk2 = base_trace_blk2.clone();
        literal_unmatch_blk2.literal_mocks = Some(Vec::from("fg".as_bytes()));
        let lit_unmatch_circuit_3 = SeqExecMockCircuit {
            traces: vec![literal_unmatch_blk1, literal_unmatch_blk2],
            output: output.clone(),
            ..Default::default()
        };

        let k = 12;
        for circuit in [
            lit_unmatch_circuit_1,
            lit_unmatch_circuit_2,
            lit_unmatch_circuit_3,
        ] {
            let mock_prover =
                MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
            let ret = mock_prover.verify();
            println!("{:?}", ret);
            assert!(ret.is_err());
        }
    }

    #[test]
    fn seq_exec_neg_phases() {
        let mut output = Vec::new();
        let base_trace_blk1 = SeqExecMock::mock_generate(
            1,
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [3, 0, 4, 5, 6, 1],
                [4, 0, 1, 1, 5, 6],
            ]),
            &mut output,
        );
        let base_trace_blk2 = SeqExecMock::mock_generate(
            2,
            Vec::from("gg".as_bytes()),
            AddressTableRow::mock_samples_full([[4, 2, 2, 1, 1, 5]]),
            &mut output,
        );

        assert_eq!(output, Vec::from("abcddeabcdeabbfgggg".as_bytes()));

        // try to put the final phase into previous one
        let mut mis_phase_blk1 = base_trace_blk1.clone();
        assert_eq!(mis_phase_blk1.exec_trace.len(), 7);
        assert_eq!(mis_phase_blk1.exec_trace[6].0, 4);
        assert_eq!(mis_phase_blk1.exec_trace[5].0, 3);
        mis_phase_blk1.exec_trace[6].0 = 3;
        mis_phase_blk1.mocks = vec![
            (14, MockEntry::Index([None, Some(Fr::from(3u64))])),
            (14, MockEntry::Phase([Some(false), None, None])),
        ];

        let circuit_mis_phase_1 = SeqExecMockCircuit {
            traces: vec![mis_phase_blk1, base_trace_blk2.clone()],
            output: output.clone(),
            ..Default::default()
        };

        // try to make last cp phase cross instruction
        let mut mis_phase_blk2 = base_trace_blk1.clone();
        mis_phase_blk2.mocks = vec![(13, MockEntry::Phase([Some(true), None, None]))];
        let circuit_mis_phase_2 = SeqExecMockCircuit {
            traces: vec![mis_phase_blk2, base_trace_blk2.clone()],
            output: output.clone(),
            ..Default::default()
        };

        // try to a phase both lit-cp and backref
        let mut mis_phase_blk3 = base_trace_blk1.clone();
        mis_phase_blk3.mocks = vec![(13, MockEntry::Phase([Some(false), Some(true), Some(true)]))];
        let circuit_mis_phase_3 = SeqExecMockCircuit {
            traces: vec![mis_phase_blk3, base_trace_blk2.clone()],
            output: output.clone(),
            ..Default::default()
        };

        // detect phase must work in a normal row
        let mut mis_phase_blk4 = base_trace_blk2.clone();
        mis_phase_blk4.mocks = vec![
            (3, MockEntry::Phase([Some(false), Some(false), Some(false)])),
            (3, MockEntry::Decode([Some(Fr::from(18)), Some(Fr::zero())])),
        ];
        let circuit_mis_phase_4 = SeqExecMockCircuit {
            traces: vec![base_trace_blk1.clone(), mis_phase_blk4],
            output: Vec::from("abcddeabcdeabbfggg".as_bytes()),
            all_padding_mocks: vec![MockEntry::Decode([Some(Fr::from(18)), None])],
            ..Default::default()
        };

        // detect out of order phases
        let mut mis_phase_blk5 = base_trace_blk2.clone();
        mis_phase_blk5.mocks = vec![
            (0, MockEntry::Decode([None, Some(Fr::from(0x66))])), //the decoded byte become 'f'
            (
                0,
                MockEntry::Position([Some(Fr::zero()), None, Some(Fr::one())]),
            ),
            (
                1,
                MockEntry::Position([Some(Fr::one()), None, Some(Fr::one())]),
            ),
            (
                2,
                MockEntry::Position([Some(Fr::from(2)), None, Some(Fr::one())]),
            ),
            (0, MockEntry::Phase([None, Some(false), Some(true)])),
            (2, MockEntry::Phase([None, Some(true), Some(false)])),
        ];
        let circuit_mis_phase_5 = SeqExecMockCircuit {
            traces: vec![base_trace_blk1.clone(), mis_phase_blk5],
            output: output.clone(),
            ..Default::default()
        };

        let k = 12;
        for circuit in [
            circuit_mis_phase_1,
            circuit_mis_phase_2,
            circuit_mis_phase_3,
            circuit_mis_phase_4,
            circuit_mis_phase_5,
        ] {
            let mock_prover =
                MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
            let ret = mock_prover.verify();
            println!("{:?}", ret);
            assert!(ret.is_err());
        }
    }

    #[test]
    fn seq_exec_neg_insts() {
        let mut output = Vec::new();
        let base_trace_blk = SeqExecMock::mock_generate(
            1,
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [3, 0, 4, 5, 6, 1],
                [4, 0, 1, 1, 5, 6],
            ]),
            &mut output,
        );

        assert_eq!(output, Vec::from("abcddeabcdeabbf".as_bytes()));

        let mut output_mis = Vec::new();
        SeqExecMock::mock_generate(
            1,
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [3, 0, 4, 5, 6, 1],
                [4, 0, 2, 1, 5, 6],
            ]),
            &mut output_mis,
        );

        assert_eq!(output_mis, Vec::from("abcddeabcdeabbbf".as_bytes()));

        let mut mis_inst_blk = base_trace_blk.clone();
        let tr = &mut mis_inst_blk.exec_trace[5].1;
        assert_eq!(*tr, SequenceExecInfo::BackRef(12..13));
        // build the mis-match len to 2
        *tr = SequenceExecInfo::BackRef(12..14);

        let circuit_mis_inst_1 = SeqExecMockCircuit {
            traces: vec![mis_inst_blk],
            output: output_mis,
            ..Default::default()
        };
        let mut mis_inst_blk = base_trace_blk.clone();
        let tr = &mut mis_inst_blk.exec_trace[5].1;
        // build the mis-match offset to 2
        *tr = SequenceExecInfo::BackRef(11..12);
        let circuit_mis_inst_2 = SeqExecMockCircuit {
            traces: vec![mis_inst_blk],
            output: Vec::from("abcddeabcdeabaf".as_bytes()),
            ..Default::default()
        };

        let k = 12;
        for circuit in [circuit_mis_inst_1, circuit_mis_inst_2] {
            let mock_prover =
                MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
            let ret = mock_prover.verify();
            println!("{:?}", ret);
            assert!(ret.is_err());
        }
    }

    #[test]
    fn seq_exec_neg_paddings() {
        let mut output = Vec::new();
        let base_trace_blk = SeqExecMock::mock_generate(
            1,
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [3, 0, 4, 5, 6, 1],
                [4, 0, 1, 1, 5, 6],
            ]),
            &mut output,
        );

        assert_eq!(output, Vec::from("abcddeabcdeabbf".as_bytes()));

        let circuit_ref = SeqExecMockCircuit {
            traces: vec![base_trace_blk.clone()],
            output: output.clone(),
            padding_mocks: vec![
                (0, MockEntry::Decode([Some(Fr::from(15)), None])),
                (1, MockEntry::Index([Some(Fr::from(2)), Some(Fr::zero())])),
            ],
            ..Default::default()
        };

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit_ref, vec![]).expect("failed to run mock prover");
        assert!(mock_prover.verify().is_ok());

        let circuit_mal_block_index = SeqExecMockCircuit {
            traces: vec![base_trace_blk.clone()],
            output: output.clone(),
            padding_mocks: vec![(4, MockEntry::Index([Some(Fr::from(3)), None]))],
            ..Default::default()
        };
        let circuit_mal_decode_len = SeqExecMockCircuit {
            traces: vec![base_trace_blk.clone()],
            output: output.clone(),
            padding_mocks: vec![(4, MockEntry::Decode([Some(Fr::from(16)), None]))],
            ..Default::default()
        };
        let circuit_mal_inst = SeqExecMockCircuit {
            traces: vec![base_trace_blk.clone()],
            output: output.clone(),
            padding_mocks: vec![
                (0, MockEntry::Index([Some(Fr::from(1)), Some(Fr::from(5))])),
                (0, MockEntry::Phase([Some(true), Some(true), None])),
            ],
            ..Default::default()
        };

        for circuit in [
            circuit_mal_block_index,
            circuit_mal_decode_len,
            circuit_mal_inst,
        ] {
            let mock_prover =
                MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
            let ret = mock_prover.verify();
            println!("{:?}", ret);
            assert!(ret.is_err());
        }
    }
}
