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
                        (self.block_index, F::one()),
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
                    || Value::known(F::from(2)),
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
    /// the maximum rotation is prev(2), next(1)
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
                        s_back_ref_phase.expr(),
                        1.expr(),
                    );
                },
            );

            let is_padding_next =
                1.expr() - s_lit_cp_phase_next.expr() - s_back_ref_phase_next.expr();
            cb.condition(is_padding.expr(), |cb| {
                cb.require_equal(
                    "padding never change once activated",
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
                        "phase can only be activated in inst border",
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
                        "phase must keep activated until block end",
                        s_last_lit_cp_phase_prev.expr(),
                        s_last_lit_cp_phase.expr(),
                    );
                },
            );

            cb.condition(s_last_lit_cp_phase.expr(), |cb| {
                cb.require_equal(
                    "lit cp must activated if last lit cp is activated",
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
    pub fn mock_assign(
        &self,
        layouter: &mut impl Layouter<F>,
        chng: Value<F>,
        n_seq: usize,
        seq_exec_infos: &[SequenceExec],
        literals: &[u8],
        // all of the decompressed bytes, not only current block
        decompressed_bytes: &[u8],
        enabled_rows: usize,
    ) -> Result<(), Error> {
        let literals = literals
            .iter()
            .copied()
            .map(|b| b as u64)
            .collect::<Vec<_>>();

        layouter.assign_region(
            || "output region",
            |mut region| {
                let offset = self.init_top_row(&mut region, None)?;
                let (offset, decoded_len, decoded_rlc) = self.assign_block(
                    &mut region,
                    chng,
                    offset,
                    0,
                    Value::known(F::zero()),
                    &SequenceInfo {
                        block_idx: 1,
                        num_sequences: n_seq,
                        ..Default::default()
                    },
                    seq_exec_infos.iter(),
                    &literals,
                    decompressed_bytes,
                )?;
                self.paddings(
                    &mut region,
                    offset,
                    enabled_rows,
                    decoded_len,
                    decoded_rlc,
                    2,
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner, dev::MockProver, halo2curves::bn256::Fr, plonk::Circuit,
    };
    use witgen::AddressTableRow;
    use zkevm_circuits::util::MockChallenges;

    #[derive(Clone, Debug)]
    struct SeqExecMock {
        outputs: Vec<u8>,
        literals: Vec<u8>,
        seq_conf: SequenceInfo,
        insts: Vec<AddressTableRow>,
        exec_trace: Vec<SequenceExec>,
    }

    impl SeqExecMock {
        // use the code in witgen to generate exec trace
        pub fn mock_generate(literals: Vec<u8>, insts: Vec<AddressTableRow>) -> Self {
            let seq_conf = SequenceInfo {
                block_idx: 1,
                num_sequences: insts.len(),
                ..Default::default()
            };

            let mut exec_trace = Vec::new();
            let mut outputs = Vec::new();

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
                outputs,
                literals,
                seq_conf,
                insts,
                exec_trace,
            }
        }
    }

    #[derive(Clone)]
    struct SeqExecMockConfig {
        config: SeqExecConfig<Fr>,
        inst_tbl: SeqInstTable<Fr>,
        literal_tbl: LiteralTable,
        seq_cfg: SequenceConfig,
        chng_mock: MockChallenges,
    }

    impl Circuit<Fr> for SeqExecMock {
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

            let chng_mock = MockChallenges::construct_p1(meta);
            let chng = chng_mock.exprs(meta);

            let config = SeqExecConfig::configure(
                meta,
                chng.keccak_input(),
                &literal_tbl,
                &inst_tbl,
                &seq_cfg,
            );

            Self::Config {
                config,
                literal_tbl,
                inst_tbl,
                seq_cfg,
                chng_mock,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            config.literal_tbl.mock_assign(
                &mut layouter,
                self.literals
                    .iter()
                    .copied()
                    .map(|b| b as u64)
                    .collect::<Vec<_>>()
                    .as_slice(),
            )?;

            config.seq_cfg.mock_assign(&mut layouter, &self.seq_conf)?;

            config
                .inst_tbl
                .mock_assign(&mut layouter, &self.insts, 15)?;

            let chng_val = config.chng_mock.values(&layouter);

            config.config.mock_assign(
                &mut layouter,
                chng_val.keccak_input(),
                self.insts.len(),
                &self.exec_trace,
                &self.literals,
                &self.outputs,
                50,
            )?;

            Ok(())
        }
    }

    #[test]
    fn seq_exec_literal_only() {
        // no instructions, we only copy literals to output
        let circuit = SeqExecMock::mock_generate(Vec::from("abcd".as_bytes()), Vec::new());

        assert_eq!(circuit.outputs, Vec::from("abcd".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }

    #[test]
    fn seq_exec_simple() {
        // no instructions, we only copy literals to output
        let circuit = SeqExecMock::mock_generate(
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [3, 0, 4, 5, 6, 1],
            ]),
        );

        assert_eq!(circuit.outputs, Vec::from("abcddeabcdeabf".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }

    #[test]
    fn seq_exec_rle_like() {
        // no instructions, we only copy literals to output
        let circuit = SeqExecMock::mock_generate(
            Vec::from("abcdef".as_bytes()),
            AddressTableRow::mock_samples_full([
                [1, 4, 1, 1, 4, 8],
                [9, 1, 3, 6, 1, 4],
                [5, 0, 6, 2, 6, 1], // an RLE like inst, match len exceed match offset
            ]),
        );

        assert_eq!(circuit.outputs, Vec::from("abcddeabcbcbcbcf".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }

    #[test]
    fn seq_exec_no_tail_cp() {
        // no instructions, we only copy literals to output
        let circuit = SeqExecMock::mock_generate(
            Vec::from("abcde".as_bytes()),
            AddressTableRow::mock_samples_full([[1, 4, 1, 1, 4, 8], [9, 1, 3, 6, 1, 4]]),
        );

        assert_eq!(circuit.outputs, Vec::from("abcddeabc".as_bytes()));

        let k = 12;
        let mock_prover =
            MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();
    }
}
