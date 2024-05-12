
use eth_types::Field;
use gadgets::{
    is_equal::*,
    is_zero::*,
    util::{and, or, not, select, Expr},
};
use halo2_proofs::{
    circuit::{Value, Region, Layouter},
    plonk::{Advice, Any, Column, ConstraintSystem, VirtualCells, Error, Expression, Fixed, SecondPhase},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon}, 
    table::LookupTable,
    util::Challenges,
};
use crate::aggregation::decoder::witgen;
use witgen::{ZstdTag, SequenceInfo, SequenceExec, SequenceExecInfo};
use super::tables;
use tables::SeqInstTable;

/// TODO: This is in fact part of the `BlockConfig` in
/// Decoder, we can use BlockConfig if it is decoupled 
/// from Decoder module later

#[derive(Clone)] 
pub struct SequenceConfig {
    // the `is_block` flag in `BlockConfig`
    enabled: Column<Advice>,
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
    ) -> Result<(), Error>{

        layouter.assign_region(||"seq cfg mock", 
            |mut region|{
                let mut offset = 0usize;

                for col in [self.enabled, self.block_index, self.num_sequences]{
                    region.assign_advice(||"flush for non lookup", col, offset, ||Value::known(F::zero()))?;
                }

                offset += 1;
                for (col, val) in [
                    (self.enabled, F::one()),
                    (self.block_index, F::from(seq_cfg.block_idx as u64)),
                    (self.num_sequences, F::from(seq_cfg.num_sequences as u64)),
                ]{
                    region.assign_advice(||"flush mock table", col, offset, ||Value::known(val))?;
                }

                Ok(())
            }
        )
    }

    /// construct table for rows: [enabled, blk_index, num_seq]
    pub fn construct(cols: [Column<Advice>;3]) -> Self {
        Self {
            enabled: cols[0],
            block_index: cols[1],
            num_sequences: cols[2],
        }
    }

    /// export the exps for literal copying lookup: [tag, blk_ind, byte_ind, char, padding]
    pub fn lookup_tbl<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>
    ) -> [Expression<F>; 3]{
        [
            meta.query_advice(self.enabled, Rotation::cur()),
            meta.query_advice(self.block_index, Rotation::cur()),   
            meta.query_advice(self.num_sequences, Rotation::cur()),     
        ]
    }
}

/// The literal table which execution circuit expect to lookup from
#[derive(Clone)]
pub struct LiteralTable {
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
    ) -> Result<(), Error>{

        layouter.assign_region(||"literal tbl mock", 
            |mut region|{
                let mut offset = 0usize;

                for col in [self.tag, self.block_index, self.byte_index, self.char, self.last_flag, self.padding_flag]{
                    region.assign_advice(||"flush for non lookup", col, offset, ||Value::known(F::zero()))?;
                }
                offset += 1;
                // TODO: ensure the index in literal table is 0 or 1 indexed
                for (i, char) in literals.iter().copied().enumerate() {
                    for (col, val) in [
                        (self.tag, F::from(ZstdTag::ZstdBlockLiteralsRawBytes as u64)),
                        (self.block_index, F::one()),
                        (self.byte_index, F::from(i as u64 +1)),
                        (self.char, F::from(char)),
                        (self.last_flag, F::zero()),
                        (self.padding_flag, F::zero()),
                    ]{
                        region.assign_advice(||"flush mock table", col, offset, ||Value::known(val))?;
                    }
                    offset += 1;
                }

                for col in [self.byte_index, self.char, self.padding_flag]{
                    region.assign_advice(||"flush dummy row for border", col, offset, ||Value::known(F::zero()))?;
                }
                region.assign_advice(||"set dummy border", self.tag, offset, ||Value::known(F::from(ZstdTag::ZstdBlockLiteralsRawBytes as u64)))?;
                region.assign_advice(||"set dummy border", self.block_index, offset, ||Value::known(F::from(2 as u64)))?;
                region.assign_advice(||"set dummy border", self.last_flag, offset, ||Value::known(F::one()))?;

                Ok(())
            }
        )
    }

    /// construct table for rows: [tag, blk_index, byte_index, char, last, padding]
    pub fn construct(cols: [Column<Advice>;6]) -> Self {
        Self {
            tag: cols[0],
            block_index: cols[1],
            byte_index: cols[2],
            char: cols[3],
            last_flag: cols[4],
            padding_flag: cols[5],
        }
    }

    /// export the exps for literal copying lookup: [tag, blk_ind, byte_ind, char, padding]
    pub fn lookup_tbl_for_lit_cp<F: Field>(
        &self,
        meta: &mut VirtualCells<'_, F>
    ) -> [Expression<F>; 5]{
        [
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
        meta: &mut VirtualCells<'_, F>
    ) -> [Expression<F>; 5]{
        [
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
    // indicate the row above active region
    q_head: Column<Fixed>,       
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
    decoded_len_acc: Column<Advice>,

    // the flag indicate current seq is the special one 
    // (copying the rest bytes in literal section)
    s_last_lit_cp_phase: Column<Advice>,
    // the flag indicate the execution is under
    // "literal copying" phase
    s_lit_cp_phase: Column<Advice>,
    // the flag indicate the execution is under
    // back reference phase
    s_back_ref_phase: Column<Advice>,
    // the copied index in literal section 
    literal_pos: Column<Advice>,
    // the back-ref pos 
    backref_pos: Column<Advice>,
    // counting the progress of back ref bytes
    backref_progress: Column<Advice>,    

    // the flag indicate the execution has ended and rows
    // are filled by padding data
    is_padding: Expression<F>,
    // the flag exp indicate current row is the beginning 
    // of a new instruction, it is also the beginning of
    // a literal copying 
    is_inst_begin: Expression<F>,
    // the flag indicate current row is the beginning of
    // a new block
    is_block_begin: Expression<F>,
}


impl<F: Field> SeqExecConfig<F> {

    /// Construct the sequence instruction table
    /// the maxium rotation is prev(2), next(1)
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        challenges: &Challenges<Expression<F>>,
        literal_table: &LiteralTable,
        inst_table: &SeqInstTable<F>,
        seq_config: &SequenceConfig,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let q_head = meta.fixed_column();
        let block_index = meta.advice_column();
        let seq_index = meta.advice_column();
        let decoded_len = meta.advice_column();
        let decoded_byte = meta.advice_column();
        let decoded_rlc = meta.advice_column_in(SecondPhase);
        // TODO: constraint the len acc
        let decoded_len_acc = meta.advice_column();
        let s_last_lit_cp_phase = meta.advice_column();
        let s_lit_cp_phase = meta.advice_column();
        let s_back_ref_phase = meta.advice_column();
        let backref_progress = meta.advice_column();
        let literal_pos = meta.advice_column();
        let backref_pos = meta.advice_column();

        // need to constraint the final block index so
        // we ensure all blocks has been handled
        meta.enable_equality(block_index);

        // dummy init
        let mut is_inst_begin = 0.expr();
        let mut is_block_begin = 0.expr();
        let mut is_padding = 0.expr();

        meta.create_gate("borders", |meta|{
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

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::cur())
            )
        });

        debug_assert!(meta.degree() <= 9);

        meta.create_gate("phases", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let s_lit_cp_phase_next = meta.query_advice(s_lit_cp_phase, Rotation::next());
            let s_back_ref_phase_next = meta.query_advice(s_back_ref_phase, Rotation::next());
            let s_lit_cp_phase_prev = meta.query_advice(s_lit_cp_phase, Rotation::prev());
            let s_back_ref_phase_prev = meta.query_advice(s_back_ref_phase, Rotation::prev());
            let s_lit_cp_phase = meta.query_advice(s_lit_cp_phase, Rotation::cur());
            let s_back_ref_phase = meta.query_advice(s_back_ref_phase, Rotation::cur());

            cb.require_boolean("phase is boolean", s_lit_cp_phase.expr());
            cb.require_boolean("phase is boolean", s_back_ref_phase.expr());

            is_padding = 1.expr() - s_lit_cp_phase.expr() - s_back_ref_phase.expr();
            // constraint padding is boolean, so cp/back_ref phase is excluded
            // i.e. two phases can not be enabled at the same time
            cb.require_boolean("padding is boolean", is_padding.expr());

            cb.condition(and::expr([
                    not::expr(is_inst_begin.expr()),
                    not::expr(s_lit_cp_phase_prev.expr()),
                ]),
                |cb|{
                    cb.require_equal("inside a inst, cp phase keep 0 once it changed to 0", 
                        s_lit_cp_phase.expr(),
                        0.expr(),
                );
            });

            cb.condition(and::expr([
                not::expr(is_inst_begin.expr()),
                s_back_ref_phase_prev.expr(),
            ]),
            |cb|{
                cb.require_equal("inside a inst, backref phase keep 1 once it changed to 1", 
                    s_back_ref_phase_prev.expr(),
                    1.expr(),
                );
            });

            let is_padding_next = 1.expr() - s_lit_cp_phase_next.expr() - s_back_ref_phase_next.expr();
            cb.condition(is_padding.expr(), |cb|{
                cb.require_equal("padding never change once actived", 
                    is_padding_next.expr(), 
                    is_padding.expr(),
                );
            });

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::cur())
            )
        });

        debug_assert!(meta.degree() <= 9);
        meta.create_gate("last literal cp phase", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let s_last_lit_cp_phase_prev = meta.query_advice(s_last_lit_cp_phase, Rotation::prev());
            let s_last_lit_cp_phase = meta.query_advice(s_last_lit_cp_phase, Rotation::cur());
            cb.require_boolean("last lit_cp phase is boolean", s_last_lit_cp_phase.expr());

            cb.condition(and::expr([
                s_last_lit_cp_phase.expr(),
                not::expr(s_last_lit_cp_phase_prev.expr()),
            ]), |cb|{
                cb.require_equal("phase can only be actived in inst border", 
                    is_inst_begin.expr(),
                    1.expr(),
                );
            });

            cb.condition(and::expr([
                s_last_lit_cp_phase_prev.expr(),
                not::expr(is_block_begin.expr()),
            ]), |cb|{
                cb.require_equal("phase must keep actived until block end", 
                    s_last_lit_cp_phase_prev.expr(),
                    s_last_lit_cp_phase.expr(),
                );
            });

            cb.condition(s_last_lit_cp_phase.expr(), |cb|{
                cb.require_equal("lit cp must actived if last lit cp is actived", 
                    meta.query_advice(s_lit_cp_phase, Rotation::cur()), 
                    1.expr(),
                );
            });

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::cur())
            )
        });

        debug_assert!(meta.degree() <= 9);
        meta.create_gate("lit cp phase pos", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let literal_pos_prev = meta.query_advice(literal_pos, Rotation::prev());
            let literal_pos = meta.query_advice(literal_pos, Rotation::cur());

            let s_lit_cp_phase = meta.query_advice(s_lit_cp_phase, Rotation::cur());

            let in_block_prog = select::expr(
                s_lit_cp_phase.expr(),
                literal_pos_prev.expr() + 1.expr(),
                literal_pos_prev.expr(),
            );
            cb.require_equal("lit cp is increment in one block", 
                select::expr(
                    is_block_begin.expr(),
                    // so we start at 1 if first row is lit cp
                    // or 0 if not
                    s_lit_cp_phase.expr(),
                    in_block_prog.expr(),
                ), 
                literal_pos.expr(),
            );

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::cur())
            )
        });

        debug_assert!(meta.degree() <= 9);
        meta.create_gate("backref phase pos", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let backref_progress_prev = meta.query_advice(backref_progress, Rotation::prev());
            let backref_progress = meta.query_advice(backref_progress, Rotation::cur());

            let s_back_ref_phase = meta.query_advice(s_back_ref_phase, Rotation::cur());

            let back_ref_prog = select::expr(
                s_back_ref_phase.expr(),
                backref_progress_prev.expr() + 1.expr(),
                backref_progress_prev.expr(),
            );
                        
            cb.require_equal("backref progress is increment in one inst", 
                select::expr(
                    is_inst_begin.expr(),
                    // so we start at 1 if first row is lit cp
                    // or 0 if not
                    s_back_ref_phase.expr(),
                    back_ref_prog.expr(),
                ), 
                backref_progress.expr(),
            );

            let backref_pos_prev = meta.query_advice(backref_pos, Rotation::prev());
            let backref_pos = meta.query_advice(backref_pos, Rotation::cur());

            cb.condition(
                not::expr(is_inst_begin.expr()), |cb|{
                    cb.require_equal("backref position keep the same in one instruction", 
                        backref_pos_prev.expr(), 
                        backref_pos.expr(),
                    );
                }
            );

            cb.require_equal("backref progress keep the same in back ref phase", 
                select::expr(
                    is_inst_begin.expr(),
                    // so we start at 1 if first row is lit cp
                    // or 0 if not
                    s_back_ref_phase.expr(),
                    back_ref_prog.expr(),
                ), 
                backref_pos.expr(),
            );

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::cur())
            )
        });        

        debug_assert!(meta.degree() <= 9);
        meta.create_gate("output and paddings", |meta|{
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
            cb.condition(
                is_padding.expr(),
                |cb|cb.require_zero(
                    "while padding, byte is always zero", 
                    decoded_byte.expr(),
                ),
            );

            cb.require_equal("rlc accumulate", 
                decoded_rlc_prev.expr() * 
                (decoded_len.expr() - decoded_len_prev.expr())
                * challenges.evm_word() + decoded_byte.expr(), 
                decoded_rlc.expr(),
            );

            cb.gate(meta.query_fixed(q_head, Rotation::cur()))
        });

        debug_assert!(meta.degree() <= 9);
        // meta.create_gate("header", |meta|{
        //     let mut cb = BaseConstraintBuilder::default();

        //     cb.gate(meta.query_fixed(q_head, Rotation::cur()))
        // });

        meta.lookup_any("the instruction from inst table", |meta|{

            let q_enabled = meta.query_fixed(q_enabled, Rotation::prev());

            let block_index = meta.query_advice(block_index, Rotation::prev());
            let seq_index = meta.query_advice(seq_index, Rotation::prev());
            let not_last_lit_cp = not::expr(meta.query_advice(s_last_lit_cp_phase, Rotation::prev()));
            let literal_pos_at_inst_end = meta.query_advice(literal_pos, Rotation::prev());
            let backref_pos_at_inst_end = meta.query_advice(backref_pos, Rotation::prev());
            let backref_len_at_inst_end = meta.query_advice(backref_progress, Rotation::prev());

            inst_table.instructions().into_iter().zip(
                [
                    block_index,
                    seq_index,
                    backref_pos_at_inst_end,
                    literal_pos_at_inst_end,
                    backref_len_at_inst_end
                ]
            ).map(|(lookup_col, src_expr)|{
                let lookup_expr = meta.query_advice(lookup_col, Rotation::cur());
                let src_expr = src_expr 
                * is_inst_begin.expr()
                * not_last_lit_cp.expr()
                * q_enabled.expr();
                assert!(src_expr.degree() <= 5);
                (src_expr, lookup_expr)
            }).collect()
        });

        debug_assert!(meta.degree() <= 9);
        meta.lookup_any("lit cp char", |meta|{
            let enabled = meta.query_fixed(q_enabled, Rotation::cur())
                * meta.query_advice(s_lit_cp_phase, Rotation::cur());

            let block_index = meta.query_advice(block_index, Rotation::cur());
            let literal_pos = meta.query_advice(literal_pos, Rotation::cur());
            let cp_byte = meta.query_advice(decoded_byte, Rotation::cur());

            let tbl_exprs = literal_table.lookup_tbl_for_lit_cp(meta);
            tbl_exprs.into_iter().zip(
                [
                    ZstdTag::ZstdBlockLiteralsRawBytes.expr(),
                    block_index,
                    literal_pos,
                    cp_byte,
                    0.expr(),                    
                ]
            ).map(|(lookup_expr, src_expr)|{
                (src_expr * enabled.expr(), lookup_expr)
            }).collect()
        });

        debug_assert!(meta.degree() <= 9);
        meta.lookup_any("back ref char", |meta|{
            let enabled = meta.query_fixed(q_enabled, Rotation::cur())
                * meta.query_advice(s_back_ref_phase, Rotation::cur());

            let block_index = meta.query_advice(block_index, Rotation::cur());
            let backref_pos = meta.query_advice(backref_pos, Rotation::cur());
            let cp_byte = meta.query_advice(decoded_byte, Rotation::cur());
            let decode_pos = meta.query_advice(decoded_len, Rotation::cur());
            let ref_pos = decode_pos.expr() - backref_pos.expr();

            let tbl_exprs = [
                block_index.expr(),
                decode_pos.expr(),
                cp_byte.expr(),
            ];
            tbl_exprs.into_iter().zip(
                [
                    block_index,
                    ref_pos,
                    cp_byte,                 
                ]
            ).map(|(lookup_expr, src_expr)|{
                (src_expr * enabled.expr(), lookup_expr)
            }).collect()
        });

        debug_assert!(meta.degree() <= 9);
        meta.lookup_any("actual literal byte", |meta|{
            let q_enabled = meta.query_fixed(q_enabled, Rotation::prev());
            let block_index = meta.query_advice(block_index, Rotation::prev());
            let literal_pos_at_block_end = meta.query_advice(literal_pos, Rotation::prev());

            let tbl_exprs = literal_table.lookup_tbl_for_lit_size(meta);
            tbl_exprs.into_iter().zip(
                [
                    ZstdTag::ZstdBlockLiteralsRawBytes.expr(),
                    block_index,
                    literal_pos_at_block_end,
                    1.expr(),
                    0.expr(),
                ]
            ).map(|(lookup_expr, src_expr)|{
                (src_expr * is_block_begin.expr() * q_enabled.expr(), lookup_expr)
            }).collect()
        });

        debug_assert!(meta.degree() <= 9);
        meta.lookup_any("instruction counts", |meta|{
            let q_enabled = meta.query_fixed(q_enabled, Rotation::prev());
            let block_index = meta.query_advice(block_index, Rotation::prev());
            let seq_index_at_block_end = 
                meta.query_advice(seq_index, Rotation::prev())
                // if we have a additional literal copying phase, we 
                // in fact has one extra instruction
                - meta.query_advice(s_last_lit_cp_phase, Rotation::prev());

            seq_config.lookup_tbl(meta).into_iter().zip(
                [
                    1.expr(),
                    block_index,
                    seq_index_at_block_end,
                ]
            ).map(|(lookup_expr, src_expr)|{
                (src_expr * is_block_begin.expr() * q_enabled.expr(), lookup_expr)
            }).collect()
        });
        
        debug_assert!(meta.degree() <= 9);
        Self {
            q_enabled,
            q_head,
            block_index,
            seq_index,
            decoded_len,
            decoded_byte,
            decoded_rlc,
            decoded_len_acc,
            s_last_lit_cp_phase,
            s_lit_cp_phase,
            s_back_ref_phase,
            backref_progress,
            literal_pos,
            backref_pos,
            is_padding,
            is_inst_begin,
            is_block_begin,
        }
    }

    /// fill the rest region with padding rows
    pub fn paddings<'a>(
        &self,
        region: &mut Region<F>,        
        offset: usize,
        till_offset: usize,
        decoded_len: usize,
        decoded_rlc: Value<F>,
        padded_block_ind: u64,
    ) -> Result<(), Error>{

        for offset in offset..=till_offset {
            // flush one more row for rotation next()
            if offset != till_offset {
                region.assign_fixed(
                    ||"enable padding row",
                    self.q_enabled, 
                    offset, 
                    ||Value::known(F::one())
                )?;
            }

            for (col, val) in [
                (self.block_index, Value::known(F::from(padded_block_ind))),
                (self.decoded_len, Value::known(F::from(decoded_len as u64))),
                (self.decoded_rlc, decoded_rlc),
            ]{
                region.assign_advice(||"set padding rows", 
                    col, 
                    offset,
                    ||val,
                )?;
            }


            for col in [
                self.decoded_byte,
                self.s_last_lit_cp_phase,
                self.s_lit_cp_phase,
                self.s_back_ref_phase,
                self.backref_pos,
                self.backref_progress,
                self.literal_pos,
                self.seq_index,
            ] {
                region.assign_advice(||"flush padding rows", 
                    col, 
                    offset,
                    ||Value::known(F::zero()),
                )?;
            }
        }

        Ok(())

    }

    /// assign a single block from current offset / byte decompression
    /// progress and return the offset / progress below the last used row
    pub fn assign_block<'a>(
        &self,
        region: &mut Region<F>,
        chng: Value<F>,
        mut offset: usize,
        mut decoded_len: usize,
        mut decoded_rlc: Value<F>,
        seq_info: &SequenceInfo,
        seq_exec_infos: impl Iterator<Item=&'a SequenceExec>,
        literals: &[u64],
        // all of the decompressed bytes, not only current block
        decompressed_bytes: &[u8],
    ) -> Result<(usize, usize, Value<F>), Error>{

        let block_ind = seq_info.block_idx;
        let mut cur_literal_cp = 0usize;
        let last_exec = SequenceExec(seq_info.num_sequences+1, SequenceExecInfo::LastLiteralCopy);

        for SequenceExec(inst_ind, exec_info) in seq_exec_infos
            .map(|v|v) // a trick to handle the lifetime issue
            .chain(std::iter::once(&last_exec)) {

            let base_rows = [
                (self.block_index, F::from(block_ind as u64)),
                (self.seq_index, F::from(*inst_ind as u64)),
                (
                    self.s_last_lit_cp_phase, 
                    if *inst_ind > seq_info.num_sequences { 
                        F::one()
                    }else {
                        F::zero()
                    },
                ),
            ];

            let (is_literal, r) = match exec_info {
                SequenceExecInfo::LiteralCopy(r) => {
                    assert_eq!(cur_literal_cp, r.start);
                    cur_literal_cp = r.end;
                    (true, r.clone())
                },
                SequenceExecInfo::BackRef(r) => (false, r.clone()),
                SequenceExecInfo::LastLiteralCopy => 
                    (true, cur_literal_cp..literals.len()),
            };

            for (i, pos) in r.clone().enumerate() {
                decoded_len += 1;   
                let out_byte = F::from(
                    if is_literal {
                        literals[pos as usize]
                    } else {
                        decompressed_bytes[pos as usize] as u64
                    }
                );
                decoded_rlc = decoded_rlc * chng + Value::known(out_byte);

                println!("set row at {}, output {}:{:x}", offset, decoded_len, out_byte.get_lower_32());

                region.assign_advice(
                    ||"set output region", 
                    self.decoded_rlc, offset,
                    ||decoded_rlc,
                )?;

                let decodes = [
                    (
                        self.decoded_len,
                        F::from(decoded_len as u64),

                    ),
                    (
                        self.decoded_byte, 
                        out_byte,
                    ),
                ];

                for (col, val) in base_rows.clone()
                    .into_iter()
                    .chain(decodes)
                    .chain(
                        if is_literal {
                            println!("literal cp {}-{}-{}", pos+1, 0, 0);
                            [
                                (self.s_lit_cp_phase, F::one()),
                                (self.s_back_ref_phase, F::zero()),
                                (self.literal_pos, F::from(pos as u64+1)),
                                (self.backref_pos, F::zero()),
                                (self.backref_progress, F::zero()),
                            ]
                        } else {
                            println!("backref cp {}-{}-{}", cur_literal_cp, pos - i, i);
                            [
                                (self.s_lit_cp_phase, F::one()),
                                (self.s_back_ref_phase, F::zero()),
                                (self.literal_pos, F::from(cur_literal_cp as u64)),
                                (self.backref_pos, F::from((pos - i) as u64)),
                                (self.backref_progress, F::from(i as u64)),
                            ]
                        }
                    ){
                        region.assign_advice(
                            ||"set output region", 
                            col, offset,
                            ||Value::known(val),
                        )?;

                    }

                region.assign_fixed(
                    ||"enable row",
                    self.q_enabled, 
                    offset, 
                    ||Value::known(F::one())
                )?;
                offset += 1;
            }
        }

        Ok((offset, decoded_len, decoded_rlc))
    }  

    /// assign the top row 
    pub fn init_top_row(
        &self,
        region: &mut Region<F>,
        from_offset: Option<usize>,
    ) -> Result<usize, Error>{
        let offset = from_offset.unwrap_or_default();

        for col in [
            self.decoded_byte,
            self.decoded_len,
            self.decoded_rlc,
            self.block_index,
            self.seq_index,
            self.s_back_ref_phase,
            self.s_lit_cp_phase,
            self.s_back_ref_phase,
            self.backref_pos,
            self.literal_pos,
            self.backref_progress,
        ] {
            region.assign_advice(||"top row fluash", col, offset, ||Value::known(F::zero()))?;
        }

        Ok(offset+1)
    }

    #[cfg(test)]
    pub fn mock_assign(
        &self,
        layouter: &mut impl Layouter<F>,
        chng: &Challenges<Value<F>>,
        n_seq: usize,
        seq_exec_infos: &[SequenceExec],
        literals: &[u8],
        // all of the decompressed bytes, not only current block
        decompressed_bytes: &[u8],
        enabled_rows: usize,
    ) -> Result<(), Error>{

        let literals = literals.iter().copied().map(|b|b as u64).collect::<Vec<_>>();

        layouter.assign_region(
            || "output region",
            |mut region|{

                let offset = self.init_top_row(&mut region, None)?;
                let (offset, decoded_len, decoded_rlc) = self.assign_block(
                    &mut region,
                    chng.evm_word(),
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
                    decompressed_bytes
                )?;
                self.paddings(&mut region, 
                    offset, 
                    enabled_rows, 
                    decoded_len, 
                    decoded_rlc, 
                    2
                )?;

                Ok(())
            }
        )
    }

}


#[cfg(test)]
mod tests {

    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::bn256::Fr,
        plonk::Circuit,
    };
    use super::*;
    use witgen::AddressTableRow;
    use zkevm_circuits::util::MockChallenges;

    #[derive(Clone, Debug)]
    struct SeqExecMock {
        outputs: Vec<u8>,
        literal: Vec<u8>,
        seq_conf: SequenceInfo,
        insts: Vec<AddressTableRow>,
        exec_trace: Vec<SequenceExec>,
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

            let literal_tbl = LiteralTable::construct(
                [0;6].map(|_|meta.advice_column())
            );

            let seq_cfg = SequenceConfig::construct(
                [0;3].map(|_|meta.advice_column())
            );

            let inst_tbl = SeqInstTable::configure(meta);

            let chng_mock = MockChallenges::construct(meta);
            let chng = chng_mock.exprs(meta);

            let config = SeqExecConfig::configure(meta, &chng, &literal_tbl, &inst_tbl, &seq_cfg);

            Self::Config{
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

            config.literal_tbl.mock_assign(&mut layouter, 
                self.literal.iter().copied()
                .map(|b|b as u64).collect::<Vec<_>>().as_slice())?;

            config.seq_cfg.mock_assign(&mut layouter, &self.seq_conf)?;

            config.inst_tbl.mock_assign(&mut layouter, &self.insts, 15)?;

            let chng_val = config.chng_mock.values(&mut layouter);

            config.config.mock_assign(
                &mut layouter, 
                &chng_val,
                self.insts.len(), 
                &self.exec_trace, 
                &self.literal, 
                &self.outputs, 
                50,
            )?;

            Ok(())
        }
    }

    fn build_table_row(samples: &[[u64;5]]) -> Vec<AddressTableRow> {
        let mut ret = Vec::<AddressTableRow>::new();

        for sample in samples {
            let mut new_item = AddressTableRow {
                cooked_match_offset: sample[0],
                literal_length: sample[1],
                repeated_offset1: sample[2],
                repeated_offset2: sample[3],
                repeated_offset3: sample[4],
                actual_offset: sample[2],
                ..Default::default()
            };
    
            if let Some(old_item) = ret.last() {
                new_item.instruction_idx = old_item.instruction_idx + 1;
                new_item.literal_length_acc = old_item.literal_length_acc + sample[1];
            } else {
                new_item.literal_length_acc = sample[1];
            }
            
            ret.push(new_item);
        }

        ret
    }

    #[test]
    fn seq_exec_literal_only(){

        // no instructions, we only copy literals to output
        let circuit = SeqExecMock{
            outputs: Vec::from("abcd".as_bytes()),
            literal: Vec::from("abcd".as_bytes()),
            seq_conf: SequenceInfo {
                num_sequences: 0,
                block_idx: 1,
                ..Default::default()
            },
            insts: Vec::new(),
            exec_trace: Vec::new(),
        };

        let k = 12;
        let mock_prover = MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();

    }
}
