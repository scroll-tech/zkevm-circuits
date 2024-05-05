
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
use witgen::{AddressTableRow, ZstdTag};
use super::tables;
use tables::SeqInstTable;

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
    pub fn lookup_tbl_for_lit_cp<'a, F: Field>(
        &self,
        meta: &mut VirtualCells<'a, F>
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
    pub fn lookup_tbl_for_lit_size<'a, F: Field>(
        &self,
        meta: &mut VirtualCells<'a, F>
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
#[derive(Clone)]
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

        meta.create_gate("phases", |meta|{
            let mut cb = BaseConstraintBuilder::default();

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

            let is_padding_prev = 1.expr() - s_lit_cp_phase_prev.expr() - s_back_ref_phase_prev.expr();
            cb.condition(is_padding_prev.expr(), |cb|{
                cb.require_equal("padding never change once actived", 
                    is_padding_prev.expr(), 
                    is_padding.expr(),
                );
            });

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::cur())
            )
        });

        meta.create_gate("last literal cp phase", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let s_last_lit_cp_phase_prev = meta.query_advice(s_last_lit_cp_phase, Rotation::prev());
            let s_last_lit_cp_phase = meta.query_advice(s_last_lit_cp_phase, Rotation::cur());
            cb.require_boolean("last lit_cp phase is boolean", s_last_lit_cp_phase.expr());
            cb.condition(and::expr([
                s_last_lit_cp_phase.expr(),
                is_inst_begin.expr(),
            ]), |cb|{
                cb.require_zero("phase can only be actived in inst border", 
                    s_last_lit_cp_phase_prev.expr());
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

        meta.create_gate("padding", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            cb.gate(meta.query_fixed(q_head, Rotation::cur()))
        });

        meta.create_gate("header", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            cb.gate(meta.query_fixed(q_head, Rotation::cur()))
        });

        meta.lookup_any("lookup the instruction from inst table", |meta|{

            let q_enabled = meta.query_fixed(q_enabled, Rotation::prev());

            let block_index = meta.query_advice(block_index, Rotation::prev());
            let seq_index = meta.query_advice(seq_index, Rotation::prev());
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
                (src_expr * is_inst_begin.expr() * q_enabled.expr(), lookup_expr)
            }).collect()
        });

        meta.lookup_any("lookup lit cp char", |meta|{
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

        meta.lookup_any("lookup back ref char", |meta|{
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

        meta.lookup_any("lookup actual literal byte", |meta|{
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

        // TODO:
        meta.lookup_any("lookup instruction counts", |meta|{
            let q_enabled = meta.query_fixed(q_enabled, Rotation::prev());
            let block_index = meta.query_advice(block_index, Rotation::prev());
            let seq_index_at_block_end = meta.query_advice(seq_index, Rotation::prev());

            [].into_iter().zip(
                [
                    block_index,
                    seq_index_at_block_end,
                ]
            ).map(|(lookup_col, src_expr)|{
                let lookup_expr = meta.query_advice(lookup_col, Rotation::cur());
                (src_expr * is_block_begin.expr() * q_enabled.expr(), lookup_expr)
            }).collect()
        });

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

    /// TODO:
    pub fn assign<'a>(
        &self,
        layouter: &mut impl Layouter<F>,
        table_rows: impl Iterator<Item=&'a AddressTableRow> + Clone,
        enabled_rows: usize,
    ) -> Result<(), Error>{

        layouter.assign_region(
            || "output region",
            |mut region|{
                Ok(())
            }
        )
    }    
}