
use eth_types::Field;
use gadgets::{
    is_equal::*,
    is_zero::*,
    util::{and, or, not, select, Expr},
};
use halo2_proofs::{
    circuit::{Value, Region, Layouter},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon}, 
    table::LookupTable,
    util::Challenges,
};
use crate::aggregation::decoder::witgen;
use witgen::AddressTableRow;
use super::tables;
use tables::SeqInstTable;

/// The literal table which execution circuit expect to lookup from
#[derive(Clone)]
pub struct LiteralTable {
    /// the flag must be set to 1 for any row
    /// contain values for lookup
    pub enable_flag: Column<Advice>,
    /// the index of block which the literal section is in
    pub block_index: Column<Advice>,
    /// the 1-indexed byte of byte of literal section's raw bytes
    pub byte_index: Column<Advice>,
    /// the corresponding char of current index
    pub char: Column<Advice>,
}

/// SeqExecConfig handling the sequences in each block and output the
/// decompressed bytes
#[derive(Clone)]
pub struct SeqExecConfig<F: Field> {
    // active flag, one active row parse
    q_enabled: Column<Fixed>,
    // indicate the row above active region
    q_head: Column<Fixed>,
    // indicate the row below active region
    q_tail: Column<Fixed>,        
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

    // the flag indicate current seq is the last one in 
    // a block
    s_last_seq: Column<Advice>,
    // the flag indicate the execution is under
    // "literal copying" phase
    s_lit_cp_phase: Column<Advice>,
    // the flag indicate the execution is under
    // back reference phase
    s_back_ref_phase: Column<Advice>,
    // counting the progress of lit copying / back ref
    // bytes
    progress_cnt: Column<Advice>,
    // the copied index in literal section 
    literal_pos: Column<Advice>,
    // the back-ref pos 
    backref_pos: Column<Advice>,

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
        inst_able: &SeqInstTable<F>,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let q_head = meta.fixed_column();
        let q_tail = meta.fixed_column();
        let block_index = meta.advice_column();
        let seq_index = meta.advice_column();
        let decoded_len = meta.advice_column();
        let decoded_byte = meta.advice_column();
        let decoded_rlc = meta.advice_column_in(SecondPhase);
        // TODO: constraint the len acc
        let decoded_len_acc = meta.advice_column();
        let s_last_seq = meta.advice_column();
        let s_lit_cp_phase = meta.advice_column();
        let s_back_ref_phase = meta.advice_column();
        let progress_cnt = meta.advice_column();
        let literal_pos = meta.advice_column();
        let backref_pos = meta.advice_column();

        // dummy init
        let mut is_inst_begin = 0.expr();
        let mut is_block_begin = 0.expr();
        let mut is_padding = 0.expr();

        meta.create_gate("borders", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            is_inst_begin = meta.query_advice(seq_index, Rotation::cur())
                - meta.query_advice(seq_index, Rotation::prev());
            
            cb.require_boolean("instruction border is boolean", is_inst_begin.expr());

            is_block_begin = meta.query_advice(block_index, Rotation::cur())
            - meta.query_advice(block_index, Rotation::prev());
        
            cb.require_boolean("block border is boolean", is_block_begin.expr());

            cb.condition(is_block_begin.expr(), |cb|{
                cb.require_equal("if block begin, inst must begin",
                    is_block_begin.expr(), 
                    is_inst_begin.expr(),
                );
            });

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::next())
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

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::next())
            )
        });

        //
        meta.create_gate("", |meta|{
            let mut cb = BaseConstraintBuilder::default();
            cb.gate(
                meta.query_fixed(q_enabled, Rotation::next())
            )
        });

        //
        meta.create_gate("", |meta|{
            let mut cb = BaseConstraintBuilder::default();
            cb.gate(
                meta.query_fixed(q_enabled, Rotation::next())
            )
        });


        Self {
            q_enabled,
            q_head,
            q_tail,
            block_index,
            seq_index,
            decoded_len,
            decoded_byte,
            decoded_rlc,
            decoded_len_acc,
            s_last_seq,
            s_lit_cp_phase,
            s_back_ref_phase,
            progress_cnt,
            literal_pos,
            backref_pos,
            is_padding,
            is_inst_begin,
            is_block_begin,
        }
    }    
}