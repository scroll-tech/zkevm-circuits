
use eth_types::Field;
use gadgets::{
    is_equal::*,
    is_zero::*,
    util::{and, or, not, select, Expr},
};
use halo2_proofs::{
    circuit::{Value, Region, Layouter},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon}, 
    table::LookupTable,
};
use crate::aggregation::decoder::witgen;
use witgen::AddressTableRow;
use super::tables;
use tables::SeqInstTable;

/// The literal table which execution circuit expect to lookup from
#[derive(Clone)]
pub struct LiteralTable {
    q_enabled: Column<Fixed>,
    block_index: Column<Advice>,
    byte_index: Column<Advice>,
    char: Column<Advice>,
}

/// SeqExecConfig handling the sequences in each block and output the
/// decompressed bytes
#[derive(Clone)]
pub struct SeqExecConfig<F: Field> {
    // active flag, one active row parse
    q_enabled: Column<Fixed>,
    // 1-index for each block, keep the same for each row
    // until all sequenced has been handled
    block_index: Column<Advice>,
    // the 1-indexed seq number (1..=n_seq) for each 
    // sequence.
    seq_index: Column<Advice>,
    // the index of output byte (0-indexd)
    byte_index: Column<Advice>,
    // the output byte under current index
    output_byte: Column<Advice>,
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

    // the flag exp indicate current row is the beginning of
    // a literal copying
    is_lit_cp_begin: Expression<F>,
}


impl<F: Field> SeqExecConfig<F> {

    /// Construct the sequence instruction table
    /// the maxium rotation is prev(2), next(1)
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        inst_able: &SeqInstTable<F>,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let block_index = meta.advice_column();
        let seq_index = meta.advice_column();
        let byte_index = meta.advice_column();
        let output_byte = meta.advice_column();
        let s_last_seq = meta.advice_column();
        let s_lit_cp_phase = meta.advice_column();
        let s_back_ref_phase = meta.advice_column();
        let progress_cnt = meta.advice_column();
        let literal_pos = meta.advice_column();
        let backref_pos = meta.advice_column();

        Self {
            q_enabled,
            block_index,
            seq_index,
            byte_index,
            output_byte,
            s_last_seq,
            s_lit_cp_phase,
            s_back_ref_phase,
            progress_cnt,
            literal_pos,
            backref_pos,
        }
    }    
}