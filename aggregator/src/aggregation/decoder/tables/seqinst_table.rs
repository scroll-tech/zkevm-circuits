use eth_types::Field;
use gadgets::util::{and, not, select, Expr};
use halo2_proofs::{
    circuit::Layouter,
    halo2curves::bn256::Fr,
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::LookupTable,
};
use crate::aggregation::decoder::witgen;
use witgen::AddressTableRow;

/// Table used carry the raw sequence instructions parsed from sequence section
/// and would be later transformed as the back-reference instructions
///
/// | Blk index |  Seq ind. |   Tag  |  Value | 
/// |-----------|-----------|--------|--------|
/// |     1     |    0      |  COUNT |   30   |
/// |     1     |    0      | LITERAL|   4    |
/// |     1     |    0      | OFFSET |   2    |
/// |     1     |    0      |  MATCH |   4    |
/// |     1     |    1      | LITERAL|   2    |
/// |     1     |    1      | OFFSET |   10   |
/// |     1     |    1      |  MATCH |   5    |
/// |    ...    |   ...     |   ...  |  ...   |
/// |     1     |    30     |  MATCH |   6    |
/// 
/// Above is a representation of this table. The Tag has following types:
/// - COUNT: indicate the count of sequence in current block
/// - LITERAL, OFFSET, MATCH: indicate the `Value` represent the parsed
///   value of `literal_len`, `offset` and `match_len`
/// 
/// The LITERAL, OFFSET, MATCH tag for the same sequence index MUST be
/// put in the continuous rows and in the same sequence as mentioned above
/// 
/// For block index we should use an 1-index so the empty
/// row can be safely as the default row for lookup
/// 
#[derive(Clone, Debug)]
pub struct SeqValueTable {
    /// Fixed column to denote whether the constraints will be enabled or not.
    pub q_enabled: Column<Fixed>,
    /// The block's 1-indexed
    pub block_index: Column<Advice>,
    /// The sequence index for each tag, for COUNT tag it must be 0
    pub sequence_index: Column<Advice>,
    /// The tag for each value, 0 MUST be a non-tagged row and the
    /// value in this row would be omitted
    pub tag: Column<Advice>,
    /// The value of each entry in parsed sequence
    pub value: Column<Advice>,
}


/// Table used carry the raw sequence instructions parsed from sequence section
/// and would be later transformed as the back-reference instructions
///
/// | Blk index |  Seq ind. |   Tag  |  Value | 
/// |-----------|-----------|--------|--------|
/// |     1     |    0      |  COUNT |   30   |
/// |     1     |    0      | LITERAL|   4    |
/// |     1     |    0      | OFFSET |   2    |
/// |     1     |    0      |  MATCH |   4    |
/// |     1     |    1      | LITERAL|   2    |
/// |     1     |    1      | OFFSET |   10   |
/// |     1     |    1      |  MATCH |   5    |
/// |    ...    |   ...     |   ...  |  ...   |
/// |     1     |    30     |  MATCH |   6    |
/// 

pub struct SeqInstTable {

    q_enabled: Column<Fixed>,

    block_index: Column<Advice>,
    n_seq: Column<Advice>,
    // the value directly decoded from bitstream
    literal_len: Column<Advice>,
    match_offset: Column<Advice>,
    match_len: Column<Advice>,

    // exported, note the match_len would be exported as-is
    // updated offset
    offset: Column<Advice>,
    // updated (acc) literal len
    acc_literal_len: Column<Advice>,

    // helper cols
    repeated_offset: [Column<Advice>;3],
    is_offset_ref: [Column<Advice>;3],
    s_beginning: Column<Advice>,
    seq_index: Column<Advice>,
    seq_helper: Column<Advice>,
    
}


impl SeqInstTable {

    /// Obtian the instruction table cols
    pub fn instructions(&self) -> [Column<Advice>;5]{
        [
            self.block_index,
            self.n_seq,
            self.offset,
            self.acc_literal_len,
            self.match_len,
        ]
    }

    /// Construct the sequence instruction table
    /// the maxium rotation is prev(2), next(1)
    pub fn configure<F: Field>(
        meta: &mut ConstraintSystem<F>,
        seq_table: &SeqValueTable,
    ) -> Self {
        let config = Self {
            q_enabled: seq_table.q_enabled,
            block_index: meta.advice_column(),
            n_seq: meta.advice_column(),
            literal_len: meta.advice_column(),
            match_offset: meta.advice_column(),
            match_len: meta.advice_column(),
            offset: meta.advice_column(),
            acc_literal_len: meta.advice_column(),
            s_beginning: meta.advice_column(),
            seq_index: meta.advice_column(),
            seq_helper: meta.advice_column(),
            repeated_offset: [0;3].map(|_|meta.advice_column()),
            is_offset_ref: [0;3].map(|_|meta.advice_column()),
        };

        // block index must be: equal to prev / +1 with prev / 0
        meta.create_gate("block index and working borders", |meta|{
            let mut cb = BaseConstraintBuilder::default();


            let block_index = meta.query_advice(config.block_index, Rotation::cur());
            let block_index_prev = meta.query_advice(config.block_index, Rotation::prev());

            let prev_is_block_border = meta.query_advice(config.seq_index, Rotation::prev())
                - meta.query_advice(config.n_seq, Rotation::prev());
            
            cb.condition(prev_is_block_border.expr(),
                |cb|{
                    cb.require_equal(
                        "block index must add one or becoming 0",
                        block_index.expr() * block_index.expr(),
                        block_index.expr() * (block_index_prev.expr() + 1.expr()),
                    )
                }
            );

            cb.condition(not::expr(prev_is_block_border.expr()),
                |cb|{
                    cb.require_equal(
                        "block index equal for non-border",
                        block_index.expr(),
                        block_index_prev.expr(),
                    )
                }
            );

            cb.condition(meta.query_advice(config.s_beginning, Rotation::cur()),
                |cb|{
                    cb.require_equal(
                        "block index must add one for beginning",
                        block_index.expr(),
                        block_index_prev.expr() + 1.expr(),
                    )
                }
            );

            cb.gate(meta.query_fixed(config.q_enabled, Rotation::cur()))
        });

        // begin with a lookup for n_seq in seq_table

        config
    }

    pub fn assign<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        table_row: &AddressTableRow,
    ) -> Result<(), Error>{
        unimplemented!();

        Ok(())
    }
}