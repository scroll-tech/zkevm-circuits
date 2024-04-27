
use eth_types::Field;
use gadgets::util::{and, or, not, select, Expr};
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
    // the indexed seq number (1..=n_seq)
    seq_index: Column<Advice>,

    // helper cols
    repeated_offset: [Column<Advice>;3],
    offset_helper: [Column<Advice>;3],
    literal_helper: Column<Advice>,
    s_beginning: Column<Advice>,
    seq_helper: Column<Advice>,
    repeat_corrupt_flag: Column<Advice>,
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
            literal_helper: meta.advice_column(),
            repeated_offset: [0;3].map(|_|meta.advice_column()),
            offset_helper: [0;3].map(|_|meta.advice_column()),
            repeat_corrupt_flag: meta.advice_column(),
        };

        // seq_index must increment and compare with n_seq for seq border
        meta.create_gate("seq index and section borders", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let n_seq = meta.query_advice(config.n_seq, Rotation::cur());

            let seq_index = meta.query_advice(config.seq_index, Rotation::cur());
            let seq_index_next = meta.query_advice(config.seq_index, Rotation::next());

            let seq_border_helper = meta.query_advice(config.seq_helper, Rotation::cur());

            let is_seq_border = seq_border_helper.expr() * (n_seq.expr() - seq_index.expr());

            cb.require_zero("boolean for seq border", 
                (1.expr() - is_seq_border.expr()) * (n_seq.expr() - seq_index.expr()),
            );

            cb.require_equal("seq index must increment or 0 in s_beginning", 
                select::expr(
                    is_seq_border.expr(),
                    0.expr(),
                    seq_index.expr() + 1.expr(),
                ), seq_index_next.expr()
            );

            cb.require_boolean("s_beginning is boolean", 
                meta.query_advice(config.s_beginning, Rotation::cur())
            );

            cb.condition(not::expr(is_seq_border.expr()),
                |cb|{
                    cb.require_zero("s_beginning on enabled after seq border", 
                        meta.query_advice(config.s_beginning, Rotation::next())
                    )
                }
            );

            cb.gate(
                meta.query_fixed(config.q_enabled, Rotation::next())
            )
        });

        // block index must be increment at seq border, so section for each
        // block index can occur once
        // and the lookup from seq_table enforce valid block / seq / s_beginning
        // must be put 
        meta.create_gate("block index", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let block_index = meta.query_advice(config.block_index, Rotation::cur());
            let block_index_next = meta.query_advice(config.block_index, Rotation::next());

            let n_seq = meta.query_advice(config.n_seq, Rotation::cur());
            let seq_index = meta.query_advice(config.seq_index, Rotation::cur());
            let seq_border_helper = meta.query_advice(config.seq_helper, Rotation::cur());

            let is_seq_border = seq_border_helper.expr() * (n_seq.expr() - seq_index.expr());

            cb.require_equal("block is increment only in border", 
                select::expr(
                    is_seq_border,
                    block_index.expr() + 1.expr(),
                    block_index.expr(),
                ), 
                block_index_next,
            );
            cb.gate(meta.query_fixed(config.q_enabled, Rotation::next()))
        });

        // so, we enforce s_beginning enabled for valid block index
        meta.create_gate("border constaints", |meta|{
            let mut cb = BaseConstraintBuilder::default();
            let s_beginning = meta.query_advice(config.s_beginning, Rotation::cur());

            let repeated_offset_pairs = config.repeated_offset.map(|col|
                (meta.query_advice(col, Rotation::cur()), 
                meta.query_advice(col, Rotation::prev()))
            );

            for (repeated_offset, repeated_offset_prev) in repeated_offset_pairs {
                cb.condition(s_beginning.expr(), |cb|{

                    cb.require_equal("offset must be inherited in border", 
                        repeated_offset, 
                        repeated_offset_prev,
                    )
                });
            }

            let literal_len = meta.query_advice(config.literal_len, Rotation::cur());
            cb.require_equal("literal len accumulation", 
                select::expr(s_beginning.expr(), 
                    literal_len.expr(), 
                    literal_len.expr() + meta.query_advice(config.acc_literal_len, Rotation::prev()),
                ), 
                meta.query_advice(config.acc_literal_len, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(config.q_enabled, Rotation::cur()))
        });

        // offset is in-section (not s_beginning)
        meta.create_gate("offset reference", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let offset = meta.query_advice(config.match_offset, Rotation::cur());
            let offset_helpers = config.offset_helper
                .map(|col|meta.query_advice(col, Rotation::cur()));

            for (helper, coef) in offset_helpers
                .iter().zip([1,2,3]){

                cb.require_zero("offset helper boolean", 
                    (1.expr() - (offset.expr() - coef.expr())*helper.expr())
                    *  (offset.expr() - coef.expr()),
                );
            }

            let literal_len = meta.query_advice(config.literal_len, Rotation::cur());
            let literal_helper = meta.query_advice(config.literal_helper, Rotation::cur());
            cb.require_zero("literal helper helper boolean", 
                (1.expr() - literal_helper.expr()*literal_len.expr()) * literal_len.expr(),
            );

            let s_literal_zero = 1.expr() - literal_helper.expr()*literal_len.expr();

            let s_offsets = [
                offset_helpers[0].expr() * (offset.expr() - 1.expr()),
                offset_helpers[1].expr() * (offset.expr() - 2.expr()),
                offset_helpers[2].expr() * (offset.expr() - 3.expr()),
            ];

            let s_is_offset_ref = s_offsets.iter()
                .map(|c|c.expr()).into_iter()
                .reduce(|sum, e| sum + e).expect("has items");

            let repeated_offset_pairs = config.repeated_offset.map(|col|
                (meta.query_advice(col, Rotation::cur()), 
                meta.query_advice(col, Rotation::prev()))
            );

            let offset_val = meta.query_advice(config.offset, Rotation::cur());

            let offset_ref_val_on_literal_zero = 
                s_offsets[2].expr() * (repeated_offset_pairs[0].1.expr() - 1.expr())
                + s_offsets[1].expr() * repeated_offset_pairs[2].1.expr()
                + s_offsets[0].expr() * repeated_offset_pairs[1].1.expr();
            let offset_ref_val = 
                s_offsets[0].expr() * repeated_offset_pairs[0].1.expr()
                + s_offsets[1].expr() * repeated_offset_pairs[1].1.expr()
                + s_offsets[2].expr() * repeated_offset_pairs[2].1.expr();

            let offset_ref_val = select::expr(
                s_literal_zero.expr(),
                offset_ref_val_on_literal_zero,
                offset_ref_val,
            );

            cb.require_equal("offset value", 
                select::expr(
                    s_is_offset_ref.expr(),
                    offset_ref_val,
                    offset.expr() - 3.expr(),
                ), 
                offset_val.expr()
            );
            cb.require_equal("set offset 0 to offset val", 
                offset_val.expr(), 
                repeated_offset_pairs[0].0.expr(),
            );

            // shift nature for literal 0 / non-ref
            cb.condition(or::expr([
                s_literal_zero.expr(),
                not::expr(s_is_offset_ref.expr()),
            ]),|cb|{
                cb.require_equal("shift 1", 
                    repeated_offset_pairs[0].1.expr(), 
                    repeated_offset_pairs[1].0.expr(),
                );
                cb.require_equal("shift 2", 
                    repeated_offset_pairs[1].1.expr(), 
                    repeated_offset_pairs[2].0.expr(),
                );              
            });

            // swap for references
            cb.condition(not::expr(s_literal_zero.expr()), |cb|{

                cb.condition(s_offsets[0].expr(), |cb|{
                    cb.require_equal("copy offset 1 for ref 1", 
                        repeated_offset_pairs[1].1.expr(), 
                        repeated_offset_pairs[1].0.expr(),
                    );
                    cb.require_equal("copy offset 2 for ref 1", 
                        repeated_offset_pairs[2].1.expr(), 
                        repeated_offset_pairs[2].0.expr(),
                    );
                });

                cb.condition(s_offsets[1].expr(), |cb|{
                    cb.require_equal("swap 1&2 for ref 2", 
                        repeated_offset_pairs[0].1.expr(), 
                        repeated_offset_pairs[1].0.expr(),
                    );
                    cb.require_equal("copy offset 2 for ref 2", 
                        repeated_offset_pairs[2].1.expr(), 
                        repeated_offset_pairs[2].0.expr(),
                    );                   
                });

                cb.condition(s_offsets[2].expr(), |cb|{
                    cb.require_equal("rotate 3-1 for ref 3", 
                        repeated_offset_pairs[0].1.expr(), 
                        repeated_offset_pairs[1].0.expr(),
                    );
                    cb.require_equal("rotate 3-1 for ref 3", 
                        repeated_offset_pairs[1].1.expr(), 
                        repeated_offset_pairs[2].0.expr(),
                    );                   
                });
            });

            let corrupt_flag = meta.query_advice(config.repeat_corrupt_flag, Rotation::cur());
            cb.condition(s_literal_zero.expr(), |cb|{
                cb.require_equal("data must not corrupt", 
                    corrupt_flag.expr()*repeated_offset_pairs[0].0.expr(),
                    1.expr(),
                )
            });

            cb.gate(
                meta.query_fixed(config.q_enabled, Rotation::cur())*
                meta.query_advice(config.s_beginning, Rotation::cur()),
            )
        });

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