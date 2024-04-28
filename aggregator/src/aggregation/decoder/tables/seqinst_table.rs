
use eth_types::Field;
use gadgets::util::{and, or, not, select, Expr};
use halo2_proofs::{
    circuit::{Value, Layouter},
    plonk::{Advice, Any, Column, ConstraintSystem, Error, Expression, Fixed},
    poly::Rotation,
};
use zkevm_circuits::{
    evm_circuit::{BaseConstraintBuilder, ConstrainBuilderCommon}, table::LookupTable,
};
use crate::aggregation::decoder::witgen;
use witgen::AddressTableRow;

/// Table used carry the raw sequence instructions parsed from sequence section
/// and would be later transformed as the back-reference instructions
/// 
/// For every block, one row in the table represent a single sequence instruction 
/// in the sequence section, and handle all data parsed from the same sequence.
/// The 'block_index' is a 1-index for each block with n sequences in its 
/// sequence section, the parsed value from bitstream for current sequence is put
/// in the 'input cols' section (`literal_len`, `match_offset` and `match_len`)
/// The transformed sequence instructions is put in 'output cols' section (
/// `acc_literal_len`, `offset` and `match_len`),
/// notice we can use `match_len` without transformation.
/// 
/// | enabled |block_index| n_seq |seq_index|s_beginning|<input cols>|<output cols>| 
/// |---------|-----------|-------|---------|-----------|------------|-------------|
/// |     1   |    1      |   30  |    0    |     1     |            |             |
/// |     1   |    1      |   30  |    1    |     0     |  (4,2,4)   |  (4,4,4)    |
/// |     1   |    1      |   30  |    2    |     0     |  (1,5,2)   |  (5,5,2)    |
/// |     1   |    1      |   30  |    3    |     0     |  (0,2,1)   |  (5,1,1)    |
/// |     1   |   ...     |   30  |   ...   |     0     |    ...     |             |
/// |     1   |    1      |   30  |   30    |     0     | (1,50,11)  |             |
/// |     1   |    2      |   20  |    0    |     1     |            |             |
/// |     1   |    2      |   20  |    1    |     0     | (3,52,13)  |             |
/// |     1   |   ...     |   20  |   ...   |     0     |            |             |
/// |     1   |    2      |   20  |   20    |     0     |            |             |
/// |     1   |    3      |   4   |    0    |     1     |            |             |
/// |    ...  |   ...     |  ...  |   ...   |    ...    |            |             |
/// |     1   |   998     |   0   |    0    |     1     |            |             |
/// |     1   |   999     |   0   |    0    |     1     |            |             |
/// 
/// When all sequences from compressed data has been handled, the rest rows being enabled
/// (q_enabled is true) has to be padded with increased block index, with `n_seq` is 0 
/// and `s_beginning` is true
/// 
/// The transform from 'input cols' to 'output cols' according to zstd's spec
/// include following steps:
/// 1. accumulate the copied literal bytes in one section
/// 2. for match offset > 3, set the actual offset val is -=3, else we refer it 
/// from the reference tables represented by 'repeated_offset_1/2/3' cols
/// 3. After each sequence, the reference tables is updated according to the
/// value of cooked offset and whether `literal_len` is zero
///  
/// |literal_len|match_offset|acc_lit_len| offset |match_len|rep_offset_1|rep_offset_2|rep_offset_3|s_beginning|
/// |-----------|------------|-----------|--------|---------|------------|------------|------------|-----------|
/// |           |            |           |        |         |     1      |     4      |      8     |     1     |
/// |    4      |     2      |    4      |   4    |    4    |     4      |     1      |      8     |     0     |
/// |    1      |     5      |    5      |   5    |    2    |     5      |     4      |      1     |     0     |
/// |    0      |     2      |    5      |   1    |    1    |     1      |     5      |      4     |     0     |
/// |           |            |           |        |         |            |            |            |     0     |
/// 
pub struct SeqInstTable {

    // active flag, one active row parse
    q_enabled: Column<Fixed>,

    // 1-index for each block, keep the same for each row
    // until all sequenced has been handled
    block_index: Column<Advice>,
    // the count of sequences in one block, keey the same
    // for each row when block index is not changed
    n_seq: Column<Advice>,
    // the 1-indexed seq number (1..=n_seq) for each 
    // sequence. We have extra row at the beginning of
    // each block with seq_index is 0
    seq_index: Column<Advice>,
    // the flag for the first row in each block (i.e. seq_index is 0)
    s_beginning: Column<Advice>,

    // the value directly decoded from bitstream, one row 
    // for one sequence
    literal_len: Column<Advice>,
    match_offset: Column<Advice>,
    match_len: Column<Advice>,

    // exported instructions for one sequence, 
    // note the match_len would be exported as-is
    // updated offset
    offset: Column<Advice>,
    // updated (acc) literal len
    acc_literal_len: Column<Advice>,

    // the reference table for repeated offset
    rep_offset_1: Column<Advice>,
    rep_offset_2: Column<Advice>,
    rep_offset_3: Column<Advice>,

    // helper cols for "zero testing". i.e for a cell with
    // value v, the value in corresponding helper h is 1/v
    // (if v is not zero) or 0 (if v is zero), and we constraint
    // v * (1- v * h) == 0. We would have a boolean flag 
    // from h * v

    // helper to detect if literal_len is zero
    literal_helper: Column<Advice>,
    // helper to detect if seq_index in current row equal
    // to n_seq (i.e. n_seq - seq_index is zero)
    seq_helper: Column<Advice>,
    // helper to detect if current match_offset is 1, 2 or 3
    offset_helper_1:Column<Advice>,
    offset_helper_2:Column<Advice>,
    offset_helper_3:Column<Advice>,
     
    // helper to detect if rep_offset_1 is 0 (indicate the data
    // is corrupt)
    repeat_corrupt_flag_helper: Column<Advice>,
}

impl<F: Field> LookupTable<F> for SeqInstTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.q_enabled.into(),
            self.block_index.into(),
            self.n_seq.into(),
            self.s_beginning.into(),
            self.seq_index.into(),
            self.literal_len.into(),
            self.match_offset.into(),
            self.match_len.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("q_enabled"),
            String::from("n_seq"),
            String::from("block_index"),
            String::from("s_beginning"),
            String::from("seq_index"),
            String::from("literal_len"),
            String::from("match_offset"),
            String::from("match_len"),
        ]
    }    
}

impl SeqInstTable {

    /// The sequence count should be lookuped by parsed bitstream,
    /// used the block index and value for sequnce count tag to 
    /// lookup (`true`, `block_index`, 1, `value`) 
    /// The table would be padded by increased block index to
    /// fill all rows being enabled
    /// 
    /// | enabled |block_index| flag  | n_seq | 
    /// |---------|-----------|-------|-------|
    /// |     1   |    1      |   1   |   30  |
    /// |     1   |   ...     |  ...  |   30  |
    /// |     1   |    2      |   1   |   20  |
    /// |     1   |   ...     |  ...  |   20  |
    /// |     1   |    3      |   1   |   4   |
    /// |    ...  |   ...     |   ... |  ...  |
    /// |     1   |   999     |   1   |   0   |
    pub fn seq_count_lookup(&self) -> [Column<Any>;4]{
        [
            self.q_enabled.into(),
            self.block_index.into(),
            self.s_beginning.into(),
            self.n_seq.into(),
        ]
    }

    /// The sequence values should be lookuped by parsed bitstream,
    /// used the block index and value with each sequence tag for
    /// multiple lookup (`true`, `block_index`, 0, `seq_index`, `value`) on
    /// corresponding value column (literal len, offset, match len) 
    /// , or a lookup with suitable rotations
    /// | enabled |block_index|s_beginning|seq_index| literal | offset | match | 
    /// |---------|-----------|-----------|---------|---------|--------|-------|
    /// |     1   |    1      |     0     |    1    |   4     |   2    |   4   |
    /// |     1   |    1      |     0     |    2    |   1     |   5    |   2   |
    /// |     1   |    1      |     0     |    3    |   0     |   2    |   3   |
    /// |     1   |   ...     |     0     |   ...   |  ...    |  ...   |  ...  |
    /// |     1   |    1      |     0     |   30    |   1     |  50    |  11   |
    /// |     1   |    2      |     0     |    1    |   3     |  52    |  13   |
    /// |     1   |   ...     |     0     |   ...   |  ...    |  ...   |  ...  |
    /// 
    pub fn seq_values_lookup(&self) -> [Column<Any>;7]{
        [
            self.q_enabled.into(),
            self.block_index.into(),
            self.s_beginning.into(),
            self.seq_index.into(),
            self.literal_len.into(),
            self.match_offset.into(),
            self.match_len.into(),
        ]
    }

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
    ) -> Self {
        let config = Self {
            q_enabled: meta.fixed_column(),
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
            rep_offset_1: meta.advice_column(),
            rep_offset_2: meta.advice_column(),
            rep_offset_3: meta.advice_column(),
            offset_helper_1: meta.advice_column(),
            offset_helper_2: meta.advice_column(),
            offset_helper_3: meta.advice_column(),
            repeat_corrupt_flag_helper: meta.advice_column(),
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

            let repeated_offset_pairs = [
                config.rep_offset_1,
                config.rep_offset_2,
                config.rep_offset_3,
            ].map(|col|
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
            let offset_helpers = [
                config.offset_helper_1,
                config.offset_helper_2,
                config.offset_helper_3,
            ].map(|col|meta.query_advice(col, Rotation::cur()));

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

            let repeated_offset_pairs = [
                config.rep_offset_1,
                config.rep_offset_2,
                config.rep_offset_3,
            ].map(|col|
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

            let corrupt_flag = meta.query_advice(config.repeat_corrupt_flag_helper, Rotation::cur());
            cb.condition(s_literal_zero.expr(), |cb|{
                cb.require_equal("data must not corrupt", 
                    corrupt_flag.expr()*repeated_offset_pairs[0].0.expr(),
                    1.expr(),
                )
            });

            cb.gate(
                meta.query_fixed(config.q_enabled, Rotation::cur())*
                not::expr(meta.query_advice(config.s_beginning, Rotation::cur())),
            )
        });

        // meta.lookup_any("seq table lookup", |meta|{
        //     vec![
        //         (1.expr(), meta.query_fixed(config.q_enabled, Rotation::cur())),
        //         (
        //             meta.query_advice(config.block_index, Rotation::cur()),
        //             meta.query_advice(seq_table.block_index, Rotation::cur()),
        //         ),
        //         (
        //             meta.query_advice(config.block_index, Rotation::cur()),
        //             meta.query_advice(seq_table.block_index, Rotation::cur()),
        //         ),                
        //     ]
        // });

        config
    }

    pub fn assign<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        table_rows: impl Iterator<Item=&'a AddressTableRow> + Clone,
        enabled_rows: usize,
    ) -> Result<(), Error>{
        layouter.assign_region(
            || "addr table",
            |mut region|{

                let mut offset = 0;
                let mut header_offset = 0;
                let mut block_ind = 0u64;
                let mut n_seq = 0u64;

                // sanity check, also calculate the reference
                let mut ref_offset = [0u64;3];

                let fill_header_padding = |
                    offset,
                    block_ind: u64,
                    n_seq: u64,
                |->Result<(), Error>{
                    //region.assign_advice(||"", column, offset, to)
                    for col in [
                        self.offset_helper_1,
                        self.offset_helper_2,
                        self.offset_helper_3,
                        self.rep_offset_1,
                        self.rep_offset_2,
                        self.rep_offset_3,
                        self.match_len,
                        self.match_offset,
                        self.literal_len,
                        self.acc_literal_len,
                        self.offset,
                        self.seq_index,
                        self.literal_helper,
                        self.repeat_corrupt_flag_helper,
                    ] {
                        region.assign_advice(
                            ||"padding values", 
                            col, offset, ||Value::known(F::zero())
                        )?;
                    }
                    region.assign_advice(
                        ||"header block ind", 
                        self.block_index, offset, 
                        ||Value::known(F::from(block_ind))
                    )?;
                    region.assign_advice(
                        ||"header n_seq", 
                        self.n_seq, offset,
                        ||Value::known(F::from(n_seq))
                    )?;
                    region.assign_advice(
                        ||"header seq helper", 
                        self.seq_helper, offset, 
                        ||Value::known(
                            if n_seq == 0 {F::zero()}
                            else {
                                F::from(n_seq).invert().expect("not zero")
                            }                                                        
                        )
                    )?;                             
                    Ok(())
                };

                for row in table_rows.clone() {
                    region.assign_fixed(
                        ||"enable row",
                        self.q_enabled, offset,
                        || Value::known(F::one()),
                    )?;

                    // now AddressTableRow has no block index
                    // so we just suppose it is 1
                    const cur_block : u64 = 1;
                    if block_ind != cur_block {
                        // left one row for header
                        block_ind = cur_block;
                    }
                }

                Ok(())
            }
        )
    }
}


#[cfg(test)]
mod tests {

    use halo2_proofs::halo2curves::bn256::Fr;
    use hex::FromHex;

    #[test]
    fn seqinst_table_gates(){

    }
}