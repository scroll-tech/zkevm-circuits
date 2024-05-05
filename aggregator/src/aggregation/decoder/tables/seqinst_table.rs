
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

#[derive(Clone)]
pub struct SeqInstTable<F: Field> {

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

    // detect if literal_len is zero
    literal_is_zero: IsZeroConfig<F>,
    // detect if seq_index in current row equal
    // to n_seq (i.e. n_seq - seq_index is zero)
    seq_index_is_n_seq: IsEqualConfig<F>,
    // detect if current match_offset is 1, 2 or 3
    offset_is_1: IsEqualConfig<F>,
    offset_is_2: IsEqualConfig<F>,
    offset_is_3: IsEqualConfig<F>,
     
    // detect if rep_offset_1 is 0 (indicate the data
    // is corrupt)
    ref_offset_1_is_zero: IsZeroConfig<F>,
}

impl<F: Field> LookupTable<F> for SeqInstTable<F> {
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

impl<F: Field> SeqInstTable<F> {

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
            self.seq_index,
            self.offset,
            self.acc_literal_len,
            self.match_len,
        ]
    }

    /// Construct the sequence instruction table
    /// the maxium rotation is prev(1), next(1)
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> Self {
        let q_enabled = meta.fixed_column();
        let block_index = meta.advice_column();
        let n_seq = meta.advice_column();
        let literal_len = meta.advice_column();
        let match_offset = meta.advice_column();
        let match_len = meta.advice_column();
        let offset = meta.advice_column();
        let acc_literal_len = meta.advice_column();
        let s_beginning = meta.advice_column();
        let seq_index = meta.advice_column();
        let rep_offset_1 = meta.advice_column();
        let rep_offset_2 = meta.advice_column();
        let rep_offset_3 = meta.advice_column();

        let [literal_is_zero, ref_offset_1_is_zero] = 
        [literal_len, rep_offset_1].map(|col|{
            let inv_col = meta.advice_column();
            IsZeroChip::configure(
                meta, 
                |meta|meta.query_fixed(q_enabled, Rotation::cur()),
                |meta|meta.query_advice(col, Rotation::cur()),
                inv_col
            )
        });
        let [offset_is_1, offset_is_2, offset_is_3] = 
        [
            (rep_offset_1, 1),
            (rep_offset_2, 2),
            (rep_offset_3, 3)
        ].map(|(col, val)|{
            IsEqualChip::configure(
                meta, 
                |meta|meta.query_fixed(q_enabled, Rotation::cur()),
                |meta|meta.query_advice(col, Rotation::cur()), 
                |_|val.expr()
            )
        });
        let seq_index_is_n_seq = IsEqualChip::configure(
            meta, 
            |meta|meta.query_fixed(q_enabled, Rotation::cur()),
            |meta|meta.query_advice(seq_index, Rotation::cur()), 
            |meta|meta.query_advice(n_seq, Rotation::cur()),
        );

        // seq_index must increment and compare with n_seq for seq border
        meta.create_gate("seq index and section borders", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let n_seq = meta.query_advice(n_seq, Rotation::cur());

            let seq_index_next = meta.query_advice(seq_index, Rotation::next());
            let seq_index = meta.query_advice(seq_index, Rotation::cur());
            let is_seq_border = &seq_index_is_n_seq;

            cb.require_equal("seq index must increment or 0 in s_beginning", 
                select::expr(
                    is_seq_border.expr(),
                    0.expr(),
                    seq_index.expr() + 1.expr(),
                ), seq_index_next.expr()
            );

            cb.require_boolean("s_beginning is boolean", 
                meta.query_advice(s_beginning, Rotation::cur())
            );

            cb.condition(not::expr(is_seq_border.expr()),
                |cb|{
                    cb.require_zero("s_beginning on enabled after seq border", 
                        meta.query_advice(s_beginning, Rotation::next())
                    )
                }
            );

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::next())
            )
        });

        // block index must be increment at seq border, so section for each
        // block index can occur once
        // and the lookup from seq_table enforce valid block / seq / s_beginning
        // must be put 
        meta.create_gate("block index", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let block_index_next = meta.query_advice(block_index, Rotation::next());
            let block_index = meta.query_advice(block_index, Rotation::cur());

            let n_seq = meta.query_advice(n_seq, Rotation::cur());
            let seq_index = meta.query_advice(seq_index, Rotation::cur());
            let is_seq_border = &seq_index_is_n_seq;

            cb.require_equal("block is increment only in border", 
                select::expr(
                    is_seq_border.expr(),
                    block_index.expr() + 1.expr(),
                    block_index.expr(),
                ), 
                block_index_next,
            );
            cb.gate(meta.query_fixed(q_enabled, Rotation::next()))
        });

        // so, we enforce s_beginning enabled for valid block index
        meta.create_gate("border constaints", |meta|{
            let mut cb = BaseConstraintBuilder::default();
            let s_beginning = meta.query_advice(s_beginning, Rotation::cur());

            let repeated_offset_pairs = [
                rep_offset_1,
                rep_offset_2,
                rep_offset_3,
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

            let literal_len = meta.query_advice(literal_len, Rotation::cur());
            cb.require_equal("literal len accumulation", 
                select::expr(s_beginning.expr(), 
                    literal_len.expr(), 
                    literal_len.expr() + meta.query_advice(acc_literal_len, Rotation::prev()),
                ), 
                meta.query_advice(acc_literal_len, Rotation::cur()),
            );

            cb.gate(meta.query_fixed(q_enabled, Rotation::cur()))
        });

        // offset is in-section (not s_beginning)
        meta.create_gate("offset reference", |meta|{
            let mut cb = BaseConstraintBuilder::default();

            let offset_val = meta.query_advice(offset, Rotation::cur());
            let offset = meta.query_advice(match_offset, Rotation::cur());

            let literal_len = meta.query_advice(literal_len, Rotation::cur());

            let s_is_offset_ref = or::expr([
                offset_is_1.expr(),
                offset_is_2.expr(),
                offset_is_3.expr(),
            ]);

            let [rep_offset_1_prev, rep_offset_2_prev, rep_offset_3_prev]
             = [
                rep_offset_1,
                rep_offset_2,
                rep_offset_3,
            ].map(|col|meta.query_advice(col, Rotation::prev()));
             
            let [rep_offset_1, rep_offset_2, rep_offset_3]
             = [
                rep_offset_1,
                rep_offset_2,
                rep_offset_3,
            ].map(|col|meta.query_advice(col, Rotation::cur()));

            // in ref offset case, the actual offset val come from
            // ref offset table (exception case rasised if literal len 
            // is zero)
            let offset_ref_val_on_literal_zero = 
                offset_is_3.expr() * (rep_offset_1_prev.expr() - 1.expr())
                + offset_is_1.expr() * rep_offset_2_prev.expr()
                + offset_is_2.expr() * rep_offset_3_prev.expr();
            let offset_ref_val = 
                offset_is_1.expr() * rep_offset_1_prev.expr()
                + offset_is_2.expr() * rep_offset_2_prev.expr()
                + offset_is_3.expr() * rep_offset_3_prev.expr();

            let offset_ref_val = select::expr(
                literal_is_zero.expr(),
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
            // and ref in offset_1 is updated by current value 
            cb.require_equal("set offset 0 to offset val", 
                offset_val.expr(), 
                rep_offset_1.expr(),
            );

            // following we updated table for rep_offset_2/3

            // for no-ref or literal len is 0, ref offset table is
            // updated with a "shift" nature
            cb.condition(or::expr([
                literal_is_zero.expr(),
                not::expr(s_is_offset_ref.expr()),
            ]),|cb|{
                cb.require_equal("shift 1 -> 2", 
                    rep_offset_1_prev.expr(), 
                    rep_offset_2.expr(),
                );
                cb.require_equal("shift 2 -> 3", 
                    rep_offset_2_prev.expr(), 
                    rep_offset_3.expr(),
                );              
            });

            // in ref offset case (offset is 1-3), the table is
            // updated by more complificant fashion
            cb.condition(not::expr(literal_is_zero.expr()), |cb|{

                // offset is 1, table not change
                cb.condition(offset_is_1.expr(), |cb|{
                    cb.require_equal("copy offset 1 for ref 1", 
                        rep_offset_2_prev.expr(), 
                        rep_offset_2.expr(),
                    );
                    cb.require_equal("copy offset 2 for ref 1", 
                        rep_offset_3_prev.expr(), 
                        rep_offset_3.expr(),
                    );
                });

                // offset is 2, offset 1 and 2 is swapped (3 unchanged)
                cb.condition(offset_is_2.expr(), |cb|{
                    cb.require_equal("swap 1&2 for ref 2", 
                        rep_offset_1_prev.expr(), 
                        rep_offset_2.expr(),
                    );
                    cb.require_equal("copy offset 3 for ref 2", 
                        rep_offset_3_prev.expr(), 
                        rep_offset_3.expr(),
                    );                   
                });

                // offset is 3, offset table has a rotation
                cb.condition(offset_is_3.expr(), |cb|{
                    cb.require_equal("rotate 3-1 for ref 3", 
                        rep_offset_1_prev.expr(), 
                        rep_offset_2.expr(),
                    );
                    cb.require_equal("rotate 3-1 for ref 3", 
                        rep_offset_2_prev.expr(), 
                        rep_offset_3.expr(),
                    );                   
                });
            });

            cb.condition(literal_is_zero.expr(), |cb|{
                cb.require_zero("data must not corrupt", 
                    ref_offset_1_is_zero.expr(),
                )
            });

            cb.gate(
                meta.query_fixed(q_enabled, Rotation::cur())*
                not::expr(meta.query_advice(s_beginning, Rotation::cur())),
            )
        });

        // the beginning of following rows must be constrainted
        meta.enable_equality(block_index);
        meta.enable_equality(rep_offset_1);
        meta.enable_equality(rep_offset_2);
        meta.enable_equality(rep_offset_3);

        Self {
            q_enabled,
            block_index,
            n_seq,
            literal_len,
            match_offset,
            match_len,
            offset,
            acc_literal_len,
            s_beginning,
            seq_index,
            rep_offset_1,
            rep_offset_2,
            rep_offset_3,
            offset_is_1,
            offset_is_2,
            offset_is_3,
            literal_is_zero,
            seq_index_is_n_seq,
            ref_offset_1_is_zero,
        }
    }

    pub fn assign<'a>(
        &self,
        layouter: &mut impl Layouter<F>,
        table_rows: impl Iterator<Item=&'a AddressTableRow> + Clone,
        enabled_rows: usize,
    ) -> Result<(), Error>{

        let literal_is_zero_chip = IsZeroChip::construct(self.literal_is_zero.clone());
        let ref_offset_1_is_zero_chip = IsZeroChip::construct(self.ref_offset_1_is_zero.clone());
        let seq_index_chip = IsEqualChip::construct(self.seq_index_is_n_seq.clone());
        let offset_is_1_chip = IsEqualChip::construct(self.offset_is_1.clone());
        let offset_is_2_chip = IsEqualChip::construct(self.offset_is_2.clone());
        let offset_is_3_chip = IsEqualChip::construct(self.offset_is_3.clone());

        layouter.assign_region(
            || "addr table",
            |mut region|{

                let fill_header_padding = |
                    region: &mut Region<F>,
                    offset,
                    block_ind: u64,
                    n_seq: u64,
                    offset_table: [u64;3],
                |->Result<(), Error>{
                    region.assign_fixed(
                        ||"enable row",
                        self.q_enabled, offset,
                        || Value::known(F::one()),
                    )?;                    
                    //region.assign_advice(||"", column, offset, to)
                    for col in [
                        self.rep_offset_1,
                        self.rep_offset_2,
                        self.rep_offset_3,
                        self.match_len,
                        self.match_offset,
                        self.literal_len,
                        self.acc_literal_len,
                        self.offset,
                        self.seq_index,
                    ] {
                        region.assign_advice(
                            ||"padding values", 
                            col, offset, ||Value::known(F::zero())
                        )?;
                    }

                    for (col, val) in [
                        (self.rep_offset_1, offset_table[0]),
                        (self.rep_offset_2, offset_table[1]),
                        (self.rep_offset_3, offset_table[2]),
                        (self.block_index, block_ind),
                        (self.n_seq, n_seq)
                    ]{
                        region.assign_advice(
                            ||"header block fill", 
                            col, offset, 
                            ||Value::known(F::from(val))
                        )?;                        
                    }
                    for chip in [
                        &literal_is_zero_chip,
                        &ref_offset_1_is_zero_chip,
                    ] {
                        chip.assign(region, offset, Value::known(F::zero()))?;
                    }

                    for (chip, val) in [
                        (&offset_is_1_chip, F::from(1u64)),
                        (&offset_is_2_chip, F::from(2u64)),
                        (&offset_is_3_chip, F::from(3u64)),
                        (&seq_index_chip, F::from(n_seq)),
                    ]{
                        chip.assign(region, offset, Value::known(F::zero()), Value::known(val))?;
                    }

                    Ok(())
                };

                // top row constraint
                for (col, val) in [
                    (self.block_index, F::zero()),
                    (self.rep_offset_1, F::from(1u64)),
                    (self.rep_offset_1, F::from(4u64)),
                    (self.rep_offset_1, F::from(8u64)),
                ] {
                    region.assign_advice_from_constant(||"top row", col, 0, val)?;
                }

                for col in [
                    self.seq_index,
                    self.acc_literal_len,
                ] {
                    region.assign_advice(||"top row flush", col, 0, ||Value::known(F::zero()))?;
                }


                let mut offset = 1;
                let mut block_ind = 0u64;
                let mut n_seq = 0u64;
                let mut block_head_fill_f : Box<
                    dyn FnOnce(&mut Region<F>, u64) -> Result<(), Error>
                >
                    = Box::new(|_, _|Ok(()));

                // sanity check, also calculate the reference
                let mut seq_index = 0u64;
                let mut offset_table : [u64;3]= [1,4,8];
                let mut acc_literal_len = 0u64;

                for table_row in table_rows.clone() {

                    // now AddressTableRow has no block index
                    // so we just suppose it is 1
                    let cur_block = 1u64;

                    // when meet first new block, we insert a
                    // header row first, but the calling has to
                    // be postpone since we need to collect the
                    // n_seq later
                    if block_ind != cur_block {
                        block_head_fill_f(&mut region, n_seq)?;
                        // left one row for header
                        block_ind = cur_block;
                        seq_index = 0;
                        acc_literal_len = 0;
                        block_head_fill_f = Box::new(move |region, n_seq|
                            fill_header_padding(
                                region,
                                offset,
                                cur_block,
                                n_seq,
                                offset_table,
                            )
                        );
                        offset += 1;
                    }

                    region.assign_fixed(
                        ||"enable row",
                        self.q_enabled, offset,
                        || Value::known(F::one()),
                    )?;

                    let offset_val = match table_row.cooked_match_offset {
                        0 => panic!("invalid cooked offset"),
                        1 => if table_row.literal_length == 0 {
                            offset_table[1]
                        } else {
                            offset_table[0]
                        },
                        2 => if table_row.literal_length == 0 {
                            offset_table[2]
                        } else {
                            offset_table[1]
                        },
                        3 => if table_row.literal_length == 0 {
                            offset_table[0] - 1
                        } else {
                            offset_table[2]
                        },
                        val => val - 3,
                    };
                    n_seq = table_row.instruction_idx + 1;
                    acc_literal_len += table_row.literal_length;

                    assert_eq!(offset_val, table_row.actual_offset);
                    offset_table[0] = table_row.repeated_offset1;
                    offset_table[1] = table_row.repeated_offset2;
                    offset_table[2] = table_row.repeated_offset3;

                    for (name, col, val) in [
                        ("offset table 1", self.rep_offset_1, F::from(offset_table[0])),
                        ("offset table 2", self.rep_offset_2, F::from(offset_table[1])),
                        ("offset table 3", self.rep_offset_3, F::from(offset_table[2])),
                        ("mlen", self.match_len, F::from(table_row.match_length)),
                        ("moff", self.match_offset, F::from(table_row.cooked_match_offset)),
                        ("llen", self.literal_len, F::from(table_row.literal_length)),
                        ("llen_acc", self.acc_literal_len, F::from(acc_literal_len)),
                        ("offset", self.offset, F::from(offset_val)),
                        ("seq ind", self.seq_index, F::from(seq_index)),
                    ] {
                        region.assign_advice(
                            ||name, col, offset, ||Value::known(val)
                        )?;
                    }

                    for (chip, val) in [
                        (&literal_is_zero_chip, F::from(table_row.literal_length)),
                        (&ref_offset_1_is_zero_chip, F::from(offset_table[0])),
                    ] {
                        chip.assign(&mut region, offset, Value::known(val))?;
                    }

                    for (chip, val_l, val_r) in [
                        (&offset_is_1_chip, F::from(offset_table[0]), F::from(1u64)),
                        (&offset_is_2_chip, F::from(offset_table[1]), F::from(2u64)),
                        (&offset_is_3_chip, F::from(offset_table[2]), F::from(3u64)),
                        (&seq_index_chip, F::from(seq_index), F::from(n_seq)),
                    ]{
                        chip.assign(&mut region, offset, Value::known(val_l), Value::known(val_r))?;
                    }
                    offset += 1;
                    seq_index += 1;  
                }
                // final call for last post-poned head filling func
                block_head_fill_f(&mut region, n_seq)?;

                // pad the rest rows until final row
                for (offset, blk_index) in (offset..enabled_rows)
                    .zip(std::iter::successors(Some(block_ind+1), |ind|Some(ind+1))){

                    fill_header_padding(
                        &mut region,
                        offset,
                        blk_index,
                        0,
                        offset_table,
                    )?;
                }

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
    use hex::FromHex;
    use super::*;

    #[derive(Clone, Debug)]
    struct SeqTable (Vec<AddressTableRow>);

    impl Circuit<Fr> for SeqTable {
        type Config = SeqInstTable<Fr>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }
    
        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {

            let const_col = meta.fixed_column();
            meta.enable_constant(const_col);

            Self::Config::configure(meta)
        }
    
        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {

            config.assign(
                &mut layouter,
                self.0.iter(),
                100,
            )?;

            Ok(())
        }
    }

    #[test]
    fn seqinst_table_gates(){

        let circuit = SeqTable(vec![

        ]);

        let k = 12;
        let mock_prover = MockProver::<Fr>::run(k, &circuit, vec![]).expect("failed to run mock prover");
        mock_prover.verify().unwrap();

    }
}