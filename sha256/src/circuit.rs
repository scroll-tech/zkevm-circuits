
use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Selector, Advice, Any, Assigned, Column, ConstraintSystem, Constraints, TableColumn, Error, Fixed, Expression, Challenge, SecondPhase},
    poly::Rotation,
    halo2curves::bn256::Fr,
};
use std::convert::TryInto;
use crate::table16::*;

/// the defination for a sha256 table
pub trait SHA256Table {
    /// the cols has layout [s_enable, input_bytes, hashes]
    fn cols(&self) -> [Column<Any>;3];

    /// ...
    fn s_enable(&self) -> Column<Fixed> {
        self.cols()[0].try_into().expect("must provide cols as expected layout")
    }
    /// ...
    fn input_rlc(&self) -> Column<Advice> {
        self.cols()[1].try_into().expect("must provide cols as expected layout")
    }
    /// ...
    fn hashes_rlc(&self) -> Column<Advice> {
        self.cols()[2].try_into().expect("must provide cols as expected layout")
    }
}

/// ...
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    table16: Table16Config,
    byte_range: TableColumn,

    copied_data: Column<Advice>,
    trans_byte: Column<Advice>,
    bytes_rlc: Column<Advice>, // phase 2 col obtained from SHA256 table, used for saving the rlc bytes from input
    helper: Column<Advice>, // phase 2 col used to save series of data, like the final input rlc cell, the padding bit count, etc

    s_final_block: Column<Advice>, // indicate it is the last block, it can be 0/1 in input region and 
                                   // digest region is set the same as corresponding input region
    s_padding: Column<Advice>, // indicate cur bytes is padding
    byte_counter: Column<Advice>, // counting for the input bytes

    s_output: Column<Fixed>, // indicate the row is used for output to sha256 table

    s_begin: Selector, // indicate as the first line in region
    s_final: Selector, // indicate the last byte
    s_enable: Selector, // indicate the main rows
    s_common_bytes: Selector, // mark the s_enable region except for the last 8 bytes
    s_padding_size: Selector, // mark the last 8 bytes for padding size
    s_assigned_u16: Selector,// indicate copied_data cell is a assigned u16 word
}


impl CircuitConfig {

    fn setup_gates(&self, 
        meta: &mut ConstraintSystem<Fr>,
        keccak_chng: Challenge,
    ){
        let one = Expression::Constant(Fr::one());

        meta.create_gate("haves to rlc_byte", |meta|{
            
            let s_u16 = meta.query_selector(self.s_assigned_u16);
            let u16 = meta.query_advice(self.copied_data, Rotation::cur());
            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let byte_next = meta.query_advice(self.trans_byte, Rotation::next());
            let rlc_byte_prev = meta.query_advice(self.bytes_rlc, Rotation::prev());
            let rlc_byte = meta.query_advice(self.bytes_rlc, Rotation::cur());

            let s_enable = meta.query_selector(self.s_enable);

            // constraint u16 in table16 with byte
            let byte_from_u16 = s_u16 * (u16 - (byte.clone() * Expression::Constant(Fr::from(256u64)) + byte_next));

            let rnd = meta.query_challenge(keccak_chng);
            let byte_rlc = rlc_byte - (rlc_byte_prev * rnd + byte);

            vec![
                byte_from_u16,
                s_enable * byte_rlc,
            ]
        });

        meta.create_gate("sha256 block padding", |meta|{

            let s_padding = meta.query_advice(self.s_padding, Rotation::cur());
            let s_padding_prev = meta.query_advice(self.s_padding, Rotation::prev());
            
            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let byte_counter = meta.query_advice(self.byte_counter, Rotation::cur());
            let byte_counter_prev = meta.query_advice(self.byte_counter, Rotation::prev());

            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());

            let padding_is_bool = s_padding.clone() * (one.clone() - s_padding.clone());
            let s_not_padding = one.clone() - s_padding.clone();

            let byte_counter_continue = s_not_padding *(byte_counter.clone() - (byte_counter_prev.clone() + one.clone()))
                + s_padding.clone() *(byte_counter.clone() - byte_counter_prev);

            let padding_change = s_padding - s_padding_prev.clone();

            // if prev padding is 1, the following padding would always 1 (no change)
            let padding_continue = s_padding_prev.clone() * padding_change.clone();

            // the byte on first padding is 128 (first bit is 1)
            let padding_byte_on_change = padding_change.clone() * (byte.clone() - Expression::Constant(Fr::from(128u64)));

            // constraint the padding byte, notice it in fact constraint the first byte of the final 64-bit integer
            // is 0, but it is ok (we have no so large bytes for 48-bit integer)
            let padding_byte_is_zero = s_padding_prev * is_final.clone() * byte;

            let padding_change_on_size = meta.query_selector(self.s_padding_size) * is_final * padding_change;

            Constraints::with_selector(meta.query_selector(self.s_enable), 
                vec![
                    padding_is_bool,
                    padding_continue,
                    byte_counter_continue,
                ]
            ).into_iter()
            .chain(
                Constraints::with_selector(meta.query_selector(self.s_common_bytes), 
                    vec![
                        padding_byte_is_zero,
                        padding_byte_on_change,
                    ]
                )
            ).chain(
                vec![padding_change_on_size.into()]
            )
        });

        meta.create_gate("sha256 block final", |meta|{
            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());
            // final is decided by the begin row
            let final_continue = is_final.clone() - meta.query_advice(self.s_final_block, Rotation::prev());
            let final_is_bool = is_final.clone() * (one.clone() - is_final.clone());

            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let padding_size = meta.query_advice(self.helper, Rotation::cur());
            let padding_size_prev = meta.query_advice(self.helper, Rotation::prev());

            let padding_size_calc = padding_size.clone() - (padding_size_prev * Expression::Constant(Fr::from(256u64)) + byte);
            let final_must_padded = (one.clone() - meta.query_advice(self.s_padding, Rotation::cur())) * is_final.clone();

            let padding_size_is_zero = meta.query_selector(self.s_common_bytes) * padding_size.clone();

            // final contintion: byte counter equal to padding size
            let final_condition = meta.query_selector(self.s_final) * (padding_size - meta.query_advice(self.byte_counter, Rotation::cur())) * is_final.clone();

            let u16 = meta.query_advice(self.copied_data, Rotation::cur());
            let u16_exported = meta.query_advice(self.copied_data, Rotation::next());
            let init_iv_u16 = meta.query_fixed(self.s_output, Rotation::cur());
            let is_not_final = one.clone() - is_final.clone();

            let select_exported = meta.query_selector(self.s_assigned_u16) * (u16_exported - is_final * u16 - is_not_final * init_iv_u16);

            Constraints::with_selector(meta.query_selector(self.s_enable), 
                vec![
                    final_continue,
                    final_is_bool,
                ]
            ).into_iter()
            .chain(
                Constraints::with_selector(meta.query_selector(self.s_padding_size), 
                    vec![
                        final_must_padded,
                        padding_size_calc,
                    ]
                )
            )
            .chain(
                vec![
                    padding_size_is_zero.into(),
                    final_condition.into(),
                    select_exported.into(),
                ]
            )
            
        });

        meta.create_gate("input block beginning", |meta|{

            // is *last block* final
            let is_final = meta.query_advice(self.s_final_block, Rotation::prev());
            let is_not_final = one.clone() - is_final.clone();

            let inherited_counter = meta.query_advice(self.byte_counter, Rotation::prev());
            let byte_counter = meta.query_advice(self.byte_counter, Rotation::cur());

            let applied_counter = is_not_final.clone() * (byte_counter.clone() - inherited_counter) + is_final.clone() * byte_counter;

            let inherited_bytes_rlc = meta.query_advice(self.bytes_rlc, Rotation::prev());
            let bytes_rlc = meta.query_advice(self.bytes_rlc, Rotation::prev());

            let applied_bytes_rlc = is_not_final.clone() * (bytes_rlc.clone() - inherited_bytes_rlc) + is_final.clone() * bytes_rlc;

            let inherited_s_padding = meta.query_advice(self.s_padding, Rotation::prev());
            let s_padding = meta.query_advice(self.s_padding, Rotation::prev());

            let applied_s_padding = is_not_final.clone() * (s_padding.clone() - inherited_s_padding.clone()) + is_final.clone() * s_padding;

            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());
            let final_is_bool = is_final.clone() * (one.clone() - is_final.clone());
            
            // notice now the 'is_final' point to current block and 'is_not_final' point to last block (prev)
            // this constraint make circuit can not make a full block is padded but not final
            let enforce_final = is_not_final * inherited_s_padding * (one.clone() - is_final);

            Constraints::with_selector(meta.query_selector(self.s_enable), 
                vec![
                    final_is_bool,
                    applied_counter,
                    applied_bytes_rlc,
                    applied_s_padding,
                    enforce_final,
                ]
            )
        });

    }

    /// Configures a circuit to include this chip.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        sha256_table: impl SHA256Table,
    ) -> Self {
        
        let table16 = Table16Chip::configure(meta);
        let helper = meta.advice_column();
        let trans_byte = meta.advice_column();

        let bytes_rlc = sha256_table.hashes_rlc();
        let copied_data = sha256_table.input_rlc();
        let s_output = sha256_table.s_enable();

        let s_padding_size = meta.selector();
        let s_final_block = meta.advice_column();
        let s_padding = meta.advice_column();
        let byte_counter = meta.advice_column();
        let s_begin = meta.selector();
        let s_common_bytes = meta.selector();
        let s_final = meta.selector();
        let s_enable = meta.selector();
        let s_assigned_u16 = meta.selector();

        let byte_range = meta.lookup_table_column(); 

        meta.enable_equality(copied_data);
        meta.enable_equality(bytes_rlc);
        meta.enable_equality(s_final_block);
        meta.enable_equality(byte_counter);

        let ret = Self {
            table16,
            byte_range,

            copied_data,
            trans_byte,
            bytes_rlc,
            helper,

            s_final_block,
            s_common_bytes,
            s_padding_size,
            s_padding,
            byte_counter,
            
            s_output,

            s_begin,
            s_final,
            s_enable,
            s_assigned_u16,
        };

        meta.lookup("byte range checking", |meta|{
            let byte = meta.query_advice(ret.trans_byte, Rotation::cur());
            vec![(byte, byte_range)]
        });

        let chng = meta.challenge_usable_after(SecondPhase);
        ret.setup_gates(meta, chng);

        ret
    }
}