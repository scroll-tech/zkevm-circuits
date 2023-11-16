use crate::{table16::*, Sha256Instructions};
use halo2_gadgets::sha256::BLOCK_SIZE;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Any, Column, ConstraintSystem, Constraints, Error, Expression, Fixed, Selector,
        TableColumn,
    },
    poly::Rotation,
};
use itertools::Itertools;
use std::convert::TryInto;
type BlockState = <Table16Chip as Sha256Instructions<Fr>>::State;

/// the defination for a sha256 table
pub trait SHA256Table {
    /// the cols has layout [s_enable, input_bytes, hashes, effect]
    fn cols(&self) -> [Column<Any>; 4];

    /// ...
    fn s_enable(&self) -> Column<Fixed> {
        self.cols()[0]
            .try_into()
            .expect("must provide cols as expected layout")
    }
    /// ...
    fn input_rlc(&self) -> Column<Advice> {
        self.cols()[1]
            .try_into()
            .expect("must provide cols as expected layout")
    }
    /// ...
    fn hashes_rlc(&self) -> Column<Advice> {
        self.cols()[2]
            .try_into()
            .expect("must provide cols as expected layout")
    }
    /// a phase 0 col indicate this row is effect (corresponding to a final block)
    fn is_effect(&self) -> Column<Advice> {
        self.cols()[3]
            .try_into()
            .expect("must provide cols as expected layout")
    }
}

/// ...
#[derive(Clone, Debug)]
pub struct CircuitConfig {
    table16: Table16Config,
    byte_range: TableColumn,

    copied_data: Column<Advice>,
    trans_byte: Column<Advice>,
    bytes_rlc: Column<Advice>, /* phase 2 col obtained from SHA256 table, used for saving the
                                * rlc bytes from input */
    helper: Column<Advice>, /* phase 2 col used to save series of data, like the final input rlc
                             * cell, the padding bit count, etc */

    s_final_block: Column<Advice>, /* indicate it is the last block, it can be 0/1 in input
                                    * region and */
    // digest region is set the same as corresponding input region
    s_padding: Column<Advice>,    // indicate cur bytes is padding
    byte_counter: Column<Advice>, // counting for the input bytes

    s_output: Column<Fixed>, // indicate the row is used for output to sha256 table

    s_begin: Selector,        // indicate as the first line in region
    s_final: Selector,        // indicate the last byte
    s_enable: Selector,       // indicate the main rows
    s_common_bytes: Selector, // mark the s_enable region except for the last 8 bytes
    s_padding_size: Selector, // mark the last 8 bytes for padding size
    s_assigned_u16: Selector, // indicate copied_data cell is a assigned u16 word
}

#[derive(Clone, Debug)]
struct BlockInheritments {
    s_final: AssignedBits<Fr, 1>,
    s_padding: AssignedBits<Fr, 1>,
    byte_counter: AssignedCell<Fr, Fr>,
    bytes_rlc: AssignedCell<Fr, Fr>,
}

impl CircuitConfig {
    fn setup_gates(&self, meta: &mut ConstraintSystem<Fr>, rnd: Expression<Fr>) {
        let one = Expression::Constant(Fr::one());

        meta.create_gate("haves to rlc_byte", |meta| {
            let s_u16 = meta.query_selector(self.s_assigned_u16);
            let u16 = meta.query_advice(self.copied_data, Rotation::cur());
            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let byte_next = meta.query_advice(self.trans_byte, Rotation::next());
            let rlc_byte_prev = meta.query_advice(self.bytes_rlc, Rotation::prev());
            let rlc_byte = meta.query_advice(self.bytes_rlc, Rotation::cur());

            let s_enable = meta.query_selector(self.s_enable);

            // constraint u16 in table16 with byte
            let byte_from_u16 =
                s_u16 * (u16 - (byte.clone() * Expression::Constant(Fr::from(256u64)) + byte_next));

            let byte_rlc = rlc_byte - (rlc_byte_prev * rnd + byte);

            vec![byte_from_u16, s_enable * byte_rlc]
        });

        meta.create_gate("sha256 block padding", |meta| {
            let s_padding = meta.query_advice(self.s_padding, Rotation::cur());
            let s_padding_prev = meta.query_advice(self.s_padding, Rotation::prev());

            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let byte_counter = meta.query_advice(self.byte_counter, Rotation::cur());
            let byte_counter_prev = meta.query_advice(self.byte_counter, Rotation::prev());

            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());

            let padding_is_bool = s_padding.clone() * (one.clone() - s_padding.clone());
            let s_not_padding = one.clone() - s_padding.clone();

            let byte_counter_continue = s_not_padding
                * (byte_counter.clone() - (byte_counter_prev.clone() + one.clone()))
                + s_padding.clone() * (byte_counter - byte_counter_prev);

            let padding_change = s_padding - s_padding_prev.clone();

            // if prev padding is 1, the following padding would always 1 (no change)
            let padding_continue = s_padding_prev.clone() * padding_change.clone();

            // the byte on first padding is 128 (first bit is 1)
            let padding_byte_on_change =
                padding_change.clone() * (byte.clone() - Expression::Constant(Fr::from(128u64)));

            // constraint the padding byte, notice it in fact constraint the first byte of the final
            // 64-bit integer is 0, but it is ok (we have no so large bytes for 48-bit
            // integer)
            let padding_byte_is_zero = s_padding_prev * is_final.clone() * byte;

            let padding_change_on_size =
                meta.query_selector(self.s_padding_size) * is_final * padding_change;

            Constraints::with_selector(
                meta.query_selector(self.s_enable),
                vec![padding_is_bool, padding_continue, byte_counter_continue],
            )
            .into_iter()
            .chain(Constraints::with_selector(
                meta.query_selector(self.s_common_bytes),
                vec![padding_byte_is_zero, padding_byte_on_change],
            ))
            .chain(vec![padding_change_on_size.into()])
        });

        meta.create_gate("sha256 block final", |meta| {
            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());
            // final is decided by the begin row
            let final_continue =
                is_final.clone() - meta.query_advice(self.s_final_block, Rotation::prev());
            let final_is_bool = is_final.clone() * (one.clone() - is_final.clone());

            let byte = meta.query_advice(self.trans_byte, Rotation::cur());
            let padding_size = meta.query_advice(self.helper, Rotation::cur());
            let padding_size_prev = meta.query_advice(self.helper, Rotation::prev());

            let padding_size_calc = padding_size.clone()
                - (padding_size_prev * Expression::Constant(Fr::from(256u64)) + byte);
            let final_must_padded = (one.clone()
                - meta.query_advice(self.s_padding, Rotation::cur()))
                * is_final.clone();

            let padding_size_is_zero =
                meta.query_selector(self.s_common_bytes) * padding_size.clone();

            // final contintion: byte counter equal to padding size
            let final_condition = meta.query_selector(self.s_final)
                * (padding_size
                    - (meta.query_advice(self.byte_counter, Rotation::cur())
                        * Expression::Constant(Fr::from(8u64))))
                * is_final.clone();

            let u16 = meta.query_advice(self.copied_data, Rotation::cur());
            let u16_exported = meta.query_advice(self.copied_data, Rotation::next());
            let init_iv_u16 = meta.query_fixed(self.s_output, Rotation::cur());
            let is_not_final = one.clone() - is_final.clone();

            let select_exported = meta.query_selector(self.s_assigned_u16)
                * (u16_exported - is_final * u16 - is_not_final * init_iv_u16);

            Constraints::with_selector(
                meta.query_selector(self.s_enable),
                vec![final_continue, final_is_bool],
            )
            .into_iter()
            .chain(Constraints::with_selector(
                meta.query_selector(self.s_padding_size),
                vec![final_must_padded, padding_size_calc],
            ))
            .chain(vec![
                padding_size_is_zero.into(),
                final_condition.into(),
                select_exported.into(),
            ])
        });

        meta.create_gate("input block beginning", |meta| {
            // is *last block* final
            let is_final = meta.query_advice(self.s_final_block, Rotation::prev());
            let is_not_final = one.clone() - is_final.clone();

            let inherited_counter = meta.query_advice(self.byte_counter, Rotation::prev());
            let byte_counter = meta.query_advice(self.byte_counter, Rotation::cur());

            let applied_counter = is_not_final.clone() * (byte_counter.clone() - inherited_counter)
                + is_final.clone() * byte_counter;

            let inherited_bytes_rlc = meta.query_advice(self.bytes_rlc, Rotation::prev());
            let bytes_rlc = meta.query_advice(self.bytes_rlc, Rotation::prev());

            let applied_bytes_rlc = is_not_final.clone()
                * (bytes_rlc.clone() - inherited_bytes_rlc)
                + is_final.clone() * bytes_rlc;

            let inherited_s_padding = meta.query_advice(self.s_padding, Rotation::prev());
            let s_padding = meta.query_advice(self.s_padding, Rotation::prev());

            let applied_s_padding = is_not_final.clone()
                * (s_padding.clone() - inherited_s_padding.clone())
                + is_final * s_padding;

            let is_final = meta.query_advice(self.s_final_block, Rotation::cur());
            let final_is_bool = is_final.clone() * (one.clone() - is_final.clone());

            // notice now the 'is_final' point to current block and 'is_not_final' point to last
            // block (prev) this constraint make circuit can not make a full block is
            // padded but not final
            let enforce_final = is_not_final * inherited_s_padding * (one.clone() - is_final);

            Constraints::with_selector(
                meta.query_selector(self.s_enable),
                vec![
                    final_is_bool,
                    applied_counter,
                    applied_bytes_rlc,
                    applied_s_padding,
                    enforce_final,
                ],
            )
        });
    }

    /// Configures a circuit to include this chip.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        sha256_table: impl SHA256Table,
        spec_challenge: Expression<Fr>,
    ) -> Self {
        let table16 = Table16Chip::configure(meta);
        let helper = meta.advice_column();
        let trans_byte = meta.advice_column();

        let bytes_rlc = sha256_table.hashes_rlc();
        let copied_data = sha256_table.input_rlc();
        let s_output = sha256_table.s_enable();
        let s_final_block = sha256_table.is_effect();

        let s_padding_size = meta.selector();
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

        meta.lookup("byte range checking", |meta| {
            let byte = meta.query_advice(ret.trans_byte, Rotation::cur());
            vec![(byte, byte_range)]
        });

        ret.setup_gates(meta, spec_challenge);

        ret
    }

    fn assign_message_block<'vr>(
        &self,
        region: &mut Region<'_, Fr>,
        msgs: impl Iterator<Item = (&'vr AssignedBits<Fr, 16>, u16)>,
        mut bytes_rlc: AssignedCell<Fr, Fr>,
        chng: Value<Fr>,
        offset: usize,
        is_final: bool,
    ) -> Result<(Vec<AssignedBits<Fr, 16>>, AssignedCell<Fr, Fr>), Error> {
        let mut out_ret = Vec::new();
        let mut size_calc = Value::known(Fr::zero());

        for (i, (msg, ref_iv)) in msgs.enumerate() {
            self.s_assigned_u16.enable(region, i * 2)?;

            msg.copy_advice(
                || "copied message input",
                region,
                self.copied_data,
                i * 2 + offset,
            )?;
            let assigned = region.assign_advice(
                || "dummy message cell",
                self.copied_data,
                i * 2 + 1,
                || {
                    if is_final {
                        Value::known(Bits::from(ref_iv))
                    } else {
                        msg.value().map(Clone::clone)
                    }
                },
            )?;

            let bytes_hi = region.assign_advice(
                || "u16 message hi byte",
                self.trans_byte,
                i * 2,
                || msg.value().map(|v| Fr::from((u16::from(v) >> 8) as u64)),
            )?;

            let bytes_lo = region.assign_advice(
                || "u16 message lo byte",
                self.trans_byte,
                i * 2 + 1,
                || {
                    msg.value()
                        .map(|v| Fr::from((u16::from(v) & 255u16) as u64))
                },
            )?;

            for (j, byte_v) in [bytes_hi, bytes_lo].into_iter().enumerate() {
                bytes_rlc = region.assign_advice(
                    || "bytes rlc",
                    self.bytes_rlc,
                    i * 2 + j,
                    || chng * bytes_rlc.value() + byte_v.value(),
                )?;

                // here we have a trick, since digest region has only 16 messages instead 32
                size_calc = region
                    .assign_advice(
                        || "padding size calc",
                        self.helper,
                        i * 2 + j,
                        || {
                            if i < 28 {
                                size_calc
                            } else {
                                size_calc.map(|v| v * Fr::from(256u64)) + byte_v.value()
                            }
                        },
                    )?
                    .value()
                    .map(Clone::clone);
            }

            out_ret.push(AssignedBits(assigned));
        }

        Ok((out_ret, bytes_rlc))
    }

    fn initialize_block_head(
        &self,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<BlockInheritments, Error> {
        layouter.assign_region(
            || "initialize hasher",
            |mut region| {
                let s_final = region.assign_advice_from_constant(
                    || "init s_final",
                    self.s_final_block,
                    0,
                    Bits::from([false]),
                )?;
                let s_padding = region.assign_advice_from_constant(
                    || "init padding",
                    self.s_padding,
                    0,
                    Bits::from([false]),
                )?;
                let bytes_rlc = region.assign_advice_from_constant(
                    || "init bytes rlc",
                    self.bytes_rlc,
                    0,
                    Fr::zero(),
                )?;
                let byte_counter = region.assign_advice_from_constant(
                    || "init byte counter",
                    self.byte_counter,
                    0,
                    Fr::zero(),
                )?;

                Ok(BlockInheritments {
                    s_final: AssignedBits(s_final),
                    s_padding: AssignedBits(s_padding),
                    byte_counter,
                    bytes_rlc,
                })
            },
        )
    }

    fn assign_input_block(
        &self,
        layouter: &mut impl Layouter<Fr>,
        chng: Value<Fr>,
        prev_block: BlockInheritments,
        scheduled_msg: &[(AssignedBits<Fr, 16>, AssignedBits<Fr, 16>)],
        padding_pos: Option<i16>,
    ) -> Result<BlockInheritments, Error> {
        // if no padding or the padding is in padding size pos, this block is not final
        let is_final = if let Some(pos) = padding_pos {
            pos <= 24
        } else {
            false
        };

        let padding_pos = padding_pos.unwrap_or(32) as usize;

        layouter.assign_region(
            || "sha256 input",
            |mut region| {
                prev_block.s_final.copy_advice(
                    || "inheirt s_final",
                    &mut region,
                    self.s_final_block,
                    0,
                )?;
                prev_block.s_padding.copy_advice(
                    || "inheirt padding",
                    &mut region,
                    self.s_padding,
                    0,
                )?;
                prev_block.bytes_rlc.copy_advice(
                    || "inheirt bytes rlc",
                    &mut region,
                    self.bytes_rlc,
                    0,
                )?;
                prev_block.byte_counter.copy_advice(
                    || "inheirt byte counter",
                    &mut region,
                    self.byte_counter,
                    0,
                )?;

                self.s_begin.enable(&mut region, 1)?;
                region.assign_advice(
                    || "header final",
                    self.s_final_block,
                    1,
                    || Value::known(if is_final { Fr::one() } else { Fr::zero() }),
                )?;
                for (anno, col, ref_v) in [
                    (
                        "header padding",
                        self.s_padding,
                        prev_block
                            .s_padding
                            .value()
                            .map(|v| if v[0] { Fr::one() } else { Fr::zero() }),
                    ),
                    (
                        "header rlc",
                        self.bytes_rlc,
                        prev_block.bytes_rlc.value().map(Clone::clone),
                    ),
                    (
                        "header counter",
                        self.byte_counter,
                        prev_block.byte_counter.value().map(Clone::clone),
                    ),
                ] {
                    region.assign_advice(
                        || anno,
                        col,
                        1,
                        || {
                            prev_block
                                .s_final
                                .value()
                                .zip(ref_v)
                                .map(|(s_final, ref_v)| if s_final[0] { Fr::zero() } else { ref_v })
                        },
                    )?;
                }

                let header_offset = 2;
                let mut output_block = prev_block.clone();

                for row in header_offset..(header_offset + 64) {
                    self.s_enable.enable(&mut region, row)?;
                    region.assign_fixed(
                        || "flush s_output",
                        self.s_output,
                        row,
                        || Value::known(Fr::zero()),
                    )?;
                    output_block.s_padding.0 = region.assign_advice(
                        || "padding",
                        self.s_padding,
                        row,
                        || Value::known(Bits::from([row > padding_pos + header_offset])),
                    )?;
                    output_block.s_final.0 = region.assign_advice(
                        || "final",
                        self.s_final_block,
                        row,
                        || Value::known(Bits::from([is_final])),
                    )?;
                    output_block.byte_counter = region.assign_advice(
                        || "byte counter",
                        self.byte_counter,
                        row,
                        || output_block.byte_counter.value() + Value::known(Fr::one()),
                    )?;

                    if row < 56 + header_offset {
                        self.s_common_bytes.enable(&mut region, row)?;
                    } else {
                        self.s_padding_size.enable(&mut region, row)?;
                    }
                }
                self.s_final.enable(&mut region, 32 + header_offset)?;

                // assign message state
                let (_, out_rlc) = self.assign_message_block(
                    &mut region,
                    scheduled_msg
                        .iter()
                        .flat_map(|(hi, lo)| [hi, lo])
                        .zip(std::iter::repeat(0u16))
                        .take(32),
                    output_block.bytes_rlc.clone(),
                    chng,
                    header_offset,
                    is_final,
                )?;

                output_block.bytes_rlc = out_rlc;
                Ok(output_block)
            },
        )
    }

    fn assign_output_region(
        &self,
        layouter: &mut impl Layouter<Fr>,
        chng: Value<Fr>,
        state: &BlockState,
        input_block: &BlockInheritments,
        is_final: bool,
    ) -> Result<[(AssignedBits<Fr, 16>, AssignedBits<Fr, 16>); 8], Error> {
        const IV16: [u16; 16] = [
            0x6a09, 0xe667, 0xbb67, 0xae85, 0x3c6e, 0xf372, 0xa54f, 0xf53a, 0x510e, 0x527f, 0x9b05,
            0x688c, 0x1f83, 0xd9ab, 0x5be0, 0xcd19,
        ];

        let output_cells = layouter.assign_region(
            || "sha256 digest",
            |mut region| {
                let (a, b, c, d, e, f, g, h) = state.clone().decompose();

                let a = a.into_dense().decompose();
                let b = b.into_dense().decompose();
                let c = c.into_dense().decompose();
                let d = d.decompose();
                let e = e.into_dense().decompose();
                let f = f.into_dense().decompose();
                let g = g.into_dense().decompose();
                let h = h.decompose();

                input_block.s_final.copy_advice(
                    || "inheirt s_final",
                    &mut region,
                    self.s_final_block,
                    0,
                )?;
                region.assign_advice_from_constant(
                    || "header padding",
                    self.s_padding,
                    0,
                    Fr::one(),
                )?;
                region.assign_advice_from_constant(
                    || "header counter",
                    self.byte_counter,
                    0,
                    Fr::zero(),
                )?;
                let begin_rlc = region.assign_advice_from_constant(
                    || "header rlc",
                    self.bytes_rlc,
                    0,
                    Fr::zero(),
                )?;

                let header_offset = 1;

                for i in 0..32 {
                    let row = i + header_offset;
                    self.s_enable.enable(&mut region, row)?;
                    region.assign_fixed(
                        || "set s_output for init_iv",
                        self.s_output,
                        row,
                        || Value::known(Fr::from(IV16[i / 2] as u64)),
                    )?;
                    region.assign_advice(
                        || "dummy padding",
                        self.s_padding,
                        row,
                        || Value::known(Fr::one()),
                    )?;
                    region.assign_advice(
                        || "byte counter",
                        self.byte_counter,
                        row,
                        || Value::known(Fr::zero()),
                    )?;
                    region.assign_advice(
                        || "final",
                        self.s_final_block,
                        row,
                        || Value::known(Bits::from([is_final])),
                    )?;
                }

                // assign message state
                let (export_cells, digest_rlc) = self.assign_message_block(
                    &mut region,
                    [a, b, c, d, e, f, g, h]
                        .iter()
                        .flat_map(|(hi, lo)| [hi, lo])
                        .zip_eq(IV16),
                    begin_rlc,
                    chng,
                    header_offset,
                    is_final,
                )?;

                // build output row
                let final_row = header_offset + 32;
                region.assign_fixed(
                    || "mark s_output final",
                    self.s_output,
                    final_row,
                    || Value::known(Fr::one()),
                )?;
                digest_rlc.copy_advice(
                    || "copy digest rlc",
                    &mut region,
                    self.bytes_rlc,
                    final_row,
                )?;
                input_block.bytes_rlc.copy_advice(
                    || "copy input rlc",
                    &mut region,
                    self.copied_data,
                    final_row,
                )?;
                input_block.s_final.copy_advice(
                    || "copy final",
                    &mut region,
                    self.s_final_block,
                    final_row,
                )?;

                Ok(export_cells
                    .chunks_exact(2)
                    .map(|ck_pair| (ck_pair[0].clone(), ck_pair[1].clone()))
                    .collect::<Vec<_>>())
            },
        )?;

        Ok(output_cells.try_into().unwrap())
    }
}

/// sha256 hasher for byte stream
#[derive(Debug)]
pub struct Hasher {
    chip: CircuitConfig,
    state: [(AssignedBits<Fr, 16>, AssignedBits<Fr, 16>); 8],
    hasher_state: BlockInheritments,
    cur_block: Vec<u8>,
    length: usize,
    block_usage: usize,
}

impl Hasher {
    /// return the number of 512-bit blocks which has been assigned
    pub fn blocks(&self) -> usize {
        self.block_usage
    }

    /// return the number bytes current update, 0 indicate a clean status
    pub fn updated_size(&self) -> usize {
        self.length
    }

    /// create a hasher, the circuit would be identify when block_usage is the same
    pub fn new(chip: CircuitConfig, layouter: &mut impl Layouter<Fr>) -> Result<Self, Error> {
        let table16_chip = Table16Chip::construct::<Fr>(chip.table16.clone());
        let state = table16_chip.initialization_vector(layouter)?;
        let (a, b, c, d, e, f, g, h) = state.decompose();
        let state = [
            a.into_dense().decompose(),
            b.into_dense().decompose(),
            c.into_dense().decompose(),
            d.decompose(),
            e.into_dense().decompose(),
            f.into_dense().decompose(),
            g.into_dense().decompose(),
            h.decompose(),
        ];
        let hasher_state = chip.initialize_block_head(layouter)?;
        Ok(Self {
            chip,
            state,
            hasher_state,
            cur_block: Vec::with_capacity(BLOCK_SIZE * 4),
            length: 0,
            block_usage: 0,
        })
    }

    /// update a single 512-bit block into layouter
    fn update_block(
        &mut self,
        layouter: &mut impl Layouter<Fr>,
        chng: Value<Fr>,
        input: [BlockWord; BLOCK_SIZE],
        padding: Option<i16>,
        is_final: bool,
    ) -> Result<BlockState, Error> {
        let table16_cfg = &self.chip.table16;
        let w_halves = table16_cfg.message_process(layouter, input)?;
        self.hasher_state = self.chip.assign_input_block(
            layouter,
            chng,
            self.hasher_state.clone(),
            &w_halves[..16],
            padding,
        )?;
        let init_state = table16_cfg.initialize(layouter, self.state.clone().map(|v| v.into()))?;
        let compress_state = table16_cfg.compress(layouter, init_state, w_halves)?;
        self.state = self.chip.assign_output_region(
            layouter,
            chng,
            &compress_state,
            &self.hasher_state,
            is_final,
        )?;
        self.block_usage += 1;

        Ok(compress_state)
    }

    fn block_transform(bytes: &[u8]) -> Vec<BlockWord> {
        assert_eq!(bytes.len(), BLOCK_SIZE * 4);
        bytes
            .chunks_exact(4)
            .map(|bt| bt.iter().fold(0u32, |sum, v| sum * 2 + *v as u32))
            .map(Value::known)
            .map(BlockWord)
            .collect::<Vec<_>>()
    }

    /// Digest data, updating the internal state.
    pub fn update(
        &mut self,
        layouter: &mut impl Layouter<Fr>,
        chng: Value<Fr>,
        mut data: &[u8],
    ) -> Result<(), Error> {
        use std::cmp::min;

        self.length += data.len();

        // Fill the current block, if possible.
        let remaining = BLOCK_SIZE * 4 - self.cur_block.len();
        let (l, r) = data.split_at(min(remaining, data.len()));
        self.cur_block.extend_from_slice(l);
        data = r;

        // If we still don't have a full block, we are done.
        if self.cur_block.len() < BLOCK_SIZE * 4 {
            return Ok(());
        }

        // transform to word block
        let word_block = Self::block_transform(&self.cur_block);

        // Process the now-full current block.
        self.update_block(
            layouter,
            chng,
            word_block.as_slice().try_into().unwrap(),
            None,
            false,
        )?;

        self.cur_block.clear();

        // Process any additional full blocks.
        let mut chunks_iter = data.chunks_exact(BLOCK_SIZE * 4);
        for chunk in &mut chunks_iter {
            let word_block = Self::block_transform(chunk);
            self.update_block(
                layouter,
                chng,
                word_block.as_slice().try_into().unwrap(),
                None,
                false,
            )?;
        }

        // Cache the remaining partial block, if any.
        let rem = chunks_iter.remainder();
        self.cur_block.extend_from_slice(rem);

        Ok(())
    }

    /// generate the final digest and ready for new update.
    pub fn finalize(
        &mut self,
        layouter: &mut impl Layouter<Fr>,
        chng: Value<Fr>,
    ) -> Result<([BlockWord; crate::DIGEST_SIZE]), Error> {
        // check padding requirement
        let mut padding_pos = Some(self.cur_block.len() as i16);

        // of course we have at least 1 byte left (or cur_block would have been compressed)
        // push the additional 1bit
        self.cur_block.push(128);
        let remaining = BLOCK_SIZE * 4 - self.cur_block.len();

        // if we have no enough space (64bit)， we need a extra block
        if remaining < 8 {
            self.cur_block.resize(BLOCK_SIZE * 4, 0u8);
            let word_block = Self::block_transform(&self.cur_block);

            self.update_block(
                layouter,
                chng,
                word_block.as_slice().try_into().unwrap(),
                padding_pos,
                false,
            )?;

            padding_pos = Some(-1i16);
            self.cur_block.clear();
        }

        self.cur_block.resize(BLOCK_SIZE * 4 - 8, 0u8);
        self.cur_block.extend((self.length as u64).to_be_bytes());
        assert_eq!(self.cur_block.len(), BLOCK_SIZE * 4);

        let word_block = Self::block_transform(&self.cur_block);

        let digest_state = self.update_block(
            layouter,
            chng,
            word_block.as_slice().try_into().unwrap(),
            padding_pos,
            true,
        )?;
        self.cur_block.clear();

        let (a, b, c, d, e, f, g, h) = digest_state.decompose();
        Ok([
            a.into_dense().value(),
            b.into_dense().value(),
            c.into_dense().value(),
            d.value(),
            e.into_dense().value(),
            f.into_dense().value(),
            g.into_dense().value(),
            h.value(),
        ]
        .map(BlockWord))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};

    struct MyCircuit(Vec<Vec<u8>>);

    impl Circuit<Fr> for MyCircuit {
        type Config = CircuitConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
            struct DevTable {
                s_enable: Column<Fixed>,
                input_rlc: Column<Advice>,
                hashes_rlc: Column<Advice>,
                is_effect: Column<Advice>,
            }

            impl SHA256Table for DevTable {
                fn cols(&self) -> [Column<Any>; 4] {
                    [
                        self.s_enable.into(),
                        self.input_rlc.into(),
                        self.hashes_rlc.into(),
                        self.is_effect.into(),
                    ]
                }
            }

            let dev_table = DevTable {
                s_enable: meta.fixed_column(),
                input_rlc: meta.advice_column(),
                hashes_rlc: meta.advice_column(),
                is_effect: meta.advice_column(),
            };

            let chng = Expression::Constant(Fr::from(0x1000u64));
            Self::Config::configure(meta, dev_table, chng)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fr>,
        ) -> Result<(), Error> {
            let chng_v = Value::known(Fr::from(0x1000u64));
            let mut hasher = Hasher::new(config, &mut layouter)?;

            for input in &self.0 {
                hasher.update(&mut layouter, chng_v, input)?;
                let _ = hasher.finalize(&mut layouter, chng_v)?;
            }
            Ok(())
        }
    }

    #[test]
    fn sha256_simple() {
        let circuit = MyCircuit(vec![vec!['a' as u8, 'b' as u8, 'c' as u8]]);
        let prover = match MockProver::<Fr>::run(17, &circuit, vec![]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }
}
