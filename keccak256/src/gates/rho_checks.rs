//! Inner checks in the Rho step
//!
//! ## Overview
//!
//! In the Rho checks we convert each lane from base 13 to base 9.
//! We call the base 13 lane the input and the base 9 lane the output.
//! We can view the lane as a polynomial
//! - where the input lane is `A(13) =  a0 13^0 + ... + a64 13^64`, and
//! - the output lane is  `B(9)  =  b0  9^0 + ... + b63  9^63`
//!
//! We call the a coefficient of the polynomial a chunk.
//!
//! The output chunks represent the output bits of the lane in binary, where b0
//! is the least significant bit and b63 is the most significant bit.
//!
//! Note that the input lane is special because it's an output from the Theta
//! step, so it has 65 chunks. It holds that `0 <= a0 + a64 < 13`. We refer a0
//! to be low value and a64 high value.
//!
//! In the Rho step we perform the **rotation** of chunk positions and the
//! **convertion** from base 13 to base 9.
//!
//! More formally speaking, we have a transform `T`, where `bi = T(aj)` for some
//! `i`, `j`, and `ai` is not special chunks.
//! For special chunk, `bi = T(a0 + a64)`.
//!
//! - The rotate means we perform the rotate left of the rotation specified in
//!   `ROTATION_CONSTANTS`. Say if our rotation is 3,
//! The a1 will be contribute to b3, and a63 will go to b0.
//!
//! The convert `T` is the [`crate::arith_helpers::convert_b13_coef`], in the
//! circuit we have to do a lookup check for that
//!
//! The lookup is more efficient when we lookup
//! multiple([`crate::gates::rho_helpers::BASE_NUM_OF_CHUNKS`]) chunks at a
//! time.
//!
//! ## Checks
//!
//! The goal is to check the conversion from the base 13 input lane to the base
//! 9 output lane is sound.
//!
//! ### The Essential
//!
//! For each lane, we split up the lane in slices of chunks.
//! - We run down the input accumulator by subtracting each `input_coef *
//!   power_of_13`
//! - We run up the output accumulator by adding up `output_coef * power_of_9`
//! - We lookup [`crate::gates::tables::Base13toBase9TableConfig`] and check the
//!   conversion between `input_coef` and `output_coef` is valid
//!
//! We have the copy constraint to glue input accumulator to input lane and the
//! output accumulator to output lane
//!
//! But we have special checks to do
//!
//! ### Sepcial Chunks
//!
//! The Theta step shifted left 1 chunk. So the base 13 input lane now has 65
//! chunks, where the 0th and the 64th input chunks contribute to the same
//! output chunk. We call the 0th input chunk the `low_value` and the 64th input
//! chunk the `high_value`. A the end of the running down input accumulator, the
//! remaining value is `low_value + high_value * 13**64` We lookup [`crate::
//! gates::tables::SpecialChunkTableConfig`] to convert it to
//! `convert_b13_coef(low_value + high_value)`.
//!
//! ### Overflow Checks
//!
//! The [`crate::gates::tables::Base13toBase9TableConfig`] table is built to
//! lookup 4 chunks. But we have chunks that are step 1, step 2, and step 3,
//! which means they suppose to have the last 1, 2, or 3 chunks to be 0.
//! If a step 1 step is witnessed with 2, 3, or 4 non-zero input chunks, then
//! it's a malicious overflow and we have to provent the prover from doing that.
//!
//! Doing range check for each of non-4chunks steps would be inefficient,
//! instead we use the following technique.
//!
//! We define the [`crate::gates::rho_helpers::OVERFLOW_TRANSFORM`] to map
//! `step` to a value `block_count`. We also add a column in
//! [`crate::gates::tables::Base13toBase9TableConfig`] to lookup `block_count`.
//! We sum up all the block_counts across 25 lanes, for each step 1, step 2, and
//! step 3. At the end of the Rho step we perform the final block count range
//! check in [`BlockCountFinalConfig`].
//!
//! The `OVERFLOW_TRANSFORM` maps step 1 to 0, step 2 to 1, step 3 to 13, and
//! step 4 to 170. It is defined that any possible overflow would result the
//! final block count check to fail.
//!
//! It would be better explained if we enumerate all the possible cases:
//!
//! The sum of the step 1 should be 0.
//! So that if prover witness any more than 1 non-zero chunks, the
//! [`crate::gates::tables::Base13toBase9TableConfig`] returns a block count 1,
//! 13, or 170 and fail the final sum check.
//!
//! The sum of the step 2 should be less than or equal to 1 times all numbers of
//! step 2, which can be counted at setup time to be 12. So that if prover
//! witness any more than 2 non-zero chunks, the
//! [`crate::gates::tables::Base13toBase9TableConfig`] returns a block count 13
//! or 170 and fail the final sum check.
//!
//! The sum of the step 3 should be less than or equal to 13 times all numbers
//! of step 3, which can be counted at setup time to be 13. So that if prover
//! witness any more than 3 non-zero chunks, the
//! [`crate::gates::tables::Base13toBase9TableConfig`] returns a block count 170
//! and fail the final sum check.
use crate::arith_helpers::*;
use crate::common::{LANE_SIZE, ROTATION_CONSTANTS};
use crate::gates::{
    gate_helpers::*,
    rho_helpers::*,
    tables::{Base13toBase9TableConfig, SpecialChunkTableConfig},
};
use halo2::{
    circuit::{Cell, Layouter, Region},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Selector,
        TableColumn,
    },
    poly::Rotation,
};
use pairing::arithmetic::FieldExt;
use std::iter;
use std::marker::PhantomData;

#[derive(Debug, Clone)]
struct RunningSumAdvices {
    coef: Column<Advice>,
    acc: Column<Advice>,
}
#[derive(Debug, Clone)]
pub struct BlockCountAdvices {
    block_count: Column<Advice>,
    step2_acc: Column<Advice>,
    step3_acc: Column<Advice>,
}

#[derive(Debug, Clone)]
pub struct RhoAdvices {
    input: RunningSumAdvices,
    output: RunningSumAdvices,
    bc: BlockCountAdvices,
}

impl From<[Column<Advice>; 7]> for RhoAdvices {
    fn from(cols: [Column<Advice>; 7]) -> Self {
        let input = RunningSumAdvices {
            coef: cols[0],
            acc: cols[1],
        };
        let output = RunningSumAdvices {
            coef: cols[2],
            acc: cols[3],
        };
        let bc = BlockCountAdvices {
            block_count: cols[4],
            step2_acc: cols[5],
            step3_acc: cols[6],
        };
        Self { input, output, bc }
    }
}

#[derive(Debug, Clone)]
pub struct LaneRotateConversionConfig<F> {
    adv: RhoAdvices,
    chunk_rotate_convert_configs: Vec<ChunkRotateConversionConfig<F>>,
    special_chunk_config: SpecialChunkConfig<F>,
    lane_xy: (usize, usize),
    rotation: u32,
}

impl<F: FieldExt> LaneRotateConversionConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lane_xy: (usize, usize),
        adv: RhoAdvices,
        axiliary: [Column<Advice>; 2],
        base13_to_9: [TableColumn; 3],
        special: [TableColumn; 2],
    ) -> Self {
        meta.enable_equality(adv.input.acc.into());
        meta.enable_equality(adv.output.acc.into());
        let q_is_special = meta.complex_selector();
        let rotation = ROTATION_CONSTANTS[lane_xy.0][lane_xy.1];
        let slices = slice_lane(rotation);
        let chunk_rotate_convert_configs = slices
            .iter()
            .map(|(chunk_idx, step)| {
                ChunkRotateConversionConfig::configure(
                    meta,
                    adv.clone(),
                    base13_to_9,
                    *chunk_idx,
                    rotation,
                    *step,
                )
            })
            .collect::<Vec<_>>();
        let special_chunk_config = SpecialChunkConfig::configure(
            meta,
            q_is_special,
            adv.input.acc,
            adv.output.acc,
            axiliary[0],
            special,
            rotation as u64,
        );

        Self {
            adv,
            chunk_rotate_convert_configs,
            special_chunk_config,
            lane_xy,
            rotation,
        }
    }
    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        lane_base_13: (Cell, F),
    ) -> Result<((Cell, F), BlockCount2<F>), Error> {
        let (lane, block_counts) = layouter.assign_region(
            || format!("LRCC {:?}", self.lane_xy),
            |mut region| {
                let mut offset = 0;
                let cell = region.assign_advice(
                    || "base_13_col",
                    self.adv.input.acc,
                    offset,
                    || Ok(lane_base_13.1),
                )?;
                region.constrain_equal(lane_base_13.0, cell)?;

                let (conversions, special) =
                    RhoLane::new(f_to_biguint(lane_base_13.1), self.rotation)
                        .get_full_witness();

                let all_block_counts: Result<Vec<BlockCount2<F>>, Error> = self
                    .chunk_rotate_convert_configs
                    .iter()
                    .zip(conversions.iter())
                    .map(|(config, conv)| {
                        let block_counts =
                            config.assign_region(&mut region, offset, conv)?;
                        offset += 1;
                        Ok(block_counts)
                    })
                    .collect();
                let all_block_counts = all_block_counts?;
                let block_counts =
                    all_block_counts.last().ok_or(Error::Synthesis)?;
                let lane = self.special_chunk_config.assign_region(
                    &mut region,
                    offset,
                    special,
                )?;
                Ok((lane, *block_counts))
            },
        )?;
        Ok((lane, block_counts))
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.chunk_rotate_convert_configs[0]
            .base_13_to_base_9_lookup
            .load(layouter)?;
        self.special_chunk_config
            .special_chunk_table_config
            .load(layouter)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ChunkRotateConversionConfig<F> {
    q_enable: Selector,
    q_is_first: Selector,
    adv: RhoAdvices,
    power_of_b13: F,
    power_of_b9: F,
    base_13_to_base_9_lookup: Base13toBase9TableConfig<F>,
    block_count_acc_config: BlockCountAccConfig<F>,
    chunk_idx: u32,
}

impl<F: FieldExt> ChunkRotateConversionConfig<F> {
    fn configure(
        meta: &mut ConstraintSystem<F>,
        adv: RhoAdvices,
        fix_cols: [TableColumn; 3],
        chunk_idx: u32,
        rotation: u32,
        step: u32,
    ) -> Self {
        let q_enable = meta.complex_selector();
        let q_is_first = meta.complex_selector();
        let base_13_to_base_9_lookup = Base13toBase9TableConfig::configure(
            meta,
            q_enable,
            adv.input.coef,
            adv.output.coef,
            adv.bc.block_count,
            fix_cols,
        );

        let power_of_b13 =
            F::from(B13.into()).pow(&[chunk_idx.into(), 0, 0, 0]);

        // | coef | 13**x | acc       |
        // |------|-------|-----------|
        // |  a   |  b    | c         |
        // |  ... | ...   | c - a * b |
        meta.create_gate("Running down input", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let coef = meta.query_advice(adv.input.coef, Rotation::cur());
            let power_of_base = Expression::Constant(power_of_b13);
            let acc = meta.query_advice(adv.input.acc, Rotation::cur());
            let acc_next = meta.query_advice(adv.input.acc, Rotation::next());
            // We assumed the first acc is enforced by the copy constraint
            // so no need to add is_first check constraint here
            vec![(
                "delta_acc === - coef * power_of_base", /* running down for
                                                         * input */
                q_enable * (acc_next - acc + coef * power_of_base),
            )]
        });
        let power_of_b9 = F::from(B9.into()).pow(&[
            ((rotation + chunk_idx) % LANE_SIZE).into(),
            0,
            0,
            0,
        ]);
        // | coef | 9**x  |    acc |
        // |------|-------|--------|
        // |  a   |  b    |      0 |
        // |  ... | ...   |  a * b |
        meta.create_gate("Running up for output", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let q_is_first = meta.query_selector(q_is_first);
            let coef = meta.query_advice(adv.output.coef, Rotation::cur());
            let power_of_base = Expression::Constant(power_of_b9);
            let acc = meta.query_advice(adv.output.acc, Rotation::cur());
            let acc_next = meta.query_advice(adv.output.acc, Rotation::next());
            vec![
                (
                    "delta_acc === coef * power_of_base", /* running up for
                                                           * output */
                    q_enable * (acc_next - acc.clone() - coef * power_of_base),
                ),
                ("first acc to be 0", q_is_first * acc),
            ]
        });

        let block_count_acc_config = BlockCountAccConfig::configure(
            meta,
            q_enable,
            adv.bc.clone(),
            step,
        );

        Self {
            q_enable,
            q_is_first,
            adv,
            power_of_b13,
            power_of_b9,
            base_13_to_base_9_lookup,
            block_count_acc_config,
            chunk_idx,
        }
    }

    fn assign_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        conv: &Conversion,
    ) -> Result<BlockCount2<F>, Error> {
        assert_eq!(
            biguint_to_f::<F>(&conv.input.power_of_base),
            self.power_of_b13
        );
        assert_eq!(
            biguint_to_f::<F>(&conv.output.power_of_base),
            self.power_of_b9
        );
        self.q_enable.enable(region, offset)?;
        if offset == 0 {
            self.q_is_first.enable(region, 0)?;
        }
        region.assign_advice(
            || format!("Input Coef {}", self.chunk_idx),
            self.adv.input.coef,
            offset,
            || Ok(biguint_to_f::<F>(&conv.input.coef)),
        )?;
        region.assign_advice(
            || "Input accumulator",
            self.adv.input.acc,
            offset,
            || Ok(biguint_to_f::<F>(&conv.input.pre_acc)),
        )?;
        region.assign_advice(
            || "Output Coef",
            self.adv.output.coef,
            offset,
            || Ok(biguint_to_f::<F>(&conv.output.coef)),
        )?;
        region.assign_advice(
            || "Output accumulator",
            self.adv.output.acc,
            offset,
            || Ok(biguint_to_f::<F>(&conv.output.pre_acc)),
        )?;
        let block_counts = self.block_count_acc_config.assign_region(
            region,
            offset,
            &conv.overflow_detector,
        )?;
        Ok(block_counts)
    }
}

#[derive(Debug, Clone)]
pub struct SpecialChunkConfig<F> {
    q_enable: Selector,
    last_b9_coef: Column<Advice>,
    base_13_acc: Column<Advice>,
    base_9_acc: Column<Advice>,
    special_chunk_table_config: SpecialChunkTableConfig<F>,
}

impl<F: FieldExt> SpecialChunkConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: Selector,
        base_13_acc: Column<Advice>,
        base_9_acc: Column<Advice>,
        last_b9_coef: Column<Advice>,
        special: [TableColumn; 2],
        rotation: u64,
    ) -> Self {
        meta.create_gate("validate base_9_acc", |meta| {
            let delta_base_9_acc = meta
                .query_advice(base_9_acc, Rotation::next())
                - meta.query_advice(base_9_acc, Rotation::cur());
            let last_b9_coef = meta.query_advice(last_b9_coef, Rotation::cur());
            let pow_of_9 = Expression::Constant(
                F::from(B9.into()).pow(&[rotation, 0, 0, 0]),
            );
            vec![(
                "delta_base_9_acc === (high_value + low_value) * 9**rotation",
                meta.query_selector(q_enable)
                    * (delta_base_9_acc - last_b9_coef * pow_of_9),
            )]
        });
        let special_chunk_table_config = SpecialChunkTableConfig::configure(
            meta,
            q_enable,
            base_13_acc,
            last_b9_coef,
            special,
        );
        Self {
            q_enable,
            last_b9_coef,
            base_13_acc,
            base_9_acc,
            special_chunk_table_config,
        }
    }
    fn assign_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        special: Special,
    ) -> Result<(Cell, F), Error> {
        self.q_enable.enable(region, offset)?;
        region.assign_advice(
            || "input_acc",
            self.base_13_acc,
            offset,
            || Ok(biguint_to_f::<F>(&special.input)),
        )?;
        region.assign_advice(
            || "ouput_acc",
            self.base_9_acc,
            offset,
            || Ok(biguint_to_f::<F>(&special.output_acc_pre)),
        )?;
        region.assign_advice(
            || "last_b9_coef",
            self.last_b9_coef,
            offset,
            || Ok(F::from(special.output_coef as u64)),
        )?;
        region.assign_advice(
            || "input_acc",
            self.base_13_acc,
            offset + 1,
            || Ok(F::zero()),
        )?;
        let value = biguint_to_f::<F>(&special.output_acc_post);
        let cell = region.assign_advice(
            || "input_acc",
            self.base_9_acc,
            offset + 1,
            || Ok(value),
        )?;

        Ok((cell, value))
    }
}

/// Gates to check if block counts are accumulated correctly
#[derive(Debug, Clone)]
pub struct BlockCountAccConfig<F> {
    bc: BlockCountAdvices,
    step: u32,
    q_first: Selector,
    q_rest: Selector,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> BlockCountAccConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_all: Selector,
        bc: BlockCountAdvices,
        step: u32,
    ) -> Self {
        let q_first = meta.complex_selector();
        let q_rest = meta.complex_selector();
        if step == 1 {
            meta.create_gate("block count step 1", |meta| {
                let q_all = meta.query_selector(q_all);
                let block_count =
                    meta.query_advice(bc.block_count, Rotation::cur());
                vec![("block_count === 0", q_all * block_count)]
            });
        }
        meta.create_gate("first row", |meta| {
            let q_first = meta.query_selector(q_first);
            let block_count =
                meta.query_advice(bc.block_count, Rotation::cur());
            let step2_acc = meta.query_advice(bc.step2_acc, Rotation::cur());
            let step3_acc = meta.query_advice(bc.step3_acc, Rotation::cur());
            vec![match step {
                2 => (
                    "first step2_acc === block_count",
                    q_first * (step2_acc - block_count),
                ),
                3 => (
                    "first step3_acc === block_count",
                    q_first * (step3_acc - block_count),
                ),
                1 | 4 => ("1 or 4", Expression::Constant(F::zero())),
                _ => unreachable!(),
            }]
        });

        meta.create_gate("Running up block count", |meta| {
            let q_rest = meta.query_selector(q_rest);
            let block_count =
                meta.query_advice(bc.block_count, Rotation::cur());
            let step2_acc = meta.query_advice(bc.step2_acc, Rotation::cur());
            let step2_acc_prev =
                meta.query_advice(bc.step2_acc, Rotation::prev());
            let step3_acc = meta.query_advice(bc.step3_acc, Rotation::cur());
            let step3_acc_prev =
                meta.query_advice(bc.step3_acc, Rotation::prev());

            let step2_poly = {
                if step == 2 {
                    (
                        "delta_step2 === block_count",
                        step2_acc - step2_acc_prev - block_count.clone(),
                    )
                } else {
                    ("delta_step2 === 0", step2_acc - step2_acc_prev)
                }
            };
            let step3_poly = {
                if step == 3 {
                    (
                        "delta_step3 === block_count",
                        step3_acc - step3_acc_prev - block_count,
                    )
                } else {
                    ("delta_step3 === 0", step3_acc - step3_acc_prev)
                }
            };

            vec![step2_poly, step3_poly]
                .iter()
                .map(|(name, poly)| (*name, q_rest.clone() * poly.clone()))
                .collect::<Vec<_>>()
        });

        Self {
            bc,
            step,
            q_first,
            q_rest,
            _marker: PhantomData,
        }
    }

    pub fn assign_region(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        ofdet: &OverflowDetector,
    ) -> Result<BlockCount2<F>, Error> {
        if offset == 0 {
            self.q_first.enable(region, 0)?;
        } else {
            self.q_rest.enable(region, offset)?;
        }
        region.assign_advice(
            || format!("block count step{}", self.step),
            self.bc.block_count,
            offset,
            || Ok(F::from(ofdet.block_count.into())),
        )?;
        let step2 = {
            let value = F::from(ofdet.step2_acc.into());
            let cell = region.assign_advice(
                || "step 2 bc acc",
                self.bc.step2_acc,
                offset,
                || Ok(value),
            )?;
            BlockCount { cell, value }
        };
        let step3 = {
            let value = F::from(ofdet.step3_acc.into());
            let cell = region.assign_advice(
                || "step 3 bc acc",
                self.bc.step3_acc,
                offset,
                || Ok(value),
            )?;
            BlockCount { cell, value }
        };
        Ok((step2, step3))
    }
}

#[derive(Debug, Clone)]
pub struct BlockCountFinalConfig<F> {
    q_enable: Selector,
    block_count_cols: [Column<Advice>; 2],
    _marker: PhantomData<F>,
}
impl<F: FieldExt> BlockCountFinalConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        block_count_cols: [Column<Advice>; 2],
    ) -> Self {
        let q_enable = meta.complex_selector();
        for column in block_count_cols.iter() {
            meta.enable_equality((*column).into());
        }

        meta.create_gate("block count final check", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let step2_acc =
                meta.query_advice(block_count_cols[0], Rotation::cur());
            let step3_acc =
                meta.query_advice(block_count_cols[1], Rotation::cur());
            let one = Expression::Constant(F::one());
            iter::empty()
                .chain(Some((
                    "step2_acc <= 12",
                    (0..=STEP2_RANGE)
                        .map(|x| {
                            step2_acc.clone() - Expression::Constant(F::from(x))
                        })
                        .fold(one.clone(), |acc, x| acc * x),
                )))
                .chain(Some((
                    "step3_acc <= 13 * 13",
                    (0..=STEP3_RANGE)
                        .map(|x| {
                            step3_acc.clone() - Expression::Constant(F::from(x))
                        })
                        .fold(one, |acc, x| acc * x),
                )))
                .map(|(name, poly)| (name, q_enable.clone() * poly))
                .collect::<Vec<_>>()
        });

        Self {
            q_enable,
            block_count_cols,
            _marker: PhantomData,
        }
    }
    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        block_count_cells: [BlockCount2<F>; 25],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "final block count",
            |mut region| {
                for (offset, bc) in block_count_cells.iter().enumerate() {
                    self.q_enable.enable(&mut region, offset)?;
                    let cell_1 = region.assign_advice(
                        || format!("block_count step2 acc lane {}", offset),
                        self.block_count_cols[0],
                        offset,
                        || Ok(bc.0.value),
                    )?;
                    region.constrain_equal(cell_1, bc.0.cell)?;
                    let cell_2 = region.assign_advice(
                        || format!("block_count step3 acc lane {}", offset),
                        self.block_count_cols[1],
                        offset,
                        || Ok(bc.1.value),
                    )?;
                    region.constrain_equal(cell_2, bc.1.cell)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
