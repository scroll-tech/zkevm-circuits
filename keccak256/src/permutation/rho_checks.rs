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
//! The output chunks represent the output bits of the lane in binary, in little
//! endian.
//!
//! Note that the input lane is special because it's an output from the Theta
//! step, so it has 65 chunks. It holds that `0 <= a0 + a64 < 13`. We refer a0
//! to be low value and a64 high value.
//!
//! In the Rho step we perform the **rotation** of chunk positions and the
//! **conversion** from base 13 to base 9.
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
//! multiple([`crate::permutation::rho_helpers::BASE_NUM_OF_CHUNKS`]) chunks at
//! a time.
//!
//! ## Checks
//!
//! The goal is to check the conversion from the base 13 input lane to the base
//! 9 output lane is sound.
//!
//! ### The Normal Slices
//!
//! For each lane, we split up the lane in slices of chunks.
//! - We run down the input accumulator by subtracting each `input_coef *
//!   power_of_13`
//! - We run up the output accumulator by adding up `output_coef * power_of_9`
//! - We lookup [`crate::permutation::tables::Base13toBase9TableConfig`] and
//!   check the conversion between `input_coef` and `output_coef` is valid
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
//! permutation::tables::SpecialChunkTableConfig`] to convert it to
//! `convert_b13_coef(low_value + high_value)`.
//!
//! ### Overflow Checks
//!
//! The [`crate::permutation::tables::Base13toBase9TableConfig`] table is built
//! to lookup 4 chunks. But we have chunks that are step 1, step 2, and step 3,
//! which means they suppose to have the last 1, 2, or 3 chunks to be 0.
//! If a step 1 step is witnessed with 2, 3, or 4 non-zero input chunks, then
//! it's a malicious overflow and we have to provent the prover from doing that.
//!
//! Doing range check for each of non-4chunks steps would be inefficient,
//! instead we use the following technique.
//!
//! We define the [`crate::permutation::rho_helpers::OVERFLOW_TRANSFORM`] to map
//! `step` to a value `overflow_detector`. We also add a column in
//! [`crate::permutation::tables::Base13toBase9TableConfig`] to lookup
//! `overflow_detector`. We sum up all the overflow_detectors across 25 lanes,
//! for each step 1, step 2, and step 3. At the end of the Rho step we perform
//! the final overflow detector range check in [`OverflowCheckConfig`].
//!
//! The `OVERFLOW_TRANSFORM` maps step 1 to 0, step 2 to 1, step 3 to 13, and
//! step 4 to 170. It is defined that any possible overflow would result the
//! final overflow detector check to fail.
//!
//! It would be better explained if we enumerate all the possible cases:
//!
//! The sum of the step 1 should be 0.
//! So that if prover witness any more than 1 non-zero chunks, the
//! [`crate::permutation::tables::Base13toBase9TableConfig`] returns a overflow
//! detector 1, 13, or 170 and fail the final sum check.
//!
//! The sum of the step 2 should be less than or equal to 1 times all numbers of
//! step 2, which can be counted at setup time to be 12. So that if prover
//! witness any more than 2 non-zero chunks, the
//! [`crate::permutation::tables::Base13toBase9TableConfig`] returns a overflow
//! detector 13 or 170 and fail the final sum check.
//!
//! The sum of the step 3 should be less than or equal to 13 times all numbers
//! of step 3, which can be counted at setup time to be 13. So that if prover
//! witness any more than 3 non-zero chunks, the
//! [`crate::permutation::tables::Base13toBase9TableConfig`] returns a overflow
//! detector 170 and fail the final sum check.
use crate::arith_helpers::*;
use crate::common::ROTATION_CONSTANTS;
use crate::gate_helpers::{biguint_to_f, f_to_biguint};
use crate::permutation::{
    rho_helpers::*,
    tables::{Base13toBase9TableConfig, RangeCheckConfig, SpecialChunkTableConfig},
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct LaneRotateConversionConfig<F> {
    rotation: u32,
    lane_idx: usize,
    q_normal: Selector,
    q_special: Selector,
    input_coef: Column<Advice>,
    input_pob: Column<Fixed>,
    input_acc: Column<Advice>,
    output_coef: Column<Advice>,
    output_pob: Column<Fixed>,
    output_acc: Column<Advice>,
    pub overflow_detector: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: Field> LaneRotateConversionConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        lane_idx: usize,
        lane: Column<Advice>,
        base13_to_9_table: &Base13toBase9TableConfig<F>,
        special_chunk_table: &SpecialChunkTableConfig<F>,
    ) -> Self {
        meta.enable_equality(lane);
        let rotation = {
            let x = lane_idx / 5;
            let y = lane_idx % 5;
            ROTATION_CONSTANTS[x][y]
        };

        let q_normal = meta.complex_selector();
        let q_special = meta.complex_selector();
        let input_coef = meta.advice_column();
        let input_pob = meta.fixed_column();
        let input_acc = meta.advice_column();
        let output_coef = meta.advice_column();
        let output_pob = meta.fixed_column();
        let output_acc = meta.advice_column();
        let overflow_detector = meta.advice_column();

        let constant = meta.fixed_column();
        meta.enable_constant(constant);

        meta.enable_equality(input_acc);
        meta.enable_equality(output_acc);
        meta.enable_equality(overflow_detector);

        // | coef | 13**x | acc       |
        // |------|-------|-----------|
        // |  a   |  b    | c         |
        // |  ... | ...   | c - a * b |
        meta.create_gate("Running down input", |meta| {
            let q_normal = meta.query_selector(q_normal);
            let coef = meta.query_advice(input_coef, Rotation::cur());
            let pob = meta.query_fixed(input_pob, Rotation::cur());
            let acc = meta.query_advice(input_acc, Rotation::cur());
            let acc_next = meta.query_advice(input_acc, Rotation::next());
            vec![(
                "delta_acc === - coef * power_of_base",
                q_normal * (acc_next - acc + coef * pob),
            )]
        });
        // | coef | 9**x  |    acc |
        // |------|-------|--------|
        // |  a   |  b    |      0 |
        // |  ... | ...   |  a * b |
        meta.create_gate("Running up for output", |meta| {
            let q_normal = meta.query_selector(q_normal);
            let q_special = meta.query_selector(q_special);
            let coef = meta.query_advice(output_coef, Rotation::cur());
            let pob = meta.query_fixed(output_pob, Rotation::cur());
            let acc = meta.query_advice(output_acc, Rotation::cur());
            let acc_next = meta.query_advice(output_acc, Rotation::next());
            // delta_acc === coef * power_of_base
            let poly = acc_next - acc - coef * pob;
            vec![
                ("check for q_normal", q_normal * poly.clone()),
                ("check for q_special", q_special * poly),
            ]
        });

        meta.lookup("b13 -> b9 table", |meta| {
            let q_normal = meta.query_selector(q_normal);
            let base13_coef = meta.query_advice(input_coef, Rotation::cur());
            let base9_coef = meta.query_advice(output_coef, Rotation::cur());
            let od = meta.query_advice(overflow_detector, Rotation::cur());

            vec![
                (q_normal.clone() * base13_coef, base13_to_9_table.base13),
                (q_normal.clone() * base9_coef, base13_to_9_table.base9),
                (q_normal * od, base13_to_9_table.overflow_detector),
            ]
        });

        meta.lookup("special chunk", |meta| {
            let q_special = meta.query_selector(q_special);
            let input_acc = meta.query_advice(input_acc, Rotation::cur());
            let output_coef = meta.query_advice(output_coef, Rotation::cur());

            vec![
                (
                    q_special.clone() * input_acc,
                    special_chunk_table.last_chunk,
                ),
                (q_special * output_coef, special_chunk_table.output_coef),
            ]
        });
        Self {
            rotation,
            lane_idx,
            q_normal,
            q_special,
            input_coef,
            input_pob,
            input_acc,
            output_coef,
            output_pob,
            output_acc,
            overflow_detector,
            _marker: PhantomData,
        }
    }

    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        lane_base_13: AssignedCell<F, F>,
    ) -> Result<
        (
            AssignedCell<F, F>,
            Vec<AssignedCell<F, F>>,
            Vec<AssignedCell<F, F>>,
        ),
        Error,
    > {
        let (conversions, special) = RhoLane::new(
            f_to_biguint(*lane_base_13.value().unwrap_or(&F::zero())),
            self.rotation,
        )
        .get_full_witness();
        layouter.assign_region(
            || "lane rotate conversion",
            |mut region| {
                let slices = slice_lane(self.rotation);
                let (step2_od, step3_od) = {
                    let mut step2_od: Vec<AssignedCell<F, F>> = vec![];
                    let mut step3_od: Vec<AssignedCell<F, F>> = vec![];
                    for (offset, (&(chunk_idx, step), conv)) in
                        slices.iter().zip(conversions.iter()).enumerate()
                    {
                        self.q_normal.enable(&mut region, offset)?;
                        region.assign_advice(
                            || format!("Input Coef {}", chunk_idx),
                            self.input_coef,
                            offset,
                            || Ok(biguint_to_f::<F>(&conv.input.coef)),
                        )?;
                        region.assign_fixed(
                            || "Input power of base",
                            self.input_pob,
                            offset,
                            || Ok(biguint_to_f::<F>(&conv.input.power_of_base)),
                        )?;
                        {
                            let cell = region
                                .assign_advice(
                                    || "Input accumulator",
                                    self.input_acc,
                                    offset,
                                    || Ok(biguint_to_f::<F>(&conv.input.pre_acc)),
                                )?
                                .cell();
                            if offset == 0 {
                                region.constrain_equal(lane_base_13.cell(), cell)?;
                            }
                        }
                        region.assign_advice(
                            || "Output Coef",
                            self.output_coef,
                            offset,
                            || Ok(biguint_to_f::<F>(&conv.output.coef)),
                        )?;
                        region.assign_fixed(
                            || "Output power of base",
                            self.output_pob,
                            offset,
                            || Ok(biguint_to_f::<F>(&conv.output.power_of_base)),
                        )?;
                        {
                            let cell = region
                                .assign_advice(
                                    || "Output accumulator",
                                    self.output_acc,
                                    offset,
                                    || Ok(biguint_to_f::<F>(&conv.output.pre_acc)),
                                )?
                                .cell();
                            if offset == 0 {
                                region.constrain_constant(cell, F::zero())?;
                            }
                        }
                        let od = {
                            let value = F::from(conv.overflow_detector.value as u64);
                            let od = region.assign_advice(
                                || "Overflow detector",
                                self.overflow_detector,
                                offset,
                                || Ok(value),
                            )?;
                            if step == 1 {
                                region.constrain_constant(od.cell(), F::zero())?;
                            }
                            od
                        };
                        match step {
                            2 => step2_od.push(od),
                            3 => step3_od.push(od),
                            _ => {}
                        }
                    }
                    (step2_od, step3_od)
                };
                // special chunks
                let output_lane = {
                    let offset = slices.len();
                    self.q_special.enable(&mut region, offset)?;
                    region.assign_advice(
                        || "Special Input acc",
                        self.input_acc,
                        offset,
                        || Ok(biguint_to_f::<F>(&special.input)),
                    )?;
                    region.assign_advice(
                        || "Special output coef",
                        self.output_coef,
                        offset,
                        || Ok(F::from(special.output_coef as u64)),
                    )?;
                    region.assign_fixed(
                        || "Special output power of base",
                        self.output_pob,
                        offset,
                        || Ok(F::from(B9 as u64).pow(&[self.rotation.into(), 0, 0, 0])),
                    )?;
                    region.assign_advice(
                        || "Special output acc pre",
                        self.output_acc,
                        offset,
                        || Ok(biguint_to_f::<F>(&special.output_acc_pre)),
                    )?;
                    {
                        let value = biguint_to_f::<F>(&special.output_acc_post);
                        region.assign_advice(
                            || "Special output acc post",
                            self.output_acc,
                            offset + 1,
                            || Ok(value),
                        )?
                    }
                };
                Ok((output_lane, step2_od, step3_od))
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct SumConfig<F> {
    q_enable: Selector,
    x: Column<Advice>,
    sum: Column<Advice>,
    _marker: PhantomData<F>,
}
impl<F: Field> SumConfig<F> {
    // We assume the input columns are all copiable
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let q_enable = meta.selector();
        let x = meta.advice_column();
        let sum = meta.advice_column();

        meta.enable_equality(x);
        meta.enable_equality(sum);

        meta.create_gate("sum", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let x = meta.query_advice(x, Rotation::cur());
            let sum_next = meta.query_advice(sum, Rotation::next());
            let sum = meta.query_advice(sum, Rotation::cur());
            vec![q_enable * (sum_next - sum - x)]
        });
        Self {
            q_enable,
            x,
            sum,
            _marker: PhantomData,
        }
    }
    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        xs: Vec<AssignedCell<F, F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
        debug_assert!(xs.len() > 1);
        layouter.assign_region(
            || "running sum",
            |mut region| {
                let mut sum = F::zero();
                let mut offset = 0;
                for xs_item in xs.iter() {
                    self.q_enable.enable(&mut region, offset)?;
                    xs_item.copy_advice(|| "x", &mut region, self.x, offset)?;
                    region.assign_advice(|| "sum", self.sum, offset, || Ok(sum))?;
                    sum += xs_item.value().unwrap_or(&F::zero());
                    offset += 1;
                }
                let sum = region.assign_advice(|| "last sum", self.sum, offset, || Ok(sum))?;

                Ok(sum)
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct OverflowCheckConfig<F> {
    q_enable: Selector,
    step2_sum_config: SumConfig<F>,
    step3_sum_config: SumConfig<F>,
    step2_acc: Column<Advice>,
    step3_acc: Column<Advice>,
}
impl<F: Field> OverflowCheckConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        cols_to_copy: Vec<Column<Advice>>,
        step2_range_table: &RangeCheckConfig<F, STEP2_RANGE>,
        step3_range_table: &RangeCheckConfig<F, STEP3_RANGE>,
    ) -> Self {
        for &col in cols_to_copy.iter() {
            meta.enable_equality(col);
        }
        let step2_sum_config = SumConfig::configure(meta);
        let step3_sum_config = SumConfig::configure(meta);

        let q_enable = meta.complex_selector();
        let step2_acc = meta.advice_column();
        let step3_acc = meta.advice_column();
        meta.enable_equality(step2_acc);
        meta.enable_equality(step3_acc);

        meta.lookup("Overflow step 2", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let step2_acc = meta.query_advice(step2_acc, Rotation::cur());
            vec![(q_enable * step2_acc, step2_range_table.range)]
        });

        meta.lookup("Overflow step 3", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let step3_acc = meta.query_advice(step3_acc, Rotation::cur());
            vec![(q_enable * step3_acc, step3_range_table.range)]
        });

        Self {
            q_enable,
            step2_sum_config,
            step3_sum_config,
            step2_acc,
            step3_acc,
        }
    }
    pub fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        step2_cells: Vec<AssignedCell<F, F>>,
        step3_cells: Vec<AssignedCell<F, F>>,
    ) -> Result<(), Error> {
        let step2_sum = self.step2_sum_config.assign_region(layouter, step2_cells)?;
        let step3_sum = self.step3_sum_config.assign_region(layouter, step3_cells)?;
        layouter.assign_region(
            || "Overflow range check",
            |mut region| {
                let offset = 0;
                self.q_enable.enable(&mut region, offset)?;
                // Copy constrain Steps 2 and 3 sums to `step2_acc` and `step3_acc` columns.
                step2_sum.copy_advice(|| "Step2 sum", &mut region, self.step2_acc, offset)?;
                step3_sum.copy_advice(|| "Step3 sum", &mut region, self.step3_acc, offset)?;

                Ok(())
            },
        )
    }
}
