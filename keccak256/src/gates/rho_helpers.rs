use crate::{
    arith_helpers::{convert_b13_coef, convert_b13_lane_to_b9, B13, B2, B9},
    common::LANE_SIZE,
};

use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Zero;
use std::convert::TryInto;

pub const BASE_NUM_OF_CHUNKS: u32 = 4;

/// Determine how many chunks in a step
///
/// Usually it's a step of 4 chunks, but the number of chunks could be less near
/// the rotation position and the end of the lane.
pub fn get_step_size(chunk_idx: u32, rotation: u32) -> u32 {
    // near the rotation offset position of the lane
    let offset = LANE_SIZE - rotation;
    if chunk_idx < offset && offset < chunk_idx + BASE_NUM_OF_CHUNKS {
        return offset - chunk_idx;
    }
    // near the end of the lane
    if chunk_idx < LANE_SIZE && LANE_SIZE < chunk_idx + BASE_NUM_OF_CHUNKS {
        return LANE_SIZE - chunk_idx;
    }
    BASE_NUM_OF_CHUNKS
}

/// Slice the lane into chunk indices and steps
///
/// We ask what's the current chunk index and the step we need to go to the next
/// chunk index. We start chunk_idx from 1 because the 0th chunk is from the low
/// value from the theta step.
pub fn slice_lane(rotation: u32) -> Vec<(u32, u32)> {
    let mut chunk_idx = 1;
    let mut output = vec![];
    while chunk_idx < LANE_SIZE {
        let step = get_step_size(chunk_idx, rotation);
        output.push((chunk_idx, step));
        chunk_idx += step;
    }
    output
}

/// We have 12 step 1, 12 step 2, and 13 step 3
///
/// See tests for more detail
pub const STEP_COUNTS: [u32; 3] = [12, 12, 13];

/// A mapping from `step` to a overflow detector value
///
/// See tests for the derivation of the values
pub const OVERFLOW_TRANSFORM: [u32; 5] = [0, 0, 1, 13, 170];

/// The sum of the step 2 overflow detectors across all 25 lanes should not
/// greater than this value
///
/// See tests for the derivation of the values
pub const STEP2_RANGE: u64 = 12;

/// The sum of the step 3 overflow detectors across all 25 lanes should not
/// greater than this value
///
/// See tests for the derivation of the values
pub const STEP3_RANGE: u64 = 169;

/// Get the overflow detector from an input chunks
///
/// The input is chunks of a base 13 number in big endian.
/// For example, if the input is `[1, 12, 3, 7]`, it represents a coefficient
/// `1*13^3 + 12*13^2 + 3*13 + 7`. The example only happens when `step = 4`. If
/// we have a `step = 3`, the first chunk must be 0. It could be the case that
/// we have `step = 4`, but all of the chunks are 0. That would result our
/// overflow detector value to be 0.
///
/// In the circuit, if we have a `step = 3`, but a non-zero first chunk is
/// adviced. It would cause the non_zero_chunk_count to be 4, resulting the
/// overflow detector to be 170.
///
/// This would fail the final overflow detector check.
pub fn get_overflow_detector(
    b13_chunks: [u8; BASE_NUM_OF_CHUNKS as usize],
) -> u32 {
    // could be 0, 1, 2, 3, 4
    let non_zero_chunk_count = BASE_NUM_OF_CHUNKS as usize
        - b13_chunks.iter().take_while(|x| **x == 0).count();
    // could be 0, 0, 1, 13, 170
    OVERFLOW_TRANSFORM[non_zero_chunk_count]
}

#[derive(Debug, Clone)]
pub struct Slice {
    pub coef: BigUint,
    pub power_of_base: BigUint,
    pub pre_acc: BigUint,
}

#[derive(Debug, Clone)]
pub struct OverflowDetector {
    pub value: u32,
    pub step2_acc: u32,
    pub step3_acc: u32,
}

#[derive(Debug, Clone)]
pub struct Conversion {
    chunk_idx: u32,
    step: u32,
    pub input: Slice,
    pub output: Slice,
    pub overflow_detector: OverflowDetector,
}

pub struct Special {
    pub input: BigUint,
    pub output_acc_pre: BigUint,
    pub output_acc_post: BigUint,
    pub output_coef: u8,
}

const RHO_LANE_SIZE: usize = 65;

#[derive(Debug, Clone)]
pub struct RhoLane {
    // base 13. 65 chunks
    input: BigUint,
    // base 9
    pub output: BigUint,
    // output in binary, useful to check against plain rho output
    output_b2: u64,
    rotation: u32,
    // base13 in little endian
    chunks: [u8; RHO_LANE_SIZE],
    special_high: u8,
    special_low: u8,
}

impl RhoLane {
    pub fn new(input: BigUint, rotation: u32) -> Self {
        assert!(
            input.lt(&BigUint::from(B13).pow(RHO_LANE_SIZE as u32)),
            "lane too big"
        );
        let mut chunks = input.to_radix_le(B13.into());
        chunks.resize(RHO_LANE_SIZE, 0);
        let chunks: [u8; RHO_LANE_SIZE] = chunks.try_into().unwrap();
        let special_high = *chunks.get(64).unwrap();
        let special_low = *chunks.get(0).unwrap();
        assert!(special_high + special_low < B13, "invalid Rho input lane");
        let output = convert_b13_lane_to_b9(input.clone(), rotation);
        let output_b2 =
            *BigUint::from_radix_le(&output.to_radix_le(B9.into()), B2.into())
                .unwrap_or_default()
                .to_u64_digits()
                .first()
                .unwrap_or(&0);

        Self {
            input,
            output,
            output_b2,
            rotation,
            chunks,
            special_high,
            special_low,
        }
    }

    pub fn get_full_witness(&self) -> (Vec<Conversion>, Special) {
        let mut input_acc = self.input.clone();
        let mut output_acc = BigUint::zero();
        let mut step2_acc: u32 = 0;
        let mut step3_acc: u32 = 0;
        let conversions: Vec<Conversion> = slice_lane(self.rotation)
            .iter()
            .map(|&(chunk_idx, step)| {
                let chunks = self
                    .chunks
                    .get(chunk_idx as usize..(chunk_idx + step) as usize)
                    .unwrap();
                let input = {
                    let coef = BigUint::from_radix_le(chunks, B13.into())
                        .unwrap_or_default();
                    let power_of_base = BigUint::from(B13).pow(chunk_idx);
                    let pre_acc = input_acc.clone();
                    input_acc -= &coef * &power_of_base;
                    Slice {
                        coef,
                        power_of_base,
                        pre_acc,
                    }
                };
                let output = {
                    let converted_chunks = chunks
                        .iter()
                        .map(|&x| convert_b13_coef(x))
                        .collect_vec();
                    let coef =
                        BigUint::from_radix_le(&converted_chunks, B9.into())
                            .unwrap_or_default();
                    let power = (chunk_idx + self.rotation) % LANE_SIZE;
                    let power_of_base = BigUint::from(B9).pow(power);
                    let pre_acc = output_acc.clone();
                    output_acc += &coef * &power_of_base;
                    Slice {
                        coef,
                        power_of_base,
                        pre_acc,
                    }
                };
                let overflow_detector = {
                    let mut v = chunks.to_vec();
                    // pad to 4 chunks
                    v.resize(BASE_NUM_OF_CHUNKS as usize, 0);
                    // to big endian
                    v.reverse();
                    let chunks_be: [u8; BASE_NUM_OF_CHUNKS as usize] =
                        v.try_into().unwrap();
                    let value = get_overflow_detector(chunks_be);
                    match step {
                        2 => step2_acc += value,
                        3 => step3_acc += value,
                        _ => {}
                    };
                    OverflowDetector {
                        value,
                        step2_acc,
                        step3_acc,
                    }
                };
                Conversion {
                    chunk_idx,
                    step,
                    input,
                    output,
                    overflow_detector,
                }
            })
            .collect_vec();
        self.sanity_check(&input_acc);
        let special = {
            let input = input_acc;
            let output_acc_pre = output_acc;
            let output_coef =
                convert_b13_coef(self.special_high + self.special_low);
            let output_acc_post = &output_acc_pre
                + output_coef * BigUint::from(B9 as u64).pow(self.rotation);
            Special {
                input,
                output_acc_pre,
                output_acc_post,
                output_coef,
            }
        };
        (conversions, special)
    }

    /// After we run down the input accumulator for the normal chunks,
    /// the remaining value should be equal to what the special chunks
    /// represent
    fn sanity_check(&self, input_acc: &BigUint) {
        let expect = (self.special_low as u64)
            + (self.special_high as u64) * BigUint::from(B13).pow(LANE_SIZE);
        assert_eq!(
            *input_acc,
            expect,
            "input_acc got: {:?}  expect: {:?} = low({:?}) + high({:?}) * 13**64",
            input_acc,
            expect,
            self.special_low,
            self.special_high,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ROTATION_CONSTANTS;
    #[test]
    fn test_overflow_counting() {
        // counting how many step 1, step 2, and step 3 in the lane slices.
        let mut counts = vec![0; BASE_NUM_OF_CHUNKS as usize - 1];
        for rotation in ROTATION_CONSTANTS.iter().flat_map(|r| r.iter()) {
            let chunks = slice_lane(*rotation);
            for (_, step) in chunks.iter() {
                if *step < BASE_NUM_OF_CHUNKS {
                    counts[*step as usize - 1] += 1;
                }
            }
        }
        // We know exactly at setup time there would be 12 step 1, 12 step 2 and
        // 13 step 3.
        assert_eq!(counts, STEP_COUNTS);

        // We define a mapping overflow g(x), it maps step to a overflow
        // detector value We first define g(0) = 0, g(1) = 0
        // Mapping from step 0 is meaningless, because we don't have step 0
        // Mapping step 1 to 0 as the base case.
        // Then we define `g(i+1) = g(i) * previous_step_count + 1`
        // Because `g(i) * previous_step_count` is the max possible overflow
        // detector sum from previous step An overflow in previous step
        // would get the `g(i+1)` value from the lookup table and fail
        // the final range check
        let mut overflow = vec![0, 0];
        for c in counts.iter() {
            let elem = overflow.last().cloned().unwrap();
            overflow.push(c * elem + 1);
        }
        assert_eq!(overflow, OVERFLOW_TRANSFORM);

        let step2 = 2;
        assert_eq!(
            STEP2_RANGE,
            (STEP_COUNTS[step2 - 1] * OVERFLOW_TRANSFORM[step2]).into()
        );

        let step3 = 3;
        assert_eq!(
            STEP3_RANGE,
            (STEP_COUNTS[step3 - 1] * OVERFLOW_TRANSFORM[step3]).into()
        );
    }
    #[test]
    fn test_rho_lane_rotation() {
        // Chosen such that special chunks are all 0
        // The special chunks transformed (high+low) value is 0 too
        let rho_arith_input_chunks = [0, 5, 4, 3, 2, 1];
        let rho_arith_lane =
            BigUint::from_radix_le(&rho_arith_input_chunks, B13.into())
                .unwrap_or_default();
        let rho_chunks_transformed_no_special = [5, 4, 3, 2, 1]
            .iter()
            .map(|&x| convert_b13_coef(x))
            .collect_vec();
        assert_eq!(rho_chunks_transformed_no_special, [1, 0, 1, 0, 1]);
        // We need to add back the transformed value of special chunks.
        let rho_chunks_transformed = [0, 1, 0, 1, 0, 1];
        let rho_bin_input: u64 =
            BigUint::from_radix_le(&rho_chunks_transformed, B2.into())
                .unwrap_or_default()
                .iter_u64_digits()
                .collect_vec()[0];
        assert_eq!(rho_bin_input, 42);

        let rotation = 5;
        let lane = RhoLane::new(rho_arith_lane, rotation);

        let (conversions, special) = lane.get_full_witness();
        assert_eq!(conversions.len(), slice_lane(rotation).len());
        assert_eq!(special.output_acc_post, lane.output);
    }
}
