use crate::common::State;
use eth_types::Field;
use halo2_proofs::circuit::AssignedCell;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::Zero;
use std::ops::{Index, IndexMut};

pub const B2: u8 = 2;
pub const B13: u8 = 13;
pub const B9: u8 = 9;

/// Base 9 coef mapper scalers
/// f_logic(x1, x2, x3, x4) = x1 ^ (!x2 & x3) ^ x4
/// f_arith(x1, x2, x3, x4) = 2*x1 + x2 + 3*x3 + 2*x4
/// where x1, x2, x3, x4 are binary.
/// We have the property that `0 <= f_arith(...) < 9` and
/// the map from `f_arith(...)` to `f_logic(...)` is injective.
pub const A1: u64 = 2;
pub const A2: u64 = 1;
pub const A3: u64 = 3;
pub const A4: u64 = 2;

pub type Lane13 = BigUint;
pub type Lane9 = BigUint;

#[derive(Debug)]
pub struct StateBigInt {
    pub(crate) xy: Vec<BigUint>,
}
impl Default for StateBigInt {
    fn default() -> Self {
        let mut xy: Vec<BigUint> = Vec::with_capacity(25);
        for _ in 0..25 {
            xy.push(Zero::zero());
        }
        Self { xy }
    }
}

impl From<State> for StateBigInt {
    fn from(state: State) -> Self {
        let xy = state
            .iter()
            .flatten()
            .map(|num| BigUint::from(*num))
            .collect();
        Self { xy }
    }
}

impl StateBigInt {
    pub fn from_state_big_int<F>(a: &StateBigInt, lane_transform: F) -> Self
    where
        F: Fn(BigUint) -> BigUint,
    {
        let mut out = StateBigInt::default();
        for (x, y) in (0..5).cartesian_product(0..5) {
            out[(x, y)] = lane_transform(a[(x, y)].clone());
        }
        out
    }
}

impl Index<(usize, usize)> for StateBigInt {
    type Output = BigUint;
    fn index(&self, xy: (usize, usize)) -> &Self::Output {
        debug_assert!(xy.0 < 5);
        debug_assert!(xy.1 < 5);

        &self.xy[xy.0 * 5 + xy.1]
    }
}

impl IndexMut<(usize, usize)> for StateBigInt {
    fn index_mut(&mut self, xy: (usize, usize)) -> &mut Self::Output {
        debug_assert!(xy.0 < 5);
        debug_assert!(xy.1 < 5);

        &mut self.xy[xy.0 * 5 + xy.1]
    }
}

impl Clone for StateBigInt {
    fn clone(&self) -> StateBigInt {
        let xy = self.xy.clone();
        StateBigInt { xy }
    }
}

pub fn convert_b2_to_b13(a: u64) -> Lane13 {
    let mut lane13: BigUint = Zero::zero();
    for i in 0..64 {
        let bit = (a >> i) & 1;
        lane13 += bit * BigUint::from(B13).pow(i);
    }
    lane13
}

pub fn convert_b2_to_b9(a: u64) -> Lane9 {
    let mut lane9: BigUint = Zero::zero();
    for i in 0..64 {
        let bit = (a >> i) & 1;
        lane9 += bit * BigUint::from(B9).pow(i);
    }
    lane9
}

/// Maps a sum of 12 bits to the XOR result of 12 bits.
///
/// The input `x` is a chunk of a base 13 number and it represents the
/// arithmatic sum of 12 bits. Asking the result of the 12 bits XORed together
/// is equivalent of asking if `x` being an odd number.
///
/// For example, if we have 5 bits set and 7 bits unset, then we have `x` as 5
/// and the xor result to be 1.
pub fn convert_b13_coef(x: u8) -> u8 {
    debug_assert!(x < 13);
    x & 1
}

/// Maps the arithmatic result `2*a + b + 3*c + 2*d` to the bit operation result
/// `a ^ (~b & c) ^ d`
///
/// The input `x` is a chunk of a base 9 number and it represents the arithmatic
/// result of `2*a + b + 3*c + 2*d`, where `a`, `b`, `c`, and `d` each is a bit.
pub fn convert_b9_coef(x: u8) -> u8 {
    debug_assert!(x < 9);
    let bit_table: [u8; 9] = [0, 0, 1, 1, 0, 0, 1, 1, 0];
    bit_table[x as usize]
}

// We assume the input comes from Theta step and has 65 chunks
// expecting outputs from theta gate
pub fn convert_b13_lane_to_b9(x: Lane13, rot: u32) -> Lane9 {
    // 65 chunks
    let mut chunks = x.to_radix_le(B13.into());
    chunks.resize(65, 0);
    // 0 and 64 was separated in Theta, we now combined them together
    let special = chunks.get(0).unwrap() + chunks.get(64).unwrap();
    // middle 63 chunks
    let middle = chunks.get(1..64).unwrap();
    // split at offset
    let (left, right) = middle.split_at(63 - rot as usize);
    // rotated has 64 chunks
    // left is rotated right, and the right is wrapped over to left
    // with the special chunk in the middle
    let rotated: Vec<u8> = right
        .iter()
        .chain(vec![special].iter())
        .chain(left.iter())
        .map(|&x| convert_b13_coef(x))
        .collect_vec();
    BigUint::from_radix_le(&rotated, B9.into()).unwrap_or_default()
}

pub fn convert_lane<F>(lane: BigUint, from_base: u8, to_base: u8, coef_transform: F) -> BigUint
where
    F: Fn(u8) -> u8,
{
    let chunks = lane.to_radix_be(from_base.into());
    let converted_chunks: Vec<u8> = chunks.iter().map(|&x| coef_transform(x)).collect();
    BigUint::from_radix_be(&converted_chunks, to_base.into()).unwrap_or_default()
}

pub fn convert_b9_lane_to_b13(x: Lane9) -> Lane13 {
    convert_lane(x, B9, B13, convert_b9_coef)
}

pub fn convert_b9_lane_to_b2(x: Lane9) -> u64 {
    convert_lane(x, B9, 2, convert_b9_coef)
        .iter_u64_digits()
        .take(1)
        .next()
        .unwrap_or(0)
}

pub fn convert_b9_lane_to_b2_normal(x: Lane9) -> u64 {
    convert_lane(x, B9, 2, |y| y)
        .iter_u64_digits()
        .take(1)
        .next()
        .unwrap_or(0)
}

/// This function allows us to inpect coefficients of big-numbers in different
/// bases.
pub fn inspect(x: BigUint, name: &str, base: u8) {
    let mut chunks = x.to_radix_le(base.into());
    chunks.resize(65, 0);
    let info: Vec<(usize, u8)> = (0..65).zip(chunks.iter().copied()).collect_vec();
    println!("inspect {} {} info {:?}", name, x, info);
}

pub fn state_to_biguint<F: Field, const N: usize>(state: [F; N]) -> StateBigInt {
    StateBigInt {
        xy: state
            .iter()
            .map(|elem| elem.to_repr())
            .map(|bytes| BigUint::from_bytes_le(&bytes))
            .collect(),
    }
}

pub fn state_to_state_bigint<F: Field, const N: usize>(state: [F; N]) -> State {
    let mut matrix = [[0u64; 5]; 5];

    let mut elems: Vec<u64> = state
        .iter()
        .map(|elem| elem.to_repr())
        // This is horrible. But Field does not give much better alternatives
        // and refactoring `State` will be done once the
        // keccak_all_togheter is done.
        .map(|bytes| {
            debug_assert!(bytes[8..32] == vec![0u8; 24]);
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[0..8]);
            u64::from_le_bytes(arr)
        })
        .collect();
    elems.extend(vec![0u64; 25 - N]);
    (0..5)
        .into_iter()
        .for_each(|idx| matrix[idx].copy_from_slice(&elems[5 * idx..(5 * idx + 5)]));

    matrix
}

pub fn state_bigint_to_field<F: Field, const N: usize>(state: StateBigInt) -> [F; N] {
    let mut arr = [F::zero(); N];
    let vector: Vec<F> = state
        .xy
        .iter()
        .map(|elem| {
            let mut array = [0u8; 32];
            let bytes = elem.to_bytes_le();
            array[0..bytes.len()].copy_from_slice(&bytes[0..bytes.len()]);
            array
        })
        .map(|bytes| F::from_repr(bytes).unwrap())
        .collect();
    arr[0..N].copy_from_slice(&vector[0..N]);
    arr
}

/// Returns only the value of a an assigned state cell.
pub fn split_state_cells<F: Field, const N: usize>(state: [AssignedCell<F, F>; N]) -> [F; N] {
    let mut res = [F::zero(); N];
    state
        .iter()
        .enumerate()
        .for_each(|(idx, assigned_cell)| res[idx] = *assigned_cell.value().unwrap());
    res
}

pub fn f_from_radix_be<F: Field>(buf: &[u8], base: u8) -> F {
    let base = F::from(base as u64);
    buf.iter()
        .fold(F::zero(), |acc, &x| acc * base + F::from(x as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    #[test]
    fn test_convert_b13_lane_to_b9() {
        // the number 1 is chosen that `convert_b13_coef` has no effect
        let mut a = vec![0, 1, 1, 1];
        a.resize(65, 0);
        let lane = BigUint::from_radix_le(&a, B13.into()).unwrap_or_default();
        assert_eq!(
            convert_b13_lane_to_b9(lane.clone(), 0),
            BigUint::from_radix_le(&a, B9.into()).unwrap_or_default()
        );

        // rotate by 4
        let mut b = vec![0, 0, 0, 0, 0, 1, 1, 1];
        b.resize(65, 0);
        assert_eq!(
            convert_b13_lane_to_b9(lane, 4),
            BigUint::from_radix_le(&b, B9.into()).unwrap_or_default()
        );
    }
}
