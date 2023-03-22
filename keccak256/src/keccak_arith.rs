use crate::{arith_helpers::*, common::*};
use itertools::Itertools;

#[derive(Default)]
pub struct KeccakFArith {}

impl KeccakFArith {
    pub fn permute_and_absorb(
        a: &mut StateBigInt,
        next_inputs: Option<&State>,
    ) -> Option<StateBigInt> {
        for rc in ROUND_CONSTANTS.iter().take(PERMUTATION - 1) {
            let s1 = KeccakFArith::theta(a);
            let s2 = KeccakFArith::rho(&s1);
            let s3 = KeccakFArith::pi(&s2);
            let s4 = KeccakFArith::xi(&s3);
            let s5 = KeccakFArith::iota_b9(&s4, *rc);
            *a = StateBigInt::from_state_big_int(&s5, convert_b9_lane_to_b13);
        }
        let s1 = KeccakFArith::theta(a);
        let s2 = KeccakFArith::rho(&s1);
        let s3 = KeccakFArith::pi(&s2);
        let s4 = KeccakFArith::xi(&s3);
        let res = KeccakFArith::mixing(&s4, next_inputs, *ROUND_CONSTANTS.last().unwrap());
        *a = res.clone();
        if next_inputs.is_some() {
            Some(res)
        } else {
            None
        }
    }

    pub fn theta(a: &StateBigInt) -> StateBigInt {
        let mut c: Vec<Lane13> = Vec::with_capacity(5);
        let mut out = StateBigInt::default();

        for x in 0..5 {
            c.push(&a[(x, 0)] + &a[(x, 1)] + &a[(x, 2)] + &a[(x, 3)] + &a[(x, 4)]);
        }

        for (x, y) in (0..5).cartesian_product(0..5) {
            out[(x, y)] = &a[(x, y)] + &c[(x + 4) % 5] + &c[(x + 1) % 5] * B13;
        }
        out
    }

    pub fn rho(a: &StateBigInt) -> StateBigInt {
        let mut out = StateBigInt::default();
        for (x, y) in (0..5).cartesian_product(0..5) {
            out[(x, y)] = convert_b13_lane_to_b9(a[(x, y)].clone(), ROTATION_CONSTANTS[x][y]);
        }
        out
    }

    pub fn pi(a: &StateBigInt) -> StateBigInt {
        let mut out = StateBigInt::default();
        for (x, y) in (0..5).cartesian_product(0..5) {
            out[(y, (2 * x + 3 * y) % 5)] = a[(x, y)].clone();
        }
        out
    }

    pub fn xi(a: &StateBigInt) -> StateBigInt {
        let mut out = StateBigInt::default();
        for (x, y) in (0..5).cartesian_product(0..5) {
            out[(x, y)] = a[(x, y)].clone() * A1
                + a[((x + 1) % 5, y)].clone() * A2
                + a[((x + 2) % 5, y)].clone() * A3;
        }
        out
    }

    pub fn absorb(a: &StateBigInt, next_input: &State) -> StateBigInt {
        let mut out = StateBigInt::default();
        for (x, y) in (0..5).cartesian_product(0..5) {
            out[(x, y)] = a[(x, y)].clone() + convert_b2_to_b9(next_input[x][y]) * A4
        }
        out
    }

    pub fn iota_b9(a: &StateBigInt, rc: u64) -> StateBigInt {
        let mut out = a.clone();
        out[(0, 0)] += convert_b2_to_b9(rc) * A4;
        out
    }

    pub fn iota_b13(a: &StateBigInt, rc: u64) -> StateBigInt {
        let mut out = a.clone();
        out[(0, 0)] += convert_b2_to_b13(rc);
        out
    }

    pub fn mixing(a: &StateBigInt, next_input: Option<&State>, rc: u64) -> StateBigInt {
        if let Some(next_input) = next_input {
            let out_1 = KeccakFArith::absorb(a, next_input);

            // Base conversion from 9 to 13
            let mut out_2 = StateBigInt::default();
            for (x, y) in (0..5).cartesian_product(0..5) {
                out_2[(x, y)] = convert_b9_lane_to_b13(out_1[(x, y)].clone())
            }
            KeccakFArith::iota_b13(&out_2, rc)
        } else {
            KeccakFArith::iota_b9(a, rc)
        }
    }
}

pub struct Keccak {
    state: State,
    sponge: Sponge,
}

impl Default for Keccak {
    fn default() -> Keccak {
        let security_level = (1088, 512);

        Keccak {
            state: [[0; 5]; 5],
            // rate & capacity in bytes
            sponge: Sponge::new(security_level.0 / 8, security_level.1 / 8),
        }
    }
}

impl Keccak {
    pub fn update(&mut self, input: &[u8]) {
        let padding_total = self.sponge.rate - (input.len() % self.sponge.rate);
        let mut padding: Vec<u8>;

        if padding_total == 1 {
            padding = vec![0x81];
        } else {
            padding = vec![0x01];
            padding.resize(padding_total - 1, 0x00);
            padding.push(0x80);
        }

        let padded_input: &[u8] = &[input, &padding].concat();
        self.sponge.absorb(&mut self.state, padded_input);
    }

    /// Returns keccak hash based on current state
    pub fn digest(&mut self) -> Vec<u8> {
        self.sponge.squeeze(&mut self.state)
    }
}

struct Sponge {
    rate: usize,
    capacity: usize,
}

impl Sponge {
    pub fn new(rate: usize, capacity: usize) -> Sponge {
        Sponge { rate, capacity }
    }

    pub fn absorb(&self, state: &mut State, message: &[u8]) {
        debug_assert!(
            message.len() % self.rate == 0,
            "Message is not divisible entirely by bytes rate"
        );

        let chunks_total = message.len() / self.rate;

        let words: Vec<u64> = Sponge::bits_to_u64_words_le(message);

        let mut state_bit_int = StateBigInt::default();
        for chunk_i in 0..chunks_total {
            let chunk_offset: usize = chunk_i * (self.rate / 8);
            let mut x = 0;
            let mut y = 0;
            let mut next_inputs = State::default();
            for i in 0..(self.rate / 8) {
                next_inputs[x][y] = words[chunk_offset + i];
                if x < 5 - 1 {
                    x += 1;
                } else {
                    y += 1;
                    x = 0;
                }
            }
            if chunk_i == 0 {
                for (x, y) in (0..5).cartesian_product(0..5) {
                    state_bit_int[(x, y)] = convert_b2_to_b13(next_inputs[x][y]);
                }
                continue;
            }
            KeccakFArith::permute_and_absorb(&mut state_bit_int, Some(&next_inputs));
        }
        KeccakFArith::permute_and_absorb(&mut state_bit_int, None);
        for (x, y) in (0..5).cartesian_product(0..5) {
            state[x][y] = convert_b9_lane_to_b2(state_bit_int[(x, y)].clone())
        }
    }

    pub fn squeeze(&self, state: &mut State) -> Vec<u8> {
        let mut output: Vec<u8> = vec![];

        let output_len: usize = self.capacity / 2;
        let elems_total: usize = output_len / 8;
        let mut counter: usize = 0;

        'outer: for y in 0..5 {
            for sheet in state.iter().take(5) {
                output.append(&mut sheet[y].to_le_bytes().to_vec());
                if counter == elems_total {
                    break 'outer;
                }
                counter += 1;
            }
        }

        output.resize(output_len, 0);
        output
    }

    fn bits_to_u64_words_le(message: &[u8]) -> Vec<u64> {
        let words_total = message.len() / 8;
        let mut words: Vec<u64> = vec![0; words_total];

        for i in 0..words_total {
            let mut word_bits: [u8; 8] = Default::default();
            word_bits.copy_from_slice(&message[i * 8..i * 8 + 8]);
            words[i] = u64::from_le_bytes(word_bits);
        }
        words
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        arith_helpers::*,
        keccak_arith::{Keccak, KeccakFArith, State},
        plain::KeccakF,
    };
    use itertools::Itertools;
    use num_bigint::BigUint;
    use num_traits::Zero;

    fn keccak256(msg: &[u8]) -> Vec<u8> {
        let mut keccak = Keccak::default();
        keccak.update(msg);
        keccak.digest()
    }

    #[test]
    fn test_helpers() {
        assert_eq!(convert_b2_to_b13(0b101u64), BigUint::from(170u64));
        assert_eq!(convert_b2_to_b9(0b10u64), BigUint::from(9u64));
        assert_eq!(convert_b2_to_b9(0b101u64), BigUint::from(82u64));
        assert_eq!(
            convert_b13_lane_to_b9(BigUint::from(170u64), 0),
            BigUint::from(82u64)
        );
        assert_eq!(convert_b9_lane_to_b13(BigUint::from(82u64)), Zero::zero());
        assert_eq!(convert_b9_lane_to_b2(BigUint::from(82u64)), 0);
        assert_eq!(
            convert_b9_lane_to_b2(BigUint::from(9u64).pow(63) * 2u64),
            1u64 << 63
        );
    }

    #[test]
    fn test_theta_rho() {
        let input1: State = [
            [1, 0, 0, 0, 0],
            [0, 0, 0, 9223372036854775808, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];
        let input2: State = [
            [4398046511105, 8, 2, 268436480, 2305844108725321728],
            [
                17592186044416,
                52776560230400,
                544,
                68719493120,
                2199023255552,
            ],
            [
                4398046543872,
                1152921504606846984,
                262144,
                1024,
                1099511627780,
            ],
            [0, 52776558133248, 514, 268451840, 2305845208236949504],
            [17592186077184, 1152921504608944128, 262176, 68719476736, 4],
        ];
        for a in [input1, input2] {
            let mut in_b13 = StateBigInt::default();
            for (x, y) in (0..5).cartesian_product(0..5) {
                in_b13[(x, y)] = convert_b2_to_b13(a[x][y]);
            }
            let s1 = KeccakF::theta(a);
            let s1_arith = KeccakFArith::theta(&in_b13);
            for (x, y) in (0..5).cartesian_product(0..5) {
                assert_eq!(
                    s1[x][y],
                    convert_b9_lane_to_b2_normal(convert_b13_lane_to_b9(
                        s1_arith[(x, y)].clone(),
                        0
                    ))
                );
            }
            let s2 = KeccakF::rho(s1);
            let s2_arith = KeccakFArith::rho(&s1_arith);
            for (x, y) in (0..5).cartesian_product(0..5) {
                let expected = convert_b9_lane_to_b2_normal(s2_arith[(x, y)].clone());
                assert_eq!(s2[x][y], expected);
            }
        }
    }

    #[test]
    fn test_empty_input_arith() {
        let output = [
            197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182,
            83, 202, 130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
        ];
        assert_eq!(keccak256(&[]), output);
    }

    #[test]
    fn test_short_input_arith() {
        let output = [
            56, 209, 138, 203, 103, 210, 92, 139, 185, 148, 39, 100, 182, 47, 24, 225, 112, 84,
            246, 106, 129, 123, 212, 41, 84, 35, 173, 249, 237, 152, 135, 62,
        ];
        assert_eq!(keccak256(&[102, 111, 111, 98, 97, 114]), output);
    }

    #[test]
    fn test_long_input_arith() {
        let input = [
            65, 108, 105, 99, 101, 32, 119, 97, 115, 32, 98, 101, 103, 105, 110, 110, 105, 110,
            103, 32, 116, 111, 32, 103, 101, 116, 32, 118, 101, 114, 121, 32, 116, 105, 114, 101,
            100, 32, 111, 102, 32, 115, 105, 116, 116, 105, 110, 103, 32, 98, 121, 32, 104, 101,
            114, 32, 115, 105, 115, 116, 101, 114, 32, 111, 110, 32, 116, 104, 101, 32, 98, 97,
            110, 107, 44, 32, 97, 110, 100, 32, 111, 102, 32, 104, 97, 118, 105, 110, 103, 32, 110,
            111, 116, 104, 105, 110, 103, 32, 116, 111, 32, 100, 111, 58, 32, 111, 110, 99, 101,
            32, 111, 114, 32, 116, 119, 105, 99, 101, 32, 115, 104, 101, 32, 104, 97, 100, 32, 112,
            101, 101, 112, 101, 100, 32, 105, 110, 116, 111, 32, 116, 104, 101, 32, 98, 111, 111,
            107, 32, 104, 101, 114, 32, 115, 105, 115, 116, 101, 114, 32, 119, 97, 115, 32, 114,
            101, 97, 100, 105, 110, 103, 44, 32, 98, 117, 116, 32, 105, 116, 32, 104, 97, 100, 32,
            110, 111, 32, 112, 105, 99, 116, 117, 114, 101, 115, 32, 111, 114, 32, 99, 111, 110,
            118, 101, 114, 115, 97, 116, 105, 111, 110, 115, 32, 105, 110, 32, 105, 116, 44, 32,
            97, 110, 100, 32, 119, 104, 97, 116, 32, 105, 115, 32, 116, 104, 101, 32, 117, 115,
            101, 32, 111, 102, 32, 97, 32, 98, 111, 111, 107, 44, 32, 116, 104, 111, 117, 103, 104,
            116, 32, 65, 108, 105, 99, 101, 32, 119, 105, 116, 104, 111, 117, 116, 32, 112, 105,
            99, 116, 117, 114, 101, 115, 32, 111, 114, 32, 99, 111, 110, 118, 101, 114, 115, 97,
            116, 105, 111, 110, 115, 63,
        ];
        let output = [
            60, 227, 142, 8, 143, 135, 108, 85, 13, 254, 190, 58, 30, 106, 153, 194, 188, 6, 208,
            49, 16, 102, 150, 120, 100, 130, 224, 177, 64, 98, 53, 252,
        ];
        assert_eq!(keccak256(&input), output);
    }
}
