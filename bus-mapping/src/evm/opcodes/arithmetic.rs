use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    evm::Opcode,
    Error,
};
use eth_types::{evm_types::OpcodeId, GethExecStep, ToBigEndian, ToLittleEndian, Word, U256, U512};
use itertools::Itertools;
use std::{
    cmp::Ordering,
    ops::{Neg, Rem},
};

/// value is treated as two’s complement signed 256-bit integers.
/// Note the when −2^255 is negated the result is −2^255
#[derive(Debug, Copy, Clone, Default, Eq, PartialEq)]
struct SignedWord(Word);

impl SignedWord {
    const ZERO: Self = Self(Word::zero());
    const MIN: Self = Self(U256([0x8000000000000000, 0, 0, 0]));

    const MAX: Self = Self(U256([i64::MAX as u64, u64::MAX, u64::MAX, u64::MAX]));

    const fn is_neg(self) -> bool {
        self.0.bit(255)
    }

    fn abs(self) -> Word {
        if self.is_neg() {
            self.neg().0
        } else {
            self.0
        }
    }

    /// returns quotient and remainder
    fn div_mod(self, divisor: Self) -> (SignedWord, SignedWord) {
        let dividend_abs = self.abs();
        let divisor_abs = divisor.abs();
        let quotient = Self(dividend_abs / divisor_abs);
        let remainder = if self.is_neg() {
            Self(dividend_abs % divisor_abs).neg()
        } else {
            Self(dividend_abs % divisor_abs)
        };
        let sign = self.is_neg() ^ divisor.is_neg();
        if sign {
            (quotient.neg(), remainder)
        } else {
            (quotient, remainder)
        }
    }
}

impl Neg for SignedWord {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self == Self::MIN {
            Self::MIN
        } else if self == Self::ZERO {
            Self::ZERO
        } else {
            Self(U256::MAX - self.0 + U256::one())
        }
    }
}

impl Rem for SignedWord {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        let sign = self.is_neg() ^ rhs.is_neg();
        let result = Self(self.abs() % rhs.abs());
        if sign {
            result.neg()
        } else {
            result
        }
    }
}

impl PartialOrd for SignedWord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.is_neg() && !other.is_neg() {
            return Some(Ordering::Less);
        }
        if !self.is_neg() && other.is_neg() {
            return Some(Ordering::Greater);
        }
        let sign = self.is_neg();
        let result = self.abs().partial_cmp(&other.abs());
        if sign {
            result.map(|o| o.reverse())
        } else {
            result
        }
    }
}

// TODO: replace `OP: u8` after `adt_const_params` available
#[derive(Debug, Copy, Clone)]
pub(crate) struct ArithmeticOpcode<const OP: u8, const N_POPS: usize>;

trait Arithmetic<const N: usize> {
    fn handle(inputs: [Word; N]) -> Word;
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::ADD.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        lhs.overflowing_add(rhs).0
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SUB.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        lhs.overflowing_sub(rhs).0
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::MUL.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        lhs.overflowing_mul(rhs).0
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::DIV.as_u8() }, 2> {
    /// integer result of the integer division. If the denominator is 0, the result will be 0.
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        lhs.checked_div(rhs).unwrap_or_default()
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SDIV.as_u8() }, 2> {
    /// integer result of the signed integer division. If the denominator is 0, the result will be
    /// 0.
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        if rhs == Word::zero() {
            Word::zero()
        } else {
            let (quotient, _) = SignedWord(lhs).div_mod(SignedWord(rhs));
            quotient.0
        }
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::MOD.as_u8() }, 2> {
    /// integer result of the integer modulo. If the denominator is 0, the result will be 0.
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        if rhs == Word::zero() {
            Word::zero()
        } else {
            lhs % rhs
        }
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SMOD.as_u8() }, 2> {
    /// integer result of the signed integer modulo. If the denominator is 0, the result will be 0.
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        if rhs == Word::zero() {
            Word::zero()
        } else {
            let (_, remainder) = SignedWord(lhs).div_mod(SignedWord(rhs));
            remainder.0
        }
    }
}

impl Arithmetic<3> for ArithmeticOpcode<{ OpcodeId::ADDMOD.as_u8() }, 3> {
    /// integer result of the addition followed by a modulo.
    /// If the denominator is 0, the result will be 0.
    fn handle([lhs, rhs, modulus]: [Word; 3]) -> Word {
        if modulus == Word::zero() {
            Word::zero()
        } else {
            let lhs = lhs % modulus;
            let rhs = rhs % modulus;
            if let Some(sum) = lhs.checked_add(rhs) {
                sum % modulus
            } else {
                // TODO: optimize speed
                Word::try_from((U512::from(lhs) + U512::from(rhs)) % U512::from(modulus)).unwrap()
            }
        }
    }
}

impl Arithmetic<3> for ArithmeticOpcode<{ OpcodeId::MULMOD.as_u8() }, 3> {
    /// integer result of the multiplication followed by a modulo.
    /// If the denominator is 0, the result will be 0.
    fn handle([lhs, rhs, modulus]: [Word; 3]) -> Word {
        if modulus == Word::zero() {
            Word::zero()
        } else {
            // TODO: optimize speed
            Word::try_from(lhs.full_mul(rhs) % U512::from(modulus)).unwrap()
        }
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SIGNEXTEND.as_u8() }, 2> {
    /// b: size in byte - 1 of the integer to sign extend.
    /// x: integer value to sign extend.
    fn handle([b, x]: [Word; 2]) -> Word {
        if b >= Word::from(31) {
            x
        } else {
            let b = b.as_usize();
            let mut x = x.to_le_bytes();
            const POSITIVE_PADDING: [u8; 32] = [0; 32];
            const NEGATIVE_PADDING: [u8; 32] = [0xff; 32];
            if x[b] & 0x80 == 0 {
                x[b + 1..].copy_from_slice(&POSITIVE_PADDING[b + 1..]);
            } else {
                x[b + 1..].copy_from_slice(&NEGATIVE_PADDING[b + 1..]);
            }
            Word::from_little_endian(&x)
        }
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::LT.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        ((lhs < rhs) as u8).into()
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::GT.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        ((lhs > rhs) as u8).into()
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SLT.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        ((SignedWord(lhs) < SignedWord(rhs)) as u8).into()
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SGT.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        ((SignedWord(lhs) > SignedWord(rhs)) as u8).into()
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::EQ.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        ((lhs == rhs) as u8).into()
    }
}
impl Arithmetic<1> for ArithmeticOpcode<{ OpcodeId::ISZERO.as_u8() }, 1> {
    fn handle([n]: [Word; 1]) -> Word {
        (n.is_zero() as u8).into()
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::AND.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        lhs & rhs
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::OR.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        lhs | rhs
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::XOR.as_u8() }, 2> {
    fn handle([lhs, rhs]: [Word; 2]) -> Word {
        lhs ^ rhs
    }
}
impl Arithmetic<1> for ArithmeticOpcode<{ OpcodeId::NOT.as_u8() }, 1> {
    fn handle([n]: [Word; 1]) -> Word {
        !n
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::BYTE.as_u8() }, 2> {
    /// the indicated byte at the least significant position.
    /// If the byte offset is out of range, the result is 0.
    fn handle([index, word]: [Word; 2]) -> Word {
        if index > Word::from(31) {
            Word::zero()
        } else {
            let index = index.as_usize();
            let bytes = word.to_be_bytes();
            Word::from(bytes[index])
        }
    }
}

impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SHL.as_u8() }, 2> {
    fn handle([shift, word]: [Word; 2]) -> Word {
        if shift > Word::from(255) {
            Word::zero()
        } else {
            word << shift
        }
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SHR.as_u8() }, 2> {
    fn handle([shift, word]: [Word; 2]) -> Word {
        if shift > Word::from(255) {
            Word::zero()
        } else {
            word >> shift
        }
    }
}
impl Arithmetic<2> for ArithmeticOpcode<{ OpcodeId::SAR.as_u8() }, 2> {
    /// Shift the bits towards the least significant one.
    /// The bits moved before the first one are discarded,
    /// the new bits are set to 0 if the previous most significant bit was 0,
    /// otherwise the new bits are set to 1.
    fn handle([shift, word]: [Word; 2]) -> Word {
        let padding = if SignedWord(word).is_neg() {
            Word::MAX
        } else {
            Word::zero()
        };
        if shift > Word::from(255) {
            padding
        } else {
            let shift = shift.as_usize();
            let result = word >> shift;
            let mask = Word::MAX << (256 - shift);
            result | (mask & padding)
        }
    }
}

impl<const OP: u8, const N_POPS: usize> Opcode for ArithmeticOpcode<OP, N_POPS>
where
    Self: Arithmetic<N_POPS>,
{
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let stack_inputs: [Word; N_POPS] = (0..N_POPS)
            .map(|i| geth_step.stack.nth_last(i))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap();

        for (i, value) in stack_inputs.iter().enumerate() {
            state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(i), *value)?;
        }

        let output = Self::handle(stack_inputs);

        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.nth_last_filled(0),
            output,
        )?;
        assert_eq!(
            output,
            geth_steps[1].stack.nth_last(0)?,
            "stack mismatch, opcode: {}, inputs: {}, actual: {:x}, expected: {:x}",
            OpcodeId::from(OP),
            stack_inputs.iter().map(|w| format!("{:x}", w)).join(", "),
            output,
            geth_steps[1].stack.nth_last(0)?
        );

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::BlockData;
    use eth_types::{evm_types::OpcodeId, geth_types::GethData, word, Bytecode, Word};
    use mock::TestContext;
    use rand::{thread_rng, Rng};
    use rayon::iter::{IntoParallelIterator, ParallelIterator};

    fn test_handle<const N_POPS: usize, const OP: u8>(inputs: [Word; N_POPS], expected: Word)
    where
        ArithmeticOpcode<OP, N_POPS>: Arithmetic<N_POPS>,
    {
        let actual = ArithmeticOpcode::<OP, N_POPS>::handle(inputs);
        assert_eq!(
            actual,
            expected,
            "{} handle produce incrroect outputs:\ninputs: {:x?}, actual: {:x}, expected: {:x}",
            OpcodeId::from(OP),
            inputs,
            actual,
            expected
        );
    }

    fn test_trace<const N_POPS: usize>(opcode: OpcodeId, inputs: [Word; N_POPS]) {
        let mut code = Bytecode::default();
        for input in inputs.into_iter().rev() {
            code.push(32, input);
        }
        code.write_op(opcode);
        let block: GethData = TestContext::<2, 1>::simple_ctx_with_bytecode(code)
            .unwrap()
            .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
    }

    fn test_both<const N_POPS: usize, const OP: u8>(inputs: [Word; N_POPS], expected: Word)
    where
        ArithmeticOpcode<OP, N_POPS>: Arithmetic<N_POPS>,
    {
        test_handle::<N_POPS, OP>(inputs, expected);
        test_trace::<N_POPS>(OpcodeId::from(OP), inputs);
    }

    fn test_random<const N_POPS: usize, const OP: u8>()
    where
        ArithmeticOpcode<OP, N_POPS>: Arithmetic<N_POPS>,
    {
        // takes about 13s in release mode
        (0..10000).into_par_iter().for_each(|_| {
            let inputs: [Word; N_POPS] = (0..N_POPS)
                .map(|_| U256(thread_rng().gen::<[u64; 4]>()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            test_trace(OpcodeId::from(OP), inputs);
        });
    }

    #[test]
    fn random() {
        test_random::<2, { OpcodeId::ADD.as_u8() }>();
        test_random::<2, { OpcodeId::SDIV.as_u8() }>();
        test_random::<2, { OpcodeId::MUL.as_u8() }>();
        test_random::<2, { OpcodeId::DIV.as_u8() }>();
        test_random::<2, { OpcodeId::SDIV.as_u8() }>();
        test_random::<2, { OpcodeId::MOD.as_u8() }>();
        test_random::<2, { OpcodeId::SMOD.as_u8() }>();
        test_random::<3, { OpcodeId::ADDMOD.as_u8() }>();
        test_random::<3, { OpcodeId::MULMOD.as_u8() }>();
        test_random::<2, { OpcodeId::SIGNEXTEND.as_u8() }>();
        test_random::<2, { OpcodeId::LT.as_u8() }>();
        test_random::<2, { OpcodeId::GT.as_u8() }>();
        test_random::<2, { OpcodeId::SLT.as_u8() }>();
        test_random::<2, { OpcodeId::SGT.as_u8() }>();
        test_random::<2, { OpcodeId::EQ.as_u8() }>();
        test_random::<1, { OpcodeId::ISZERO.as_u8() }>();
        test_random::<2, { OpcodeId::AND.as_u8() }>();
        test_random::<2, { OpcodeId::OR.as_u8() }>();
        test_random::<2, { OpcodeId::XOR.as_u8() }>();
        test_random::<1, { OpcodeId::NOT.as_u8() }>();
        test_random::<2, { OpcodeId::BYTE.as_u8() }>();
        test_random::<2, { OpcodeId::SHL.as_u8() }>();
        test_random::<2, { OpcodeId::SHR.as_u8() }>();
        test_random::<2, { OpcodeId::SAR.as_u8() }>();
    }

    #[test]
    fn test_sdiv() {
        test_both::<2, { OpcodeId::SDIV.as_u8() }>([0x60u64.into(), 0x80u64.into()], 0u64.into());
    }

    #[test]
    fn test_mod() {
        test_both::<2, { OpcodeId::MOD.as_u8() }>([0x60u64.into(), 0x80u64.into()], 0x60u64.into());
    }

    #[test]
    fn test_smod() {
        test_both::<2, { OpcodeId::SMOD.as_u8() }>(
            [0x60u64.into(), 0x80u64.into()],
            0x60u64.into(),
        );
    }

    #[test]
    fn test_addmod() {
        // testool: randomStatetest382_d0_g0_v0, randomStatetest242_d0_g0_v0
        test_both::<3, { OpcodeId::ADDMOD.as_u8() }>(
            [
                word!("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"),
                word!("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"),
                word!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            ],
            word!("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"),
        );
        // testool: randomStatetest605_d0_g0_v0
        test_both::<3, { OpcodeId::ADDMOD.as_u8() }>(
            [
                word!("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"),
                word!("0xffffffffffffffffffffffff00000000000000000000000000000000000000ea"),
                word!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            ],
            word!("0xffffffffffffffffffffffff00000000000000000000000000000000000000e9"),
        )
    }

    #[test]
    fn test_lt() {
        test_both::<2, { OpcodeId::LT.as_u8() }>([0x01u64.into(), 0x02u64.into()], 0x01u64.into());
        test_both::<2, { OpcodeId::LT.as_u8() }>([0x01u64.into(), 0x01u64.into()], 0x00u64.into());
        test_both::<2, { OpcodeId::LT.as_u8() }>([0x02u64.into(), 0x01u64.into()], 0x00u64.into());
    }

    #[test]
    fn test_gt() {
        test_both::<2, { OpcodeId::GT.as_u8() }>([0x01u64.into(), 0x02u64.into()], 0x00u64.into());
        test_both::<2, { OpcodeId::GT.as_u8() }>([0x01u64.into(), 0x01u64.into()], 0x00u64.into());
        test_both::<2, { OpcodeId::GT.as_u8() }>([0x02u64.into(), 0x01u64.into()], 0x01u64.into());
    }

    #[test]
    fn test_slt() {
        test_both::<2, { OpcodeId::SLT.as_u8() }>([0x01u64.into(), 0x02u64.into()], 0x01u64.into());
        test_both::<2, { OpcodeId::SLT.as_u8() }>([0x01u64.into(), 0x01u64.into()], 0x00u64.into());
        test_both::<2, { OpcodeId::SLT.as_u8() }>([0x02u64.into(), 0x01u64.into()], 0x00u64.into());
    }

    #[test]
    fn test_sgt() {
        test_both::<2, { OpcodeId::SGT.as_u8() }>([0x01u64.into(), 0x02u64.into()], 0x00u64.into());
        test_both::<2, { OpcodeId::SGT.as_u8() }>([0x01u64.into(), 0x01u64.into()], 0x00u64.into());
        test_both::<2, { OpcodeId::SGT.as_u8() }>([0x02u64.into(), 0x01u64.into()], 0x01u64.into());
    }

    #[test]
    fn test_and() {
        test_both::<2, { OpcodeId::AND.as_u8() }>([0x01u64.into(), 0x02u64.into()], 0x00u64.into());
        test_both::<2, { OpcodeId::AND.as_u8() }>([0x01u64.into(), 0x01u64.into()], 0x01u64.into());
        test_both::<2, { OpcodeId::AND.as_u8() }>([0x02u64.into(), 0x01u64.into()], 0x00u64.into());
    }

    #[test]
    fn test_or() {
        test_both::<2, { OpcodeId::OR.as_u8() }>([0x01u64.into(), 0x02u64.into()], 0x03u64.into());
        test_both::<2, { OpcodeId::OR.as_u8() }>([0x01u64.into(), 0x01u64.into()], 0x01u64.into());
        test_both::<2, { OpcodeId::OR.as_u8() }>([0x02u64.into(), 0x01u64.into()], 0x03u64.into());
    }

    #[test]
    fn test_xor() {
        test_both::<2, { OpcodeId::XOR.as_u8() }>([0x01u64.into(), 0x01u64.into()], 0x00u64.into());
        test_both::<2, { OpcodeId::XOR.as_u8() }>([0x01u64.into(), 0x00u64.into()], 0x01u64.into());
        test_both::<2, { OpcodeId::XOR.as_u8() }>([0x00u64.into(), 0x00u64.into()], 0x00u64.into());
    }

    #[test]
    fn test_not() {
        test_both::<1, { OpcodeId::NOT.as_u8() }>(
            [word!(
                "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            )],
            word!("0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0"),
        );
    }
}
