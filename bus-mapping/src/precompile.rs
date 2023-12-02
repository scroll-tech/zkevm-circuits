//! precompile helpers

use eth_types::{evm_types::GasCost, Address, ToBigEndian, Word};
use revm_precompile::{Precompile, PrecompileError, Precompiles};
use strum_macros::EnumIter;

use crate::circuit_input_builder::{EcMulOp, EcPairingOp, N_BYTES_PER_PAIR, N_PAIRING_PER_OP};

/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    Precompiles::berlin()
        .get(address.as_fixed_bytes())
        .is_some()
}

pub(crate) fn execute_precompiled(
    address: &Address,
    input: &[u8],
    gas: u64,
) -> (Vec<u8>, u64, bool) {
    let Some(Precompile::Standard(precompile_fn)) = Precompiles::berlin()
        .get(address.as_fixed_bytes())  else {
        panic!("calling non-exist precompiled contract address")
    };
    log::trace!(
        "calling precompile with gas {gas}, len {}, data {}",
        input.len(),
        hex::encode(input)
    );
    let (return_data, gas_cost, is_oog, is_ok) = match precompile_fn(input, gas) {
        Ok((gas_cost, return_value)) => {
            if cfg!(feature = "scroll") {
                // Revm behavior is different from scroll evm,
                // so we need to override the behavior of invalid input
                match PrecompileCalls::from(address.0[19]) {
                    PrecompileCalls::Blake2F | PrecompileCalls::Ripemd160 => {
                        (vec![], gas, false, false)
                    }
                    PrecompileCalls::Bn128Pairing => {
                        if input.len() > N_PAIRING_PER_OP * N_BYTES_PER_PAIR {
                            (vec![], gas, false, false)
                        } else {
                            (return_value, gas_cost, false, true)
                        }
                    }
                    PrecompileCalls::Modexp => {
                        let (input_valid, [_, _, modulus_len]) = ModExpAuxData::check_input(input);
                        if input_valid {
                            // detect some edge cases like modulus = 0
                            assert_eq!(modulus_len.as_usize(), return_value.len());
                            (return_value, gas_cost, false, true) // no oog error
                        } else {
                            (vec![], gas, false, false)
                        }
                    }
                    _ => (return_value, gas_cost, false, true),
                }
            } else {
                (return_value, gas_cost, false, true)
            }
        }
        Err(err) => match err {
            PrecompileError::OutOfGas => (vec![], gas, true, false),
            _ => {
                log::warn!("unknown precompile err {err:?}");
                (vec![], gas, false, false)
            }
        },
    };
    log::trace!("called precompile with is_ok {is_ok} is_oog {is_oog}, gas_cost {gas_cost}, return_data len {}, return_data {}", return_data.len(), hex::encode(&return_data));
    (return_data, gas_cost, is_oog)
}

/// Addresses of the precompiled contracts.
#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter)]
pub enum PrecompileCalls {
    /// Elliptic Curve Recovery
    Ecrecover = 0x01,
    /// SHA2-256 hash function
    Sha256 = 0x02,
    /// Ripemd-160 hash function
    Ripemd160 = 0x03,
    /// Identity function
    Identity = 0x04,
    /// Modular exponentiation
    Modexp = 0x05,
    /// Point addition
    Bn128Add = 0x06,
    /// Scalar multiplication
    Bn128Mul = 0x07,
    /// Bilinear function
    Bn128Pairing = 0x08,
    /// Compression function
    Blake2F = 0x09,
}

impl Default for PrecompileCalls {
    fn default() -> Self {
        Self::Ecrecover
    }
}

impl From<PrecompileCalls> for Address {
    fn from(value: PrecompileCalls) -> Self {
        let mut addr = [0u8; 20];
        addr[19] = value as u8;
        Self(addr)
    }
}

impl From<PrecompileCalls> for u64 {
    fn from(value: PrecompileCalls) -> Self {
        value as u64
    }
}

impl From<PrecompileCalls> for usize {
    fn from(value: PrecompileCalls) -> Self {
        value as usize
    }
}

impl From<u8> for PrecompileCalls {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Self::Ecrecover,
            0x02 => Self::Sha256,
            0x03 => Self::Ripemd160,
            0x04 => Self::Identity,
            0x05 => Self::Modexp,
            0x06 => Self::Bn128Add,
            0x07 => Self::Bn128Mul,
            0x08 => Self::Bn128Pairing,
            0x09 => Self::Blake2F,
            _ => unreachable!("precompile contracts only from 0x01 to 0x09"),
        }
    }
}

impl PrecompileCalls {
    /// Get the base gas cost for the precompile call.
    pub fn base_gas_cost(&self) -> GasCost {
        match self {
            Self::Ecrecover => GasCost::PRECOMPILE_ECRECOVER_BASE,
            Self::Sha256 => GasCost::PRECOMPILE_SHA256_BASE,
            Self::Ripemd160 => GasCost::PRECOMPILE_RIPEMD160_BASE,
            Self::Identity => GasCost::PRECOMPILE_IDENTITY_BASE,
            Self::Modexp => GasCost::PRECOMPILE_MODEXP,
            Self::Bn128Add => GasCost::PRECOMPILE_BN256ADD,
            Self::Bn128Mul => GasCost::PRECOMPILE_BN256MUL,
            Self::Bn128Pairing => GasCost::PRECOMPILE_BN256PAIRING,
            Self::Blake2F => GasCost::PRECOMPILE_BLAKE2F,
        }
    }

    /// Get the EVM address for this precompile call.
    pub fn address(&self) -> u64 {
        (*self).into()
    }

    /// Maximum length of input bytes considered for the precompile call.
    pub fn input_len(&self) -> Option<usize> {
        match self {
            Self::Ecrecover | Self::Bn128Add => Some(128),
            Self::Bn128Mul => Some(96),
            Self::Modexp => Some(MODEXP_INPUT_LIMIT),
            _ => None,
        }
    }
}

/// Auxiliary data for Ecrecover
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EcrecoverAuxData {
    /// Keccak hash of the message being signed.
    pub msg_hash: Word,
    /// v-component of signature.
    pub sig_v: Word,
    /// r-component of signature.
    pub sig_r: Word,
    /// s-component of signature.
    pub sig_s: Word,
    /// Address that was recovered.
    pub recovered_addr: Address,
    /// Input bytes to the ecrecover call.
    pub input_bytes: Vec<u8>,
    /// Output bytes from the ecrecover call.
    pub output_bytes: Vec<u8>,
    /// Bytes returned to the caller from the ecrecover call.
    pub return_bytes: Vec<u8>,
}

impl EcrecoverAuxData {
    /// Create a new instance of ecrecover auxiliary data.
    pub fn new(input: &[u8], output: &[u8], return_bytes: &[u8]) -> Self {
        let mut resized_input = input.to_vec();
        resized_input.resize(128, 0u8);
        let mut resized_output = output.to_vec();
        resized_output.resize(32, 0u8);

        // assert that recovered address is 20 bytes.
        assert!(resized_output[0x00..0x0c].iter().all(|&b| b == 0));
        let recovered_addr = Address::from_slice(&resized_output[0x0c..0x20]);

        Self {
            msg_hash: Word::from_big_endian(&resized_input[0x00..0x20]),
            sig_v: Word::from_big_endian(&resized_input[0x20..0x40]),
            sig_r: Word::from_big_endian(&resized_input[0x40..0x60]),
            sig_s: Word::from_big_endian(&resized_input[0x60..0x80]),
            recovered_addr,
            input_bytes: input.to_vec(),
            output_bytes: output.to_vec(),
            return_bytes: return_bytes.to_vec(),
        }
    }

    /// Sanity check and returns recovery ID.
    pub fn recovery_id(&self) -> Option<u8> {
        let sig_v_bytes = self.sig_v.to_be_bytes();
        let sig_v = sig_v_bytes[31];
        if sig_v_bytes.iter().take(31).all(|&b| b == 0) && (sig_v == 27 || sig_v == 28) {
            Some(sig_v - 27)
        } else {
            None
        }
    }
}

/// size limit of modexp
pub const MODEXP_SIZE_LIMIT: usize = 32;
/// size of input limit
pub const MODEXP_INPUT_LIMIT: usize = 192;

/// Auxiliary data for Modexp
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ModExpAuxData {
    /// The specified len of inputs: [base, exp, modulus]
    pub input_lens: [Word; 3],
    /// Input value [base, exp, modulus], limited to SIZE_LIMIT
    pub inputs: [[u8; MODEXP_SIZE_LIMIT]; 3],
    /// Input valid.
    pub valid: bool,
    /// len of output, limited to lens of moduls, but can be 0
    pub output_len: usize,
    /// output of modexp.
    pub output: [u8; MODEXP_SIZE_LIMIT],
    /// Input to the modexp call.
    pub input_bytes: Vec<u8>,
    /// Output bytes from the modexp call.
    pub output_bytes: Vec<u8>,
    /// Bytes returned back to the caller from the modexp call.
    pub return_bytes: Vec<u8>,
}

impl ModExpAuxData {
    /// If mem is smaller than U256, left pad zero
    /// Or else, keep the least 32bytes.
    fn parse_memory_to_value(mem: &[u8]) -> [u8; MODEXP_SIZE_LIMIT] {
        let mut value_bytes = [0u8; MODEXP_SIZE_LIMIT];
        if !mem.is_empty() {
            let copy_len = mem.len().min(MODEXP_SIZE_LIMIT);
            let src_offset = mem.len() - copy_len;
            let dst_offset = MODEXP_SIZE_LIMIT - copy_len;
            value_bytes.as_mut_slice()[dst_offset..].copy_from_slice(&mem[src_offset..]);
        }
        value_bytes
    }

    /// check input
    pub fn check_input(input: &[u8]) -> (bool, [Word; 3]) {
        let mut i = input.chunks(32);
        let base_len = Word::from_big_endian(i.next().unwrap_or(&[]));
        let exp_len = Word::from_big_endian(i.next().unwrap_or(&[]));
        let modulus_len = Word::from_big_endian(i.next().unwrap_or(&[]));

        let limit = Word::from(MODEXP_SIZE_LIMIT);

        let input_valid = base_len <= limit && exp_len <= limit && modulus_len <= limit;
        log::debug!("modexp base_len {base_len} exp_len {exp_len} modulus_len {modulus_len}");
        if !input_valid {
            log::warn!("modexp input input_valid {input_valid}");
        }
        (input_valid, [base_len, exp_len, modulus_len])
    }

    /// Create a new instance of modexp auxiliary data.
    pub fn new(input: &[u8], output: &[u8], return_bytes: &[u8]) -> Self {
        let mut resized_input = input.to_vec();

        let (input_valid, [base_len, exp_len, modulus_len]) = Self::check_input(input);

        let base_mem_len = if input_valid { base_len.as_usize() } else { 0 };
        let exp_mem_len = if input_valid { exp_len.as_usize() } else { 0 };
        let modulus_mem_len = if input_valid {
            modulus_len.as_usize()
        } else {
            0
        };

        let (base, exp, modulus) = if base_mem_len == 0 && modulus_mem_len == 0 {
            // special case
            ([0u8; 32], [0u8; 32], [0u8; 32])
        } else {
            // In non scroll mode, this can be dangerous.
            // If base and mod are all 0, exp can be very huge.
            resized_input.resize(96 + base_mem_len + exp_mem_len + modulus_mem_len, 0);
            let mut cur_input_begin = &resized_input[96..];

            let base = Self::parse_memory_to_value(&cur_input_begin[..base_mem_len]);
            cur_input_begin = &cur_input_begin[base_mem_len..];
            let exp = Self::parse_memory_to_value(&cur_input_begin[..exp_mem_len]);
            cur_input_begin = &cur_input_begin[exp_mem_len..];
            let modulus = Self::parse_memory_to_value(&cur_input_begin[..modulus_mem_len]);
            (base, exp, modulus)
        };
        let output_len = output.len();
        let output = Self::parse_memory_to_value(output);

        Self {
            valid: input_valid,
            input_lens: [base_len, exp_len, modulus_len],
            inputs: [base, exp, modulus],
            output,
            output_len,
            input_bytes: input.to_vec(),
            output_bytes: output.to_vec(),
            return_bytes: return_bytes.to_vec(),
        }
    }
}

/// Auxiliary data for EcAdd, i.e. P + Q = R
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EcAddAuxData {
    /// x co-ordinate of the first point.
    pub p_x: Word,
    /// y co-ordinate of the first point.
    pub p_y: Word,
    /// x co-ordinate of the second point.
    pub q_x: Word,
    /// y co-ordinate of the second point.
    pub q_y: Word,
    /// x co-ordinate of the result point.
    pub r_x: Word,
    /// y co-ordinate of the result point.
    pub r_y: Word,
    /// Input bytes to the ecAdd call.
    pub input_bytes: Vec<u8>,
    /// Output bytes from the ecAdd call.
    pub output_bytes: Vec<u8>,
    /// Bytes returned back to the caller.
    pub return_bytes: Vec<u8>,
}

impl EcAddAuxData {
    /// Create a new instance of ecrecover auxiliary data.
    pub fn new(input: &[u8], output: &[u8], return_bytes: &[u8]) -> Self {
        let mut resized_input = input.to_vec();
        resized_input.resize(128, 0u8);
        let mut resized_output = output.to_vec();
        resized_output.resize(64, 0u8);

        Self {
            p_x: Word::from_big_endian(&resized_input[0x00..0x20]),
            p_y: Word::from_big_endian(&resized_input[0x20..0x40]),
            q_x: Word::from_big_endian(&resized_input[0x40..0x60]),
            q_y: Word::from_big_endian(&resized_input[0x60..0x80]),
            r_x: Word::from_big_endian(&resized_output[0x00..0x20]),
            r_y: Word::from_big_endian(&resized_output[0x20..0x40]),
            input_bytes: input.to_vec(),
            output_bytes: output.to_vec(),
            return_bytes: return_bytes.to_vec(),
        }
    }
}

/// Auxiliary data for EcMul, i.e. s * P = R
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EcMulAuxData {
    /// x co-ordinate of the point.
    pub p_x: Word,
    /// y co-ordinate of the point.
    pub p_y: Word,
    /// scalar.
    pub s: Word,
    /// unmodulated scalar
    pub s_raw: Word,
    /// x co-ordinate of the result point.
    pub r_x: Word,
    /// y co-ordinate of the result point.
    pub r_y: Word,
    /// Input bytes to the ecMul call.
    pub input_bytes: Vec<u8>,
    /// Output bytes from the ecMul call.
    pub output_bytes: Vec<u8>,
    /// Bytes returned back to the caller from the ecMul call.
    pub return_bytes: Vec<u8>,
}

impl EcMulAuxData {
    /// Create a new instance of EcMul auxiliary data.
    pub fn new(input: &[u8], output: &[u8], return_bytes: &[u8]) -> Self {
        let mut resized_input = input.to_vec();
        resized_input.resize(96, 0u8);
        let mut resized_output = output.to_vec();
        resized_output.resize(64, 0u8);

        let ec_mul_op = EcMulOp::new_from_bytes(input, output);

        Self {
            p_x: Word::from_big_endian(&resized_input[0x00..0x20]),
            p_y: Word::from_big_endian(&resized_input[0x20..0x40]),
            s: Word::from_little_endian(&ec_mul_op.s.to_bytes()),
            s_raw: Word::from_big_endian(&resized_input[0x40..0x60]),
            r_x: Word::from_big_endian(&resized_output[0x00..0x20]),
            r_y: Word::from_big_endian(&resized_output[0x20..0x40]),
            input_bytes: input.to_vec(),
            output_bytes: output.to_vec(),
            return_bytes: return_bytes.to_vec(),
        }
    }
}

/// Auxiliary data for EcPairing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcPairingAuxData(pub EcPairingOp);

/// Erroneous bytes passed to the EcPairing precompile call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EcPairingError {
    /// the calldatalength passed to EcPairing precompile call is expected to be:
    /// 1. len(input) <= 768
    /// 2. len(input) % 192 == 0
    InvalidInputLen(Vec<u8>),
}

/// Auxiliary data attached to an internal state for precompile verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrecompileAuxData {
    /// Base precompile (used for SHA256, RIPEMD-160 and BLAKE2F).
    Base {
        /// input bytes to the identity call.
        input_bytes: Vec<u8>,
        /// output bytes from the identity call.
        output_bytes: Vec<u8>,
        /// bytes returned back to the caller from the identity call.
        return_bytes: Vec<u8>,
    },
    /// Identity.
    Identity {
        /// input bytes to the identity call.
        input_bytes: Vec<u8>,
        /// output bytes from the identity call.
        output_bytes: Vec<u8>,
        /// bytes returned back to the caller from the identity call.
        return_bytes: Vec<u8>,
    },
    /// SHA256
    SHA256 {
        /// input bytes to the sha256 call.
        input_bytes: Vec<u8>,
        /// output bytes from the sha256 call.
        output_bytes: Vec<u8>,
        /// bytes returned back to the caller from the sha256 call.
        return_bytes: Vec<u8>,
    },
    /// Ecrecover.
    Ecrecover(EcrecoverAuxData),
    /// Modexp.
    Modexp(ModExpAuxData),
    /// EcAdd.
    EcAdd(EcAddAuxData),
    /// EcMul.
    EcMul(EcMulAuxData),
    /// EcPairing.
    EcPairing(Box<Result<EcPairingAuxData, EcPairingError>>),
}

impl Default for PrecompileAuxData {
    fn default() -> Self {
        Self::Ecrecover(EcrecoverAuxData::default())
    }
}
