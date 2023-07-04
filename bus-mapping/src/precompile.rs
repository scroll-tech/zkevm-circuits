//! precompile helpers

use eth_types::{evm_types::GasCost, Address, ToBigEndian, Word};
use revm_precompile::{Precompile, Precompiles};
use strum::EnumIter;

/// Check if address is a precompiled or not.
pub fn is_precompiled(address: &Address) -> bool {
    Precompiles::berlin()
        .get(address.as_fixed_bytes())
        .is_some()
}

pub(crate) fn execute_precompiled(address: &Address, input: &[u8], gas: u64) -> (Vec<u8>, u64) {
    let Some(Precompile::Standard(precompile_fn)) = Precompiles::berlin()
        .get(address.as_fixed_bytes())  else {
        panic!("calling non-exist precompiled contract address")
    };

    match precompile_fn(input, gas) {
        Ok((gas_cost, return_value)) => (return_value, gas_cost),
        Err(_) => (vec![], gas),
    }
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
}

impl EcrecoverAuxData {
    /// Create a new instance of ecrecover auxiliary data.
    pub fn new(input: Vec<u8>, output: Vec<u8>) -> Self {
        assert_eq!(input.len(), 128);
        assert_eq!(output.len(), 32);

        // assert that recovered address is 20 bytes.
        assert!(output[0x00..0x0c].iter().all(|&b| b == 0));
        let recovered_addr = Address::from_slice(&output[0x0c..0x20]);

        Self {
            msg_hash: Word::from_big_endian(&input[0x00..0x20]),
            sig_v: Word::from_big_endian(&input[0x20..0x40]),
            sig_r: Word::from_big_endian(&input[0x40..0x60]),
            sig_s: Word::from_big_endian(&input[0x60..0x80]),
            recovered_addr,
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

/// Auxiliary data attached to an internal state for precompile verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrecompileAuxData {
    /// Ecrecover.
    Ecrecover(EcrecoverAuxData),
}

impl Default for PrecompileAuxData {
    fn default() -> Self {
        Self::Ecrecover(EcrecoverAuxData::default())
    }
}
