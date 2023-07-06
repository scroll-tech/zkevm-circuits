use snark_verifier::loader::halo2::halo2_ecc::fields::fp::FpStrategy;

use crate::{BITS, LIMBS};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
/// Parameters for aggregation circuit and compression circuit configs.
pub struct ConfigParams {
    pub strategy: FpStrategy,
    pub degree: u32,
    pub num_advice: Vec<usize>,
    pub num_lookup_advice: Vec<usize>,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

impl ConfigParams {
    pub(crate) fn _aggregation_param() -> Self {
        Self {
            strategy: FpStrategy::Simple,
            degree: 23,
            num_advice: vec![8],
            num_lookup_advice: vec![1],
            num_fixed: 1,
            lookup_bits: 20,
            limb_bits: BITS,
            num_limbs: LIMBS,
        }
    }

    pub(crate) fn default_compress_wide_param() -> Self {
        Self {
            strategy: FpStrategy::Simple,
            degree: 22,
            num_advice: vec![35],
            num_lookup_advice: vec![1],
            num_fixed: 1,
            lookup_bits: 20,
            limb_bits: BITS,
            num_limbs: LIMBS,
        }
    }

    pub(crate) fn _compress_thin_param() -> Self {
        Self {
            strategy: FpStrategy::Simple,
            degree: 25,
            num_advice: vec![1],
            num_lookup_advice: vec![1],
            num_fixed: 1,
            lookup_bits: 20,
            limb_bits: BITS,
            num_limbs: LIMBS,
        }
    }
}
