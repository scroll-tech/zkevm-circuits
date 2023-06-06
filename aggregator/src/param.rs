use snark_verifier::loader::halo2::halo2_ecc::fields::fp::FpStrategy;

pub(crate) const LIMBS: usize = 3;
pub(crate) const BITS: usize = 88;

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
    pub(crate) fn aggregation_param() -> Self {
        Self {
            strategy: FpStrategy::Simple,
            degree: 25,
            num_advice: vec![2],
            num_lookup_advice: vec![1],
            num_fixed: 1,
            lookup_bits: 20,
            limb_bits: 88,
            num_limbs: 3,
        }
    }

    pub(crate) fn _compress_wide_param() -> Self {
        Self {
            strategy: FpStrategy::Simple,
            degree: 22,
            num_advice: vec![35],
            num_lookup_advice: vec![1],
            num_fixed: 1,
            lookup_bits: 20,
            limb_bits: 88,
            num_limbs: 3,
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
            limb_bits: 88,
            num_limbs: 3,
        }
    }
}
