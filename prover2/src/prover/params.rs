use serde::{Deserialize, Serialize};
use snark_verifier::loader::halo2::halo2_ecc::fields::fp::FpStrategy;

/// Parameters to configure the non-native field arithmetic chip.
#[derive(Debug, Serialize, Deserialize)]
pub struct Params {
    pub strategy: FpStrategy,
    pub degree: u32,
    pub num_advice: Vec<usize>,
    pub num_lookup_advice: Vec<usize>,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}
