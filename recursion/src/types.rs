use ce_snark_verifier::pcs::kzg::{Bdfg21, KzgAs, KzgSuccinctVerifyingKey, LimbsEncoding};
use ce_snark_verifier_sdk::{BITS, LIMBS};
use halo2curves::bn256::{Bn256, G1Affine};

pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;
pub type As = KzgAs<Bn256, Bdfg21>;

use ce_snark_verifier::verifier::plonk;
pub type PlonkSuccinctVerifier = plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;

use ce_snark_verifier::loader::halo2::halo2_ecc::ecc;
pub type BaseFieldEccChip<'chip> = ecc::BaseFieldEccChip<'chip, G1Affine>;

// const T: usize = 3;
// const RATE: usize = 2;

// use ce_snark_verifier::util::hash;
// pub type Poseidon<L> = hash::Poseidon<Fr, L, T, RATE>;
