use ce_snark_verifier::pcs::kzg::{Bdfg21, KzgAs, KzgSuccinctVerifyingKey, LimbsEncoding};
use ce_snark_verifier_sdk::{BITS, LIMBS};
use halo2curves::bn256::{Bn256, Fr, G1Affine};

// becomes LoadedScalar
// type AssignedScalar<'a> = <BaseFieldEccChip as EccInstructions<G1Affine>>::AssignedScalar;

pub type Svk = KzgSuccinctVerifyingKey<G1Affine>;
pub type As = KzgAs<Bn256, Bdfg21>;

use ce_snark_verifier::verifier::plonk;
pub type PlonkSuccinctVerifier = plonk::PlonkSuccinctVerifier<As, LimbsEncoding<LIMBS, BITS>>;

use ce_snark_verifier::loader::halo2::halo2_ecc::ecc;
pub type BaseFieldEccChip<'chip> = ecc::BaseFieldEccChip<'chip, G1Affine>;

const T: usize = 3;
const RATE: usize = 2;
const R_F: usize = 8;
const R_P: usize = 57;
// const SECURE_MDS: usize = 0;

use ce_snark_verifier::util::hash;
pub type Poseidon<L> = hash::Poseidon<Fr, L, T, RATE>;
// pub type PoseidonTranscript<L, S> = halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;
