// sha256 adapt table16 in halo2_gadgets

// The size of a SHA-256 digest, in 32-bit words.
const DIGEST_SIZE: usize = 8;
use halo2_gadgets::sha256::{BLOCK_SIZE, Sha256, Sha256Instructions};
use halo2_proofs::arithmetic::FieldExt as Field;

mod table16;