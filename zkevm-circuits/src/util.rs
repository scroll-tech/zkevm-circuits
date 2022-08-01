//! Common utility traits and functions.
use eth_types::Field;
use halo2_proofs::{
    plonk::{ConstraintSystem, Expression},
    poly::Rotation,
};

pub use gadgets::util::Expr;

pub(crate) fn random_linear_combine_word<F: Field>(bytes: [u8; 32], randomness: F) -> F {
    crate::evm_circuit::util::Word::random_linear_combine(bytes, randomness)
}

/// Query N instances at current rotation and return their expressions.  This
/// function is used to get the power of randomness (passed as
/// instances) in our tests.
pub fn power_of_randomness_from_instance<F: Field, const N: usize>(
    meta: &mut ConstraintSystem<F>,
) -> [Expression<F>; N] {
    // This gate is used just to get the array of expressions from the power of
    // randomness instance column, so that later on we don't need to query
    // columns everywhere, and can pass the power of randomness array
    // expression everywhere.  The gate itself doesn't add any constraints.

    let columns = [(); N].map(|_| meta.instance_column());
    let mut power_of_randomness = None;

    meta.create_gate("power of randomness from instance", |meta| {
        power_of_randomness =
            Some(columns.map(|column| meta.query_instance(column, Rotation::cur())));

        [0.expr()]
    });

    power_of_randomness.unwrap()
}

// the magic number is `echo 'zkevm-circuits' | hexdump`
pub(crate) const DEFAULT_RAND: u128 = 0x10000; //0x6b7a76652d6d6963637269757374u128;
