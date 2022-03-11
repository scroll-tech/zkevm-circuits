use halo2_proofs::circuit::AssignedCell;
use itertools::Itertools;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

/// The Keccak Pi step
///
/// It has no gates. We just have to permute the previous state into the correct
/// order. The copy constrain in the next gate can then enforce the Pi step
/// permutation.
pub fn pi_gate_permutation<F: FieldExt>(
    state: [AssignedCell<F, F>; 25],
) -> [AssignedCell<F, F>; 25] {
    let state: [AssignedCell<F, F>; 25] = (0..5)
        .cartesian_product(0..5)
        .map(|(x, y)| state[5 * ((x + 3 * y) % 5) + x].clone())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    state
}
