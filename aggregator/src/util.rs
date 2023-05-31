use eth_types::Field;
use halo2_proofs::circuit::AssignedCell;

use crate::{DEFAULT_KECCAK_ROWS, NUM_ROUNDS};

use std::env::var;

pub(crate) fn capacity(num_rows: usize) -> Option<usize> {
    if num_rows > 0 {
        // Subtract two for unusable rows
        Some(num_rows / ((NUM_ROUNDS + 1) * get_num_rows_per_round()) - 2)
    } else {
        None
    }
}

pub(crate) fn get_num_rows_per_round() -> usize {
    var("KECCAK_ROWS")
        .unwrap_or_else(|_| format!("{DEFAULT_KECCAK_ROWS}"))
        .parse()
        .expect("Cannot parse KECCAK_ROWS env var as usize")
}

/// Return
/// - the indices of the rows that contain the input preimages
/// - the indices of the rows that contain the output digest
pub(crate) fn get_indices(preimages: &[Vec<u8>]) -> (Vec<usize>, Vec<usize>) {
    let mut preimage_indices = vec![];
    let mut digest_indices = vec![];
    let mut round_ctr = 0;

    for preimage in preimages.iter() {
        let num_rounds = 1 + preimage.len() / 136;
        for (i, round) in preimage.chunks(136).enumerate() {
            // indices for preimages
            for (j, _chunk) in round.chunks(8).into_iter().enumerate() {
                for k in 0..8 {
                    preimage_indices.push(round_ctr * 300 + j * 12 + k + 12)
                }
            }
            // indices for digests
            if i == num_rounds - 1 {
                for j in 0..4 {
                    for k in 0..8 {
                        digest_indices.push(round_ctr * 300 + j * 12 + k + 252)
                    }
                }
            }
            round_ctr += 1;
        }
    }

    debug_assert!(is_ascending(&preimage_indices));
    debug_assert!(is_ascending(&digest_indices));

    (preimage_indices, digest_indices)
}

#[inline]
// assert two cells have same value
// (NOT constraining equality in circuit)
pub(crate) fn assert_equal<F: Field>(a: &AssignedCell<F, F>, b: &AssignedCell<F, F>) {
    let mut t1 = F::default();
    let mut t2 = F::default();
    a.value().map(|f| t1 = *f);
    b.value().map(|f| t2 = *f);
    assert_eq!(t1, t2)
}

#[inline]
// assert that the slice is ascending
fn is_ascending(a: &[usize]) -> bool {
    a.windows(2).all(|w| w[0] <= w[1])
}
