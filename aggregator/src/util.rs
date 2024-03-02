use crate::constants::{DIGEST_LEN, INPUT_LEN_PER_ROUND, MAX_AGG_SNARKS};
use eth_types::Field;
use halo2_proofs::{circuit::AssignedCell, halo2curves::bn256::Fr, plonk::Error};
use itertools::Itertools;
use zkevm_circuits::keccak_circuit::keccak_packed_multi::{
    get_num_rows_per_round, get_num_rows_per_update,
};

// Calculates the maximum keccak updates (1 absorb, or 1 f-box invoke)
// needed for the number of snarks
pub(crate) fn get_max_keccak_updates(max_snarks: usize) -> usize {
    // The public input hash for the batch is derived from hashing
    // chain_id || chunk_0's prev_state || chunk_k-1's post_state ||
    // chunk_k-1's withdraw_root || batch_data_hash.
    // In total there're 168 bytes. Therefore 2 pi rounds are required.
    let pi_rounds = 2;
    // Hash for each chunk is derived from hashing the chunk's
    // chain_id || prev_state || post_state || withdraw_root || data_hash
    // Each chunk hash therefore also requires 2 keccak rounds for 168 bytes.
    let chunk_hash_rounds = 2 * max_snarks;
    let data_hash_rounds = get_data_hash_keccak_updates(max_snarks);

    pi_rounds + chunk_hash_rounds + data_hash_rounds
}
pub(crate) fn get_data_hash_keccak_updates(max_snarks: usize) -> usize {
    let data_hash_rounds = (32 * max_snarks) / INPUT_LEN_PER_ROUND;
    // when `32 * max_snarks` happens to match a multiple of 136, a padding round will still be
    // added
    let padding_round = if data_hash_rounds * INPUT_LEN_PER_ROUND <= 32 * max_snarks {
        1
    } else {
        0
    };

    data_hash_rounds + padding_round
}

/// Return
/// - the indices of the rows that contain the input preimages
/// - the indices of the rows that contain the output digest
pub(crate) fn get_indices(preimages: &[Vec<u8>]) -> (Vec<usize>, Vec<usize>) {
    let mut preimage_indices = vec![];
    let mut digest_indices = vec![];
    let mut round_ctr = 0;

    let keccak_f_rows = get_num_rows_per_update();
    let inner_round_rows = get_num_rows_per_round();

    for preimage in preimages.iter().take(MAX_AGG_SNARKS + 1) {
        //  136 = 17 * 8 is the size in bytes of each
        //  input chunk that can be processed by Keccak circuit using absorb

        //  For example, if num_rows_per_inner_round for Keccak is 12, then
        //  each chunk of size 136 needs 300 Keccak circuit rows to prove
        //  which consists of 12 Keccak rows for each of 24 + 1 Keccak circuit rounds
        //  digest only happens at the end of the last input chunk with
        //  4 Keccak circuit rounds, so 48 Keccak rows, and 300 - 48 = 252
        let num_rounds = 1 + preimage.len() / INPUT_LEN_PER_ROUND;
        let mut preimage_padded = preimage.clone();
        preimage_padded.resize(INPUT_LEN_PER_ROUND * num_rounds, 0);
        for (i, round) in preimage_padded.chunks(INPUT_LEN_PER_ROUND).enumerate() {
            let f_round_offset = round_ctr * keccak_f_rows;
            // indices for preimages
            for (j, _chunk) in round.chunks(8).enumerate() {
                let inner_offset = f_round_offset + (j + 1) * inner_round_rows;
                for k in 0..8 {
                    preimage_indices.push(inner_offset + k);
                }
            }
            // indices for digests
            if i == num_rounds - 1 {
                for j in 0..4 {
                    let inner_offset = f_round_offset
                        + j * inner_round_rows
                        + (keccak_f_rows - inner_round_rows * (DIGEST_LEN / 8));
                    for k in 0..8 {
                        digest_indices.push(inner_offset + k);
                    }
                }
            }
            round_ctr += 1;
        }
    }
    // last hash is for data_hash and has various length, so we output all the possible cells
    for _i in 0..get_data_hash_keccak_updates(MAX_AGG_SNARKS) {
        for (j, _) in (0..INPUT_LEN_PER_ROUND).chunks(8).into_iter().enumerate() {
            let inner_offset = round_ctr * keccak_f_rows + (j + 1) * inner_round_rows;
            for k in 0..8 {
                preimage_indices.push(inner_offset + k);
            }
        }
        for j in 0..4 {
            let inner_offset = round_ctr * keccak_f_rows
                + j * inner_round_rows
                + (keccak_f_rows - inner_round_rows * (DIGEST_LEN / 8));
            for k in 0..8 {
                digest_indices.push(inner_offset + k);
            }
        }
        round_ctr += 1;
    }

    debug_assert!(is_ascending(&preimage_indices));
    debug_assert!(is_ascending(&digest_indices));

    (preimage_indices, digest_indices)
}

#[inline]
// assert two cells have same value
// (NOT constraining equality in circuit)
pub(crate) fn assert_equal<F: Field>(
    a: &AssignedCell<F, F>,
    b: &AssignedCell<F, F>,
    description: &str,
) -> Result<(), Error> {
    a.value().zip(b.value()).error_if_known_and(|(&a, &b)| {
        if a != b {
            log::error!("{description}");
        }
        a != b
    })
}

#[inline]
// if cond = 1, assert two cells have same value;
// (NOT constraining equality in circuit)
pub(crate) fn assert_conditional_equal<F: Field>(
    a: &AssignedCell<F, F>,
    b: &AssignedCell<F, F>,
    cond: &AssignedCell<F, F>,
    description: &str,
) -> Result<(), Error> {
    a.value()
        .zip(b.value().zip(cond.value()))
        .error_if_known_and(|(&a, (&b, &cond))| {
            if cond == F::one() && a != b {
                log::error!("{description}");
            }
            cond == F::one() && a != b
        })
}

#[inline]
// assert a \in [b1, b2, b3...] if both a and bi are known
// (NOT constraining equality in circuit)
pub(crate) fn assert_exist<F: Field>(
    a: &AssignedCell<F, F>,
    bi_s: &[AssignedCell<F, F>],
) -> Result<(), Error> {
    let mut res = false;

    let a_value = a.value();
    let bi_values = bi_s.iter().map(|x| x.value()).collect::<Vec<_>>();

    for &bi_value in bi_values.iter() {
        a_value.zip(bi_value).assert_if_known(|(a, bi)| {
            res = res || (a == bi);
            true
        })
    }
    a_value.zip(bi_values[0]).error_if_known_and(|_| !res)
}

#[inline]
// assert that the slice is ascending
fn is_ascending(a: &[usize]) -> bool {
    a.windows(2).all(|w| w[0] <= w[1])
}

#[inline]
#[allow(clippy::type_complexity)]
pub(crate) fn parse_hash_preimage_cells(
    hash_input_cells: &[AssignedCell<Fr, Fr>],
) -> (
    &[AssignedCell<Fr, Fr>],
    Vec<&[AssignedCell<Fr, Fr>]>,
    &[AssignedCell<Fr, Fr>],
) {
    // each pi hash has INPUT_LEN_PER_ROUND bytes as input
    // keccak will pad the input with another INPUT_LEN_PER_ROUND bytes
    // we extract all those bytes
    let batch_pi_hash_preimage = &hash_input_cells[0..INPUT_LEN_PER_ROUND * 2];
    let mut chunk_pi_hash_preimages = vec![];
    for i in 0..MAX_AGG_SNARKS {
        chunk_pi_hash_preimages.push(
            &hash_input_cells[INPUT_LEN_PER_ROUND * 2 * (i + 1)..INPUT_LEN_PER_ROUND * 2 * (i + 2)],
        );
    }
    let potential_batch_data_hash_preimage =
        &hash_input_cells[INPUT_LEN_PER_ROUND * 2 * (MAX_AGG_SNARKS + 1)..];

    (
        batch_pi_hash_preimage,
        chunk_pi_hash_preimages,
        potential_batch_data_hash_preimage,
    )
}

#[inline]
#[allow(clippy::type_complexity)]
pub(crate) fn parse_hash_digest_cells(
    hash_output_cells: &[AssignedCell<Fr, Fr>],
) -> (
    &[AssignedCell<Fr, Fr>],
    Vec<&[AssignedCell<Fr, Fr>]>,
    &[AssignedCell<Fr, Fr>],
) {
    let batch_pi_hash_digest = &hash_output_cells[0..DIGEST_LEN];
    let mut chunk_pi_hash_digests = vec![];
    for i in 0..MAX_AGG_SNARKS {
        chunk_pi_hash_digests.push(&hash_output_cells[DIGEST_LEN * (i + 1)..DIGEST_LEN * (i + 2)]);
    }
    let potential_batch_data_hash_digest = &hash_output_cells[DIGEST_LEN * (MAX_AGG_SNARKS + 1)..];
    (
        batch_pi_hash_digest,
        chunk_pi_hash_digests,
        potential_batch_data_hash_digest,
    )
}

#[inline]
pub(crate) fn parse_pi_hash_rlc_cells(
    data_rlc_cells: &[AssignedCell<Fr, Fr>],
) -> Vec<&AssignedCell<Fr, Fr>> {
    data_rlc_cells
        .iter()
        .skip(3) // the first 3 rlc cells are pad (1) + batch pi hash (2)
        .take(MAX_AGG_SNARKS * 2) // each chunk hash takes 2 rounds
        .chunks(2)
        .into_iter()
        .map(|t| t.last().unwrap())
        .collect()
}

#[cfg(test)]
pub(crate) fn rlc(inputs: &[Fr], randomness: &Fr) -> Fr {
    assert!(!inputs.is_empty());
    let mut acc = inputs[0];
    for input in inputs.iter().skip(1) {
        acc = acc * *randomness + *input;
    }

    acc
}
