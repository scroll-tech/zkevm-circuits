use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Region},
    halo2curves::bn256::Fr,
    plonk::Error,
};
use itertools::Itertools;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context,
};

use crate::{
    aggregation::RlcConfig,
    constants::{DIGEST_LEN, INPUT_LEN_PER_ROUND, MAX_AGG_SNARKS},
    DEFAULT_KECCAK_ROWS, NUM_ROUNDS,
};

use std::env::var;

pub(crate) fn keccak_round_capacity(num_rows: usize) -> Option<usize> {
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

    for preimage in preimages.iter().take(MAX_AGG_SNARKS + 1) {
        //  136 = 17 * 8 is the size in bytes of each
        //  input chunk that can be processed by Keccak circuit using absorb
        //  each chunk of size 136 needs 300 Keccak circuit rows to prove
        //  which consists of 12 Keccak rows for each of 24 + 1 Keccak circuit rounds
        //  digest only happens at the end of the last input chunk with
        //  4 Keccak circuit rounds, so 48 Keccak rows, and 300 - 48 = 252
        let num_rounds = 1 + preimage.len() / INPUT_LEN_PER_ROUND;
        let mut preimage_padded = preimage.clone();
        preimage_padded.resize(INPUT_LEN_PER_ROUND * num_rounds, 0);
        for (i, round) in preimage_padded.chunks(INPUT_LEN_PER_ROUND).enumerate() {
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
    // last hash is for data_hash and has various length, so we output all the possible cells
    for _i in 0..3 {
        for (j, _) in (0..INPUT_LEN_PER_ROUND)
            .into_iter()
            .chunks(8)
            .into_iter()
            .enumerate()
        {
            for k in 0..8 {
                preimage_indices.push(round_ctr * 300 + j * 12 + k + 12)
            }
        }
        for j in 0..4 {
            for k in 0..8 {
                digest_indices.push(round_ctr * 300 + j * 12 + k + 252)
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
pub(crate) fn assert_equal<F: Field>(a: &AssignedCell<F, F>, b: &AssignedCell<F, F>) {
    let mut t1 = F::default();
    let mut t2 = F::default();
    a.value().map(|f| t1 = *f);
    b.value().map(|f| t2 = *f);
    assert_eq!(t1, t2)
}

#[inline]
// if cond = 1, assert two cells have same value;
// (NOT constraining equality in circuit)
pub(crate) fn assert_conditional_equal<F: Field>(
    a: &AssignedCell<F, F>,
    b: &AssignedCell<F, F>,
    cond: &AssignedCell<F, F>,
) {
    let mut t1 = F::default();
    let mut t2 = F::default();
    let mut c = F::default();
    a.value().map(|f| t1 = *f);
    b.value().map(|f| t2 = *f);
    cond.value().map(|f| c = *f);
    if c == F::one() {
        assert_eq!(t1, t2)
    }
}

#[inline]
// assert a \in (b1, b2, b3)
pub(crate) fn assert_exist<F: Field>(
    a: &AssignedCell<F, F>,
    b1: &AssignedCell<F, F>,
    b2: &AssignedCell<F, F>,
    b3: &AssignedCell<F, F>,
) {
    let mut t1 = F::default();
    let mut t2 = F::default();
    let mut t3 = F::default();
    let mut t4 = F::default();
    a.value().map(|f| t1 = *f);
    b1.value().map(|f| t2 = *f);
    b2.value().map(|f| t3 = *f);
    b3.value().map(|f| t4 = *f);
    assert!(
        t1 == t2 || t1 == t3 || t1 == t4,
        "t1: {t1:?}\nt2: {t2:?}\nt3: {t3:?}\nt4: {t4:?}\n",
    )
}

#[inline]
// assert that the slice is ascending
fn is_ascending(a: &[usize]) -> bool {
    a.windows(2).all(|w| w[0] <= w[1])
}

#[inline]
#[allow(dead_code)]
pub(crate) fn assigned_cell_to_value(
    gate: &FlexGateConfig<Fr>,
    ctx: &mut Context<Fr>,
    assigned_cell: &AssignedCell<Fr, Fr>,
) -> Result<AssignedValue<Fr>, Error> {
    let value = assigned_cell.value().copied();
    let assigned_value = gate.load_witness(ctx, value);
    ctx.region
        .constrain_equal(assigned_cell.cell(), assigned_value.cell)?;
    Ok(assigned_value)
}

#[inline]
#[allow(dead_code)]
pub(crate) fn assigned_value_to_cell(
    config: &RlcConfig,
    region: &mut Region<Fr>,
    assigned_value: &AssignedValue<Fr>,
    offset: &mut usize,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let mut value = Fr::default();
    assigned_value.value().map(|&x| value = x);
    let assigned_cell = config.load_private(region, &value, offset)?;
    region.constrain_equal(assigned_cell.cell(), assigned_value.cell())?;
    Ok(assigned_cell)
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
#[allow(clippy::type_complexity)]
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

#[allow(dead_code)]
pub(crate) fn rlc(inputs: &[Fr], randomness: &Fr) -> Fr {
    assert!(!inputs.is_empty());
    let mut acc = inputs[0];
    for input in inputs.iter().skip(1) {
        acc = acc * *randomness + *input;
    }

    acc
}
