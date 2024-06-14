use gadgets::Field;
use halo2_proofs::{circuit::AssignedCell, halo2curves::bn256::Fr, plonk::Error};

#[cfg(test)]
#[ctor::ctor]
fn init_env_logger() {
    // Enable RUST_LOG during tests
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
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
#[allow(clippy::type_complexity)]
pub(crate) fn parse_hash_preimage_cells<const N_SNARKS: usize>(
    hash_input_cells: &[Vec<AssignedCell<Fr, Fr>>],
) -> (
    &[AssignedCell<Fr, Fr>],
    Vec<&Vec<AssignedCell<Fr, Fr>>>,
    &[AssignedCell<Fr, Fr>],
) {
    // each pi hash has INPUT_LEN_PER_ROUND bytes as input
    // keccak will pad the input with another INPUT_LEN_PER_ROUND bytes
    // we extract all those bytes
    let batch_pi_hash_preimage = &hash_input_cells[0];
    let mut chunk_pi_hash_preimages = vec![];
    for i in 0..N_SNARKS {
        chunk_pi_hash_preimages.push(&hash_input_cells[i + 1]);
    }
    let batch_data_hash_preimage = hash_input_cells.last().unwrap();

    (
        batch_pi_hash_preimage,
        chunk_pi_hash_preimages,
        batch_data_hash_preimage,
    )
}

#[inline]
#[allow(clippy::type_complexity)]
pub(crate) fn parse_hash_digest_cells<const N_SNARKS: usize>(
    hash_output_cells: &[Vec<AssignedCell<Fr, Fr>>],
) -> (
    &[AssignedCell<Fr, Fr>],
    Vec<&Vec<AssignedCell<Fr, Fr>>>,
    &[AssignedCell<Fr, Fr>],
) {
    let batch_pi_hash_digest = &hash_output_cells[0];
    let mut chunk_pi_hash_digests = vec![];
    for i in 0..N_SNARKS {
        chunk_pi_hash_digests.push(&hash_output_cells[i + 1]);
    }
    let batch_data_hash_digest = &hash_output_cells[N_SNARKS + 1];
    (
        batch_pi_hash_digest,
        chunk_pi_hash_digests,
        batch_data_hash_digest,
    )
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
