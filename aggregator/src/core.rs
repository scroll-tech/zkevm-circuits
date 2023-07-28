use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use rand::Rng;
use snark_verifier::{
    loader::{halo2::halo2_ecc::halo2_base, native::NativeLoader},
    pcs::{
        kzg::{Bdfg21, Kzg, KzgAccumulator, KzgAs},
        AccumulationSchemeProver,
    },
    verifier::PlonkVerifier,
    Error,
};
use snark_verifier_sdk::{
    types::{PoseidonTranscript, Shplonk, POSEIDON_SPEC},
    Snark,
};
use zkevm_circuits::{
    keccak_circuit::{keccak_packed_multi::multi_keccak, KeccakCircuitConfig},
    table::LookupTable,
    util::Challenges,
};

use crate::{
    constants::{
        CHAIN_ID_LEN, DIGEST_LEN, INPUT_LEN_PER_ROUND, LOG_DEGREE, MAX_AGG_SNARKS,
        MAX_KECCAK_ROUNDS, ROWS_PER_ROUND,
    },
    util::{
        assert_conditional_equal, assert_equal, assert_exist, get_indices, keccak_round_capacity,
        parse_hash_digest_cells, parse_hash_preimage_cells,
    },
    AggregationConfig, RlcConfig, CHUNK_DATA_HASH_INDEX, POST_STATE_ROOT_INDEX,
    PREV_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX,
};

/// Subroutine for the witness generations.
/// Extract the accumulator and proof that from previous snarks.
/// Uses SHPlonk for accumulation.
pub(crate) fn extract_accumulators_and_proof(
    params: &ParamsKZG<Bn256>,
    snarks: &[Snark],
    rng: impl Rng + Send,
) -> Result<(KzgAccumulator<G1Affine, NativeLoader>, Vec<u8>), Error> {
    let svk = params.get_g()[0].into();

    let mut transcript_read =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&[], POSEIDON_SPEC.clone());
    let accumulators = snarks
        .iter()
        .flat_map(|snark| {
            transcript_read.new_stream(snark.proof.as_slice());
            let proof = Shplonk::read_proof(
                &svk,
                &snark.protocol,
                &snark.instances,
                &mut transcript_read,
            );
            // each accumulator has (lhs, rhs) based on Shplonk
            // lhs and rhs are EC points
            Shplonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof)
        })
        .collect::<Vec<_>>();

    let mut transcript_write =
        PoseidonTranscript::<NativeLoader, Vec<u8>>::from_spec(vec![], POSEIDON_SPEC.clone());
    // We always use SHPLONK for accumulation scheme when aggregating proofs
    let accumulator =
        // core step
        // KzgAs does KZG accumulation scheme based on given accumulators and random number (for adding blinding)
        // accumulated ec_pt = ec_pt_1 * 1 + ec_pt_2 * r + ... + ec_pt_n * r^{n-1}
        // ec_pt can be lhs and rhs
        // r is the challenge squeezed from proof
        KzgAs::<Kzg<Bn256, Bdfg21>>::create_proof::<PoseidonTranscript<NativeLoader, Vec<u8>>, _>(
            &Default::default(),
            &accumulators,
            &mut transcript_write,
            rng,
        )?;
    Ok((accumulator, transcript_write.finalize()))
}

/// Input the hash input bytes,
/// assign the circuit for the hash function,
/// return
/// - cells of the hash digests
/// - the cell that contains the number of valid snarks
//
// This function asserts the following constraints on the hashes
//
// 1. batch_data_hash digest is reused for public input hash
// 2. batch_pi_hash used same roots as chunk_pi_hash
// 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
// 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
// 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 4. chunks are continuous: they are linked via the state roots
// 5. batch and all its chunks use a same chain id
// 6. chunk[i]'s prev_state_root == post_state_root when chunk[i] is padded
// 7. chunk[i]'s data_hash == "" when chunk[i] is padded
#[allow(clippy::type_complexity)]
pub(crate) fn assign_batch_hashes(
    config: &AggregationConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    preimages: &[Vec<u8>],
    num_of_valid_chunks: usize,
) -> Result<(Vec<AssignedCell<Fr, Fr>>, AssignedCell<Fr, Fr>), Error> {
    let (hash_input_cells, hash_output_cells, data_rlc_cells, hash_input_len_cells) =
        extract_hash_cells(
            &config.keccak_circuit_config,
            layouter,
            challenges,
            preimages,
        )?;
    // 2. batch_pi_hash used same roots as chunk_pi_hash
    // 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
    // 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
    // 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
    // 4. chunks are continuous: they are linked via the state roots
    // 5. batch and all its chunks use a same chain id
    copy_constraints(layouter, &hash_input_cells)?;
    // 1. batch_data_hash digest is reused for public input hash
    // 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not
    // padded
    // 6. chunk[i]'s prev_state_root == post_state_root when chunk[i] is padded
    // 7. chunk[i]'s data_hash == "" when chunk[i] is padded
    let num_valid_snarks = conditional_constraints(
        &config.rlc_config,
        // config.flex_gate(),
        layouter,
        challenges,
        &hash_input_cells,
        &hash_output_cells,
        &data_rlc_cells,
        &hash_input_len_cells,
        num_of_valid_chunks,
    )?;

    Ok((hash_output_cells, num_valid_snarks))
}

#[allow(clippy::type_complexity)]
pub(crate) fn extract_hash_cells(
    keccak_config: &KeccakCircuitConfig<Fr>,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    preimages: &[Vec<u8>],
) -> Result<
    (
        Vec<AssignedCell<Fr, Fr>>, // input cells
        Vec<AssignedCell<Fr, Fr>>, // digest cells
        Vec<AssignedCell<Fr, Fr>>, // RLC cells
        Vec<AssignedCell<Fr, Fr>>, // hash input length cells
    ),
    Error,
> {
    let mut is_first_time = true;
    let num_rows = 1 << LOG_DEGREE;

    let timer = start_timer!(|| ("multi keccak").to_string());
    // preimages consists of the following parts
    // (1) batchPiHash preimage =
    //      (chain_id ||
    //      chunk[0].prev_state_root ||
    //      chunk[k-1].post_state_root ||
    //      chunk[k-1].withdraw_root ||
    //      batch_data_hash)
    // (2) chunk[i].piHash preimage =
    //      (chain id ||
    //      chunk[i].prevStateRoot || chunk[i].postStateRoot ||
    //      chunk[i].withdrawRoot || chunk[i].datahash)
    // (3) batchDataHash preimage =
    //      (chunk[0].dataHash || ... || chunk[k-1].dataHash)
    // each part of the preimage is mapped to image by Keccak256
    let witness = multi_keccak(preimages, challenges, keccak_round_capacity(num_rows))
        .map_err(|e| Error::AssertionFailure(format!("multi keccak assignment failed: {e:?}")))?;
    end_timer!(timer);

    // extract the indices of the rows for which the preimage and the digest cells lie in
    let (preimage_indices, digest_indices) = get_indices(preimages);

    let (hash_input_cells, hash_output_cells, data_rlc_cells, hash_input_len_cells) = layouter
        .assign_region(
            || "assign keccak rows",
            |mut region| -> Result<
                (
                    Vec<AssignedCell<Fr, Fr>>,
                    Vec<AssignedCell<Fr, Fr>>,
                    Vec<AssignedCell<Fr, Fr>>,
                    Vec<AssignedCell<Fr, Fr>>,
                ),
                halo2_proofs::plonk::Error,
            > {
                if is_first_time {
                    is_first_time = false;
                    let offset = witness.len() - 1;
                    keccak_config.set_row(&mut region, offset, &witness[offset])?;
                    return Ok((vec![], vec![], vec![], vec![]));
                }

                let mut preimage_indices_iter = preimage_indices.iter();
                let mut digest_indices_iter = digest_indices.iter();

                let mut cur_preimage_index = preimage_indices_iter.next();
                let mut cur_digest_index = digest_indices_iter.next();

                // ====================================================
                // Step 1. Extract the hash cells
                // ====================================================
                let mut hash_input_cells = vec![];
                let mut hash_output_cells = vec![];
                let mut data_rlc_cells = vec![];
                let mut hash_input_len_cells = vec![];

                let timer = start_timer!(|| "assign row");
                log::trace!("witness length: {}", witness.len());
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row = keccak_config.set_row(&mut region, offset, keccak_row)?;

                    if cur_preimage_index.is_some() && *cur_preimage_index.unwrap() == offset {
                        // 10-th column is Keccak input in Keccak circuit
                        hash_input_cells.push(row[10].clone());
                        cur_preimage_index = preimage_indices_iter.next();
                    }
                    if cur_digest_index.is_some() && *cur_digest_index.unwrap() == offset {
                        // last column is Keccak output in Keccak circuit
                        hash_output_cells.push(row.last().unwrap().clone()); // sage unwrap
                        cur_digest_index = digest_indices_iter.next();
                    }
                    if offset % ROWS_PER_ROUND == 0 && offset / ROWS_PER_ROUND <= MAX_KECCAK_ROUNDS
                    {
                        // second column is data rlc
                        data_rlc_cells.push(row[1].clone());
                        // third column is hash len
                        hash_input_len_cells.push(row[2].clone());
                    }
                }
                end_timer!(timer);

                // sanity
                assert_eq!(
                    hash_input_cells.len(),
                    MAX_KECCAK_ROUNDS * INPUT_LEN_PER_ROUND
                );
                assert_eq!(hash_output_cells.len(), (MAX_AGG_SNARKS + 4) * DIGEST_LEN);

                keccak_config
                    .keccak_table
                    .annotate_columns_in_region(&mut region);
                keccak_config.annotate_circuit(&mut region);
                Ok((
                    hash_input_cells,
                    hash_output_cells,
                    data_rlc_cells,
                    hash_input_len_cells,
                ))
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("assign keccak rows: {e}")))?;

    for (i, e) in hash_input_len_cells.iter().enumerate() {
        log::trace!("{}'s round hash input len {:?}", i, e.value())
    }

    Ok((
        hash_input_cells,
        hash_output_cells,
        data_rlc_cells,
        hash_input_len_cells,
    ))
}

// Assert the following constraints
// 2. batch_pi_hash used same roots as chunk_pi_hash
// 2.1. batch_pi_hash and chunk[0] use a same prev_state_root
// 2.2. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same post_state_root
// 2.3. batch_pi_hash and chunk[MAX_AGG_SNARKS-1] use a same withdraw_root
// 4. chunks are continuous: they are linked via the state roots
// 5. batch and all its chunks use a same chain id
fn copy_constraints(
    layouter: &mut impl Layouter<Fr>,
    hash_input_cells: &[AssignedCell<Fr, Fr>],
) -> Result<(), Error> {
    let mut is_first_time = true;

    layouter
        .assign_region(
            || "copy constraints",
            |mut region| -> Result<(), halo2_proofs::plonk::Error> {
                if is_first_time {
                    // this region only use copy constraints and do not affect the shape of the
                    // layouter
                    is_first_time = false;
                    return Ok(());
                }
                // ====================================================
                // parse the hashes
                // ====================================================
                // preimages
                let (
                    batch_pi_hash_preimage,
                    chunk_pi_hash_preimages,
                    _potential_batch_data_hash_preimage,
                ) = parse_hash_preimage_cells(hash_input_cells);

                // ====================================================
                // Constraint the relations between hash preimages
                // via copy constraints
                // ====================================================
                //
                // 2 batch_pi_hash used same roots as chunk_pi_hash
                //
                // batch_pi_hash =
                //   keccak(
                //      chain_id ||
                //      chunk[0].prev_state_root ||
                //      chunk[k-1].post_state_root ||
                //      chunk[k-1].withdraw_root ||
                //      batchData_hash )
                //
                // chunk[i].piHash =
                //   keccak(
                //        chain id ||
                //        chunk[i].prevStateRoot ||
                //        chunk[i].postStateRoot ||
                //        chunk[i].withdrawRoot  ||
                //        chunk[i].datahash)
                //
                // PREV_STATE_ROOT_INDEX, POST_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX
                // used below are byte positions for
                // prev_state_root, post_state_root, withdraw_root
                for i in 0..DIGEST_LEN {
                    // 2.1 chunk[0].prev_state_root
                    // sanity check
                    assert_equal(
                        &batch_pi_hash_preimage[i + PREV_STATE_ROOT_INDEX],
                        &chunk_pi_hash_preimages[0][i + PREV_STATE_ROOT_INDEX],
                    );
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + PREV_STATE_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[0][i + PREV_STATE_ROOT_INDEX].cell(),
                    )?;
                    // 2.2 chunk[k-1].post_state_root
                    // sanity check
                    assert_equal(
                        &batch_pi_hash_preimage[i + POST_STATE_ROOT_INDEX],
                        &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + POST_STATE_ROOT_INDEX],
                    );
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + POST_STATE_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + POST_STATE_ROOT_INDEX]
                            .cell(),
                    )?;
                    // 2.3 chunk[k-1].withdraw_root
                    assert_equal(
                        &batch_pi_hash_preimage[i + WITHDRAW_ROOT_INDEX],
                        &chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + WITHDRAW_ROOT_INDEX],
                    );
                    region.constrain_equal(
                        batch_pi_hash_preimage[i + WITHDRAW_ROOT_INDEX].cell(),
                        chunk_pi_hash_preimages[MAX_AGG_SNARKS - 1][i + WITHDRAW_ROOT_INDEX].cell(),
                    )?;
                }

                // 4  chunks are continuous: they are linked via the state roots
                for i in 0..MAX_AGG_SNARKS - 1 {
                    for j in 0..DIGEST_LEN {
                        // sanity check
                        assert_equal(
                            &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j],
                            &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j],
                        );
                        region.constrain_equal(
                            chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j].cell(),
                            chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j].cell(),
                        )?;
                    }
                }

                // 5 assert hashes use a same chain id
                for chunk_pi_hash_preimage in chunk_pi_hash_preimages.iter() {
                    for (lhs, rhs) in batch_pi_hash_preimage
                        .iter()
                        .take(CHAIN_ID_LEN)
                        .zip(chunk_pi_hash_preimage.iter().take(CHAIN_ID_LEN))
                    {
                        // sanity check
                        assert_equal(lhs, rhs);
                        region.constrain_equal(lhs.cell(), rhs.cell())?;
                    }
                }
                Ok(())
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("assign keccak rows: {e}")))?;
    Ok(())
}

// Assert the following constraints
// This function asserts the following constraints on the hashes
// 1. batch_data_hash digest is reused for public input hash
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 6. chunk[i]'s prev_state_root == post_state_root when chunk[i] is padded
// 7. chunk[i]'s data_hash == "" when chunk[i] is padded
#[allow(clippy::too_many_arguments)]
pub(crate) fn conditional_constraints(
    rlc_config: &RlcConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    hash_input_cells: &[AssignedCell<Fr, Fr>],
    hash_output_cells: &[AssignedCell<Fr, Fr>],
    data_rlc_cells: &[AssignedCell<Fr, Fr>],
    hash_input_len_cells: &[AssignedCell<Fr, Fr>],
    num_of_valid_chunks: usize,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let mut first_pass = halo2_base::SKIP_FIRST_PASS;

    let num_of_valid_snarks_cell = layouter
        .assign_region(
            || "rlc conditional constraints",
            |mut region| -> Result<Vec<AssignedCell<Fr, Fr>>, halo2_proofs::plonk::Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }

                rlc_config.init(&mut region)?;
                let mut offset = 0;

                // ====================================================
                // build the flags to indicate the chunks are empty or not
                // ====================================================
                let num_of_valid_snarks_cell = vec![rlc_config.load_private(
                    &mut region,
                    &Fr::from(num_of_valid_chunks as u64),
                    &mut offset,
                )?];
                let chunk_is_valid_cells = chunk_is_valid(
                    rlc_config,
                    &mut region,
                    &num_of_valid_snarks_cell[0],
                    &mut offset,
                )?;

                let chunk_is_pad = chunk_is_valid_cells
                    .iter()
                    .map(|cell| rlc_config.not(&mut region, cell, &mut offset))
                    .collect::<Result<Vec<_>, _>>()?;

                // #valid snarks | offset of data hash | flags
                // 1,2,3,4       | 0                   | 1, 0, 0
                // 5,6,7,8       | 32                  | 0, 1, 0
                // 9,10          | 64                  | 0, 0, 1

                let four = {
                    let four = rlc_config.load_private(&mut region, &Fr::from(4), &mut offset)?;
                    let four_cell = rlc_config.four_cell(four.cell().region_index);
                    region.constrain_equal(four_cell, four.cell())?;
                    four
                };
                let eight = {
                    let eight = rlc_config.load_private(&mut region, &Fr::from(8), &mut offset)?;
                    let eight_cell = rlc_config.eight_cell(eight.cell().region_index);
                    region.constrain_equal(eight_cell, eight.cell())?;
                    eight
                };
                let flag1 = rlc_config.is_smaller_than(
                    &mut region,
                    &num_of_valid_snarks_cell[0],
                    &four,
                    &mut offset,
                )?;
                let not_flag1 = rlc_config.not(&mut region, &flag1, &mut offset)?;
                let not_flag3 = rlc_config.is_smaller_than(
                    &mut region,
                    &num_of_valid_snarks_cell[0],
                    &eight,
                    &mut offset,
                )?;
                let flag3 = rlc_config.not(&mut region, &not_flag3, &mut offset)?;
                let flag2 = rlc_config.mul(&mut region, &not_flag1, &not_flag3, &mut offset)?;
                log::trace!(
                    "flags: {:?} {:?} {:?}",
                    flag1.value(),
                    flag2.value(),
                    flag3.value()
                );
                // ====================================================
                // parse the hashes
                // ====================================================
                // preimages
                let (
                    batch_pi_hash_preimage,
                    chunk_pi_hash_preimages,
                    potential_batch_data_hash_preimage,
                ) = parse_hash_preimage_cells(hash_input_cells);

                // digests
                let (
                    _batch_pi_hash_digest,
                    _chunk_pi_hash_digests,
                    potential_batch_data_hash_digest,
                ) = parse_hash_digest_cells(hash_output_cells);
                // ====================================================
                // start the actual statements
                // ====================================================
                //
                // 1 batch_data_hash digest is reused for public input hash
                //
                // public input hash is build as
                //  keccak(
                //      chain_id ||
                //      chunk[0].prev_state_root ||
                //      chunk[k-1].post_state_root ||
                //      chunk[k-1].withdraw_root ||
                //      batch_data_hash )
                //
                // #valid snarks | offset of data hash | flags
                // 1,2,3,4       | 0                   | 1, 0, 0
                // 5,6,7,8       | 32                  | 0, 1, 0
                // 9,10          | 64                  | 0, 0, 1
                for i in 0..4 {
                    for j in 0..8 {
                        // sanity check
                        assert_exist(
                            &batch_pi_hash_preimage[i * 8 + j + CHUNK_DATA_HASH_INDEX],
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j],
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 32],
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 64],
                        );
                        // assert
                        // batch_pi_hash_preimage[i * 8 + j + CHUNK_DATA_HASH_INDEX]
                        // = flag1 * potential_batch_data_hash_digest[(3 - i) * 8 + j]
                        // + flag2 * potential_batch_data_hash_digest[(3 - i) * 8 + j + 32]
                        // + flag3 * potential_batch_data_hash_digest[(3 - i) * 8 + j + 64]

                        let rhs = rlc_config.mul(
                            &mut region,
                            &flag1,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j],
                            &mut offset,
                        )?;
                        let rhs = rlc_config.mul_add(
                            &mut region,
                            &flag2,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 32],
                            &rhs,
                            &mut offset,
                        )?;
                        let rhs = rlc_config.mul_add(
                            &mut region,
                            &flag3,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 64],
                            &rhs,
                            &mut offset,
                        )?;

                        region.constrain_equal(
                            batch_pi_hash_preimage[i * 8 + j + CHUNK_DATA_HASH_INDEX].cell(),
                            rhs.cell(),
                        )?;
                    }
                }

                // 3 batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when
                // chunk[i] is not padded
                //
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
                //
                // chunk[i].piHash =
                //     keccak(
                //        &chain id ||
                //        chunk[i].prevStateRoot ||
                //        chunk[i].postStateRoot ||
                //        chunk[i].withdrawRoot  ||
                //        chunk[i].datahash)
                let challenge_cell =
                    rlc_config.read_challenge(&mut region, challenges, &mut offset)?;

                let flags = chunk_is_valid_cells
                    .iter()
                    .flat_map(|cell| vec![cell; 32])
                    .cloned()
                    .collect::<Vec<_>>();

                let rlc_cell = rlc_config.rlc_with_flag(
                    &mut region,
                    potential_batch_data_hash_preimage[..DIGEST_LEN * MAX_AGG_SNARKS].as_ref(),
                    &challenge_cell,
                    &flags,
                    &mut offset,
                )?;

                assert_exist(
                    &rlc_cell,
                    &data_rlc_cells[MAX_AGG_SNARKS * 2 + 3],
                    &data_rlc_cells[MAX_AGG_SNARKS * 2 + 4],
                    &data_rlc_cells[MAX_AGG_SNARKS * 2 + 5],
                );
                log::trace!("rlc from chip {:?}", rlc_cell.value());
                log::trace!(
                    "rlc from table {:?}",
                    data_rlc_cells[MAX_AGG_SNARKS * 2 + 3].value()
                );
                log::trace!(
                    "rlc from table {:?}",
                    data_rlc_cells[MAX_AGG_SNARKS * 2 + 4].value()
                );
                log::trace!(
                    "rlc from table {:?}",
                    data_rlc_cells[MAX_AGG_SNARKS * 2 + 5].value()
                );

                // assertion
                let t1 = rlc_config.sub(
                    &mut region,
                    &rlc_cell,
                    &data_rlc_cells[MAX_AGG_SNARKS * 2 + 3],
                    &mut offset,
                )?;
                let t2 = rlc_config.sub(
                    &mut region,
                    &rlc_cell,
                    &data_rlc_cells[MAX_AGG_SNARKS * 2 + 4],
                    &mut offset,
                )?;
                let t3 = rlc_config.sub(
                    &mut region,
                    &rlc_cell,
                    &data_rlc_cells[MAX_AGG_SNARKS * 2 + 5],
                    &mut offset,
                )?;
                let t1t2 = rlc_config.mul(&mut region, &t1, &t2, &mut offset)?;
                let t1t2t3 = rlc_config.mul(&mut region, &t1t2, &t3, &mut offset)?;
                rlc_config.enforce_zero(&mut region, &t1t2t3)?;

                // 6. chunk[i]'s prev_state_root == post_state_root when chunk[i] is padded
                for (i, chunk_hash_input) in chunk_pi_hash_preimages.iter().enumerate() {
                    for j in 0..DIGEST_LEN {
                        let t1 = &chunk_hash_input[j + PREV_STATE_ROOT_INDEX];
                        let t2 = &chunk_hash_input[j + POST_STATE_ROOT_INDEX];

                        assert_conditional_equal(t1, t2, &chunk_is_pad[i]);
                        // assert (t1 - t2) * chunk_is_padding == 0
                        let t1_sub_t2 = rlc_config.sub(&mut region, t1, t2, &mut offset)?;
                        let res = rlc_config.mul(
                            &mut region,
                            &t1_sub_t2,
                            &chunk_is_pad[i],
                            &mut offset,
                        )?;

                        rlc_config.enforce_zero(&mut region, &res)?;
                    }
                }

                // 7. chunk[i]'s data_hash == "" when chunk[i] is padded
                // that means the data_hash length is 32 * number_of_valid_snarks
                let const32 = rlc_config.load_private(&mut region, &Fr::from(32), &mut offset)?;
                let const32_cell = rlc_config.thirty_two_cell(const32.cell().region_index);
                region.constrain_equal(const32.cell(), const32_cell)?;
                let data_hash_inputs = rlc_config.mul(
                    &mut region,
                    &num_of_valid_snarks_cell[0],
                    &const32,
                    &mut offset,
                )?;

                // sanity check
                assert_exist(
                    &data_hash_inputs,
                    &hash_input_len_cells[MAX_AGG_SNARKS * 2 + 3],
                    &hash_input_len_cells[MAX_AGG_SNARKS * 2 + 4],
                    &hash_input_len_cells[MAX_AGG_SNARKS * 2 + 5],
                );

                log::trace!("data_hash_inputs: {:?}", data_hash_inputs.value());
                log::trace!(
                    "candidate 1: {:?}",
                    hash_input_len_cells[MAX_AGG_SNARKS * 2 + 3].value()
                );
                log::trace!(
                    "candidate 2: {:?}",
                    hash_input_len_cells[MAX_AGG_SNARKS * 2 + 4].value()
                );
                log::trace!(
                    "candidate 3: {:?}",
                    hash_input_len_cells[MAX_AGG_SNARKS * 2 + 5].value()
                );

                let mut data_hash_inputs_rec = rlc_config.mul(
                    &mut region,
                    &hash_input_len_cells[MAX_AGG_SNARKS * 2 + 3],
                    &flag1,
                    &mut offset,
                )?;
                data_hash_inputs_rec = rlc_config.mul_add(
                    &mut region,
                    &hash_input_len_cells[MAX_AGG_SNARKS * 2 + 4],
                    &flag2,
                    &data_hash_inputs_rec,
                    &mut offset,
                )?;
                data_hash_inputs_rec = rlc_config.mul_add(
                    &mut region,
                    &hash_input_len_cells[MAX_AGG_SNARKS * 2 + 5],
                    &flag3,
                    &data_hash_inputs_rec,
                    &mut offset,
                )?;

                // sanity check
                assert_equal(&data_hash_inputs, &data_hash_inputs_rec);
                region.constrain_equal(data_hash_inputs.cell(), data_hash_inputs_rec.cell())?;
                log::trace!("rlc chip uses {} rows", offset);
                Ok(num_of_valid_snarks_cell)
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("aggregation: {e}")))?;
    Ok(num_of_valid_snarks_cell[0].clone())
}

/// generate a string of binary cells indicating
/// if the i-th chunk is a valid chunk
pub(crate) fn chunk_is_valid(
    rlc_config: &RlcConfig,
    region: &mut Region<Fr>,
    num_of_valid_chunks: &AssignedCell<Fr, Fr>,
    offset: &mut usize,
) -> Result<[AssignedCell<Fr, Fr>; MAX_AGG_SNARKS], halo2_proofs::plonk::Error> {
    let mut res = vec![];

    for i in 0..MAX_AGG_SNARKS {
        let value = rlc_config.load_private(region, &Fr::from(i as u64), offset)?;
        let is_valid = rlc_config.is_smaller_than(region, &value, num_of_valid_chunks, offset)?;
        res.push(is_valid);
    }
    // constrain the chunks are ordered with real ones at the beginning. that is,
    // - if res[i] == 1, res[i+1] is not enforced
    // - if res[i] == 0, res[i+1] must be 0
    // In the end we constrain
    //  (1-res[i])*res[i+1] == 0 => res[i+1] == res[i]*res[i+1]
    // res[i] are already enforced to be binary via is_smaller_than()
    for i in 0..MAX_AGG_SNARKS - 1 {
        let right = rlc_config.mul(region, &res[i], &res[i + 1], offset)?;
        region.constrain_equal(res[i + 1].cell(), right.cell())?;
    }

    // safe unwrap
    Ok(res.try_into().unwrap())
}
