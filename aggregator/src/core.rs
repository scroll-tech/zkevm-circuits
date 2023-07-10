use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::{
        halo2::halo2_ecc::{
            halo2_base,
            halo2_base::{
                gates::{flex_gate::FlexGateConfig, GateInstructions},
                AssignedValue, Context, ContextParams, QuantumCell,
            },
        },
        native::NativeLoader,
    },
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
        CHAIN_ID_LEN, DIGEST_LEN, LOG_DEGREE, MAX_AGG_SNARKS, MAX_KECCAK_ROUNDS, ROUND_LEN,
    },
    util::{
        assert_conditional_equal, assert_equal, assert_exist, assgined_cell_to_value, capacity,
        get_indices, is_smaller_than, parse_hash_digest_cells, parse_hash_preimage_cells,
    },
    AggregationConfig, CHUNK_DATA_HASH_INDEX, POST_STATE_ROOT_INDEX, PREV_STATE_ROOT_INDEX,
    WITHDRAW_ROOT_INDEX,
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
/// return cells of the hash inputs and digests.
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
// 7. chunk[i]'s data_hash == [0u8; 32] when chunk[i] is padded
pub(crate) fn assign_batch_hashes(
    config: &AggregationConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    preimages: &[Vec<u8>],
    num_of_valid_chunks: usize,
) -> Result<(Vec<AssignedCell<Fr, Fr>>, Vec<AssignedCell<Fr, Fr>>), Error> {
    let (hash_input_cells, hash_output_cells) = extract_hash_cells(
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
    // 7. chunk[i]'s data_hash == [0u8; 32] when chunk[i] is padded
    conditional_constraints(
        config.flex_gate(),
        layouter,
        &hash_input_cells,
        &hash_output_cells,
        num_of_valid_chunks,
    )?;

    Ok((hash_input_cells, hash_output_cells))
}

pub(crate) fn extract_hash_cells(
    keccak_config: &KeccakCircuitConfig<Fr>,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    preimages: &[Vec<u8>],
) -> Result<
    (
        Vec<AssignedCell<Fr, Fr>>, // input cells
        Vec<AssignedCell<Fr, Fr>>, // digest cells
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
    let witness = multi_keccak(preimages, challenges, capacity(num_rows)).unwrap();
    end_timer!(timer);

    // extract the indices of the rows for which the preimage and the digest cells lie in
    let (preimage_indices, digest_indices) = get_indices(preimages);

    let mut preimage_indices_iter = preimage_indices.iter();
    let mut digest_indices_iter = digest_indices.iter();

    let mut hash_input_cells = vec![];
    let mut hash_output_cells = vec![];

    let mut cur_preimage_index = preimage_indices_iter.next();
    let mut cur_digest_index = digest_indices_iter.next();

    layouter
        .assign_region(
            || "assign keccak rows",
            |mut region| {
                if is_first_time {
                    is_first_time = false;
                    let offset = witness.len() - 1;
                    keccak_config.set_row(&mut region, offset, &witness[offset])?;
                    return Ok(());
                }
                // ====================================================
                // Step 1. Extract the hash cells
                // ====================================================
                let timer = start_timer!(|| "assign row");
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let row = keccak_config.set_row(&mut region, offset, keccak_row)?;

                    if cur_preimage_index.is_some() && *cur_preimage_index.unwrap() == offset {
                        // 10-th column is Keccak input in Keccak circuit
                        hash_input_cells.push(row[10].clone());
                        // current_hash_input_cells.push(row[10].clone());
                        cur_preimage_index = preimage_indices_iter.next();
                    }
                    if cur_digest_index.is_some() && *cur_digest_index.unwrap() == offset {
                        // last column is Keccak output in Keccak circuit
                        hash_output_cells.push(row.last().unwrap().clone());
                        // current_hash_output_cells.push(row.last().unwrap().clone());
                        cur_digest_index = digest_indices_iter.next();
                    }
                }
                end_timer!(timer);

                // sanity
                assert_eq!(hash_input_cells.len(), MAX_KECCAK_ROUNDS * ROUND_LEN);
                assert_eq!(hash_output_cells.len(), (MAX_AGG_SNARKS + 4) * DIGEST_LEN);

                keccak_config
                    .keccak_table
                    .annotate_columns_in_region(&mut region);
                keccak_config.annotate_circuit(&mut region);
                Ok(())
            },
        )
        .unwrap();
    Ok((hash_input_cells, hash_output_cells))
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
            || "assign keccak rows",
            |mut region| {
                if is_first_time {
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
                ) = parse_hash_preimage_cells(&hash_input_cells);

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
                for i in 0..32 {
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
                    for j in 0..32 {
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
                for i in 0..MAX_AGG_SNARKS {
                    for j in 0..CHAIN_ID_LEN {
                        // sanity check
                        assert_equal(&batch_pi_hash_preimage[j], &chunk_pi_hash_preimages[i][j]);
                        region.constrain_equal(
                            batch_pi_hash_preimage[j].cell(),
                            chunk_pi_hash_preimages[i][j].cell(),
                        )?;
                    }
                }
                Ok(())
            },
        )
        .unwrap();
    Ok(())
}

// Assert the following constraints
// This function asserts the following constraints on the hashes
// 1. batch_data_hash digest is reused for public input hash
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 6. chunk[i]'s prev_state_root == post_state_root when chunk[i] is padded
// 7. chunk[i]'s data_hash == [0u8; 32] when chunk[i] is padded
#[allow(clippy::type_complexity)]
pub(crate) fn conditional_constraints(
    flex_gate: &FlexGateConfig<Fr>,
    layouter: &mut impl Layouter<Fr>,
    hash_input_cells: &[AssignedCell<Fr, Fr>],
    hash_output_cells: &[AssignedCell<Fr, Fr>],
    num_of_valid_chunks: usize,
) -> Result<(), Error> {
    let mut first_pass = halo2_base::SKIP_FIRST_PASS;
    layouter
        .assign_region(
            || "aggregation",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: flex_gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: flex_gate.constants.clone(),
                    },
                );

                let zero_cell = flex_gate.load_zero(&mut ctx);
                let chunk_is_valid = chunk_is_valid(&flex_gate, &mut ctx, num_of_valid_chunks);
                let chunk_is_pad = chunk_is_valid
                    .iter()
                    .map(|&cell| flex_gate.not(&mut ctx, QuantumCell::Existing(cell)))
                    .collect::<Vec<_>>();

                // ====================================================
                // parse the hashes
                // ====================================================
                // preimages
                let (
                    batch_pi_hash_preimage,
                    chunk_pi_hash_preimages,
                    potential_batch_data_hash_preimage,
                ) = parse_hash_preimage_cells(&hash_input_cells);

                // digests
                let (
                    _batch_pi_hash_digest,
                    _chunk_pi_hash_digests,
                    potential_batch_data_hash_digest,
                ) = parse_hash_digest_cells(&hash_output_cells);

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
                for i in 0..4 {
                    for j in 0..8 {
                        // sanity check
                        assert_exist(
                            &batch_pi_hash_preimage[i * 8 + j + CHUNK_DATA_HASH_INDEX],
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j],
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 32],
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + 64],
                        );
                        // convert halo2 proof's cells to halo2-lib's
                        let t1 = assgined_cell_to_value(
                            flex_gate,
                            &mut ctx,
                            &batch_pi_hash_preimage[i * 8 + j + CHUNK_DATA_HASH_INDEX],
                        );
                        let t2 = assgined_cell_to_value(
                            flex_gate,
                            &mut ctx,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j],
                        );
                        let t3 = assgined_cell_to_value(
                            flex_gate,
                            &mut ctx,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + DIGEST_LEN],
                        );
                        let t4 = assgined_cell_to_value(
                            flex_gate,
                            &mut ctx,
                            &potential_batch_data_hash_digest[(3 - i) * 8 + j + DIGEST_LEN * 2],
                        );

                        // assert (t1-t2)*(t1-t3)*(t1-t4)==0
                        let t2 = flex_gate.sub(
                            &mut ctx,
                            QuantumCell::Existing(t1),
                            QuantumCell::Existing(t2),
                        );
                        let t3 = flex_gate.sub(
                            &mut ctx,
                            QuantumCell::Existing(t1),
                            QuantumCell::Existing(t3),
                        );
                        let t4 = flex_gate.sub(
                            &mut ctx,
                            QuantumCell::Existing(t1),
                            QuantumCell::Existing(t4),
                        );

                        let t1 = flex_gate.mul(
                            &mut ctx,
                            QuantumCell::Existing(t2),
                            QuantumCell::Existing(t3),
                        );
                        let t1 = flex_gate.mul(
                            &mut ctx,
                            QuantumCell::Existing(t1),
                            QuantumCell::Existing(t4),
                        );
                        flex_gate.assert_equal(
                            &mut ctx,
                            QuantumCell::Existing(t1),
                            QuantumCell::Existing(zero_cell),
                        );
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
                for (i, chunk) in potential_batch_data_hash_preimage
                    .iter()
                    .take(DIGEST_LEN * MAX_AGG_SNARKS)
                    .chunks(DIGEST_LEN)
                    .into_iter()
                    .enumerate()
                {
                    for (j, cell) in chunk.into_iter().enumerate() {
                        // convert halo2 proof's cells to halo2-lib's
                        let t1 = assgined_cell_to_value(flex_gate, &mut ctx, &cell);
                        let t2 = assgined_cell_to_value(
                            flex_gate,
                            &mut ctx,
                            &chunk_pi_hash_preimages[i][j + CHUNK_DATA_HASH_INDEX],
                        );
                        assert_conditional_equal(&t1, &t2, &chunk_is_valid[i]);

                        // assert (t1 - t2) * chunk_is_valid[i] == 0
                        let t1_sub_t2 = flex_gate.sub(
                            &mut ctx,
                            QuantumCell::Existing(t1),
                            QuantumCell::Existing(t2),
                        );
                        let res = flex_gate.mul(
                            &mut ctx,
                            QuantumCell::Existing(t1_sub_t2),
                            QuantumCell::Existing(chunk_is_valid[i]),
                        );
                        flex_gate.assert_equal(
                            &mut ctx,
                            QuantumCell::Existing(res),
                            QuantumCell::Existing(zero_cell),
                        );
                    }
                }
                // 6. chunk[i]'s prev_state_root == post_state_root when chunk[i] is padded
                for (i, chunk_hash_input) in chunk_pi_hash_preimages.iter().enumerate() {
                    for j in 0..DIGEST_LEN {
                        let t1 = assgined_cell_to_value(
                            flex_gate,
                            &mut ctx,
                            &chunk_hash_input[j + PREV_STATE_ROOT_INDEX],
                        );
                        let t2 = assgined_cell_to_value(
                            flex_gate,
                            &mut ctx,
                            &chunk_hash_input[j + POST_STATE_ROOT_INDEX],
                        );
                        assert_conditional_equal(&t1, &t2, &chunk_is_pad[i]);
                        // assert (t1 - t2) * chunk_is_padding == 0
                        let t1_sub_t2 = flex_gate.sub(
                            &mut ctx,
                            QuantumCell::Existing(t1),
                            QuantumCell::Existing(t2),
                        );
                        let res = flex_gate.mul(
                            &mut ctx,
                            QuantumCell::Existing(t1_sub_t2),
                            QuantumCell::Existing(chunk_is_pad[i]),
                        );
                        flex_gate.assert_equal(
                            &mut ctx,
                            QuantumCell::Existing(res),
                            QuantumCell::Existing(zero_cell),
                        );
                    }
                }

                // 7. chunk[i]'s data_hash == [0u8; 32] when chunk[i] is padded
                for (i, chunk_hash_input) in chunk_pi_hash_preimages.iter().enumerate() {
                    for j in 0..DIGEST_LEN {
                        let t1 = assgined_cell_to_value(
                            flex_gate,
                            &mut ctx,
                            &chunk_hash_input[j + CHUNK_DATA_HASH_INDEX],
                        );
                        assert_conditional_equal(&t1, &zero_cell, &chunk_is_pad[i]);
                        // constrain t1 == 0 if chunk_is_padding == 1
                        let res = flex_gate.and(
                            &mut ctx,
                            QuantumCell::Existing(t1),
                            QuantumCell::Existing(chunk_is_pad[i]),
                        );
                        flex_gate.assert_equal(
                            &mut ctx,
                            QuantumCell::Existing(res),
                            QuantumCell::Existing(zero_cell),
                        );
                    }
                }

                Ok(())
            },
        )
        .unwrap();
    Ok(())
}

/// generate a string of binary cells indicating
/// if the i-th chunk is a valid chunk
pub(crate) fn chunk_is_valid(
    gate: &FlexGateConfig<Fr>,
    ctx: &mut Context<Fr>,
    num_of_valid_chunks: usize,
) -> [AssignedValue<Fr>; MAX_AGG_SNARKS] {
    let mut res = vec![];

    let threshold = gate.load_witness(ctx, Value::known(Fr::from(num_of_valid_chunks as u64)));

    for i in 0..MAX_AGG_SNARKS {
        let value = gate.load_witness(ctx, Value::known(Fr::from(i as u64)));
        let is_valid = is_smaller_than(&gate, ctx, &value, &threshold);
        res.push(is_valid);
    }

    // safe unwrap
    res.try_into().unwrap()
}
