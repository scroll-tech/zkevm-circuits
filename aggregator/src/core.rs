use std::iter::repeat;

use ark_std::{end_timer, start_timer};
use ethers_core::utils::keccak256;
use halo2_proofs::plonk::{Column, Instance};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::{
        bn256::{Bn256, Fq, Fr, G1Affine, G2Affine},
        pairing::Engine,
    },
    poly::{commitment::ParamsProver, kzg::commitment::ParamsKZG},
};
use itertools::Itertools;
use rand::Rng;
use snark_verifier::{
    loader::native::NativeLoader,
    pcs::{
        kzg::{Bdfg21, Kzg, KzgAccumulator, KzgAs},
        AccumulationSchemeProver,
    },
    util::arithmetic::fe_to_limbs,
    verifier::PlonkVerifier,
    Error,
};
use snark_verifier_sdk::{
    types::{PoseidonTranscript, Shplonk, POSEIDON_SPEC},
    Snark,
};
use zkevm_circuits::{
    keccak_circuit::{keccak_packed_multi::multi_keccak, KeccakCircuit, KeccakCircuitConfig},
    util::Challenges,
};

use crate::{
    constants::{
        BATCH_BLOB_VERSIONED_HASH_OFFSET, BATCH_Y_OFFSET, BATCH_Z_OFFSET, CHAIN_ID_LEN, DIGEST_LEN,
        LOG_DEGREE,
    },
    util::{assert_conditional_equal, parse_hash_preimage_cells},
    RlcConfig, BATCH_DATA_HASH_OFFSET, BATCH_PARENT_BATCH_HASH, BITS, CHUNK_CHAIN_ID_INDEX,
    CHUNK_DATA_HASH_INDEX, CHUNK_TX_DATA_HASH_INDEX, LIMBS, PI_CHAIN_ID, PI_CURRENT_BATCH_HASH,
    PI_CURRENT_STATE_ROOT, PI_CURRENT_WITHDRAW_ROOT, PI_PARENT_BATCH_HASH, PI_PARENT_STATE_ROOT,
    POST_STATE_ROOT_INDEX, PREV_STATE_ROOT_INDEX, WITHDRAW_ROOT_INDEX,
};

/// Subroutine for the witness generations.
/// Extract the accumulator and proof that from previous snarks.
/// Uses SHPlonk for accumulation.
pub(crate) fn extract_accumulators_and_proof(
    params: &ParamsKZG<Bn256>,
    snarks: &[Snark],
    rng: impl Rng + Send,
    g2: &G2Affine,
    s_g2: &G2Affine,
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
    // sanity check on the accumulator
    {
        for (i, acc) in accumulators.iter().enumerate() {
            let KzgAccumulator { lhs, rhs } = acc;
            let left = Bn256::pairing(lhs, g2);
            let right = Bn256::pairing(rhs, s_g2);
            log::trace!("acc extraction {}-th acc check: left {:?}", i, left);
            log::trace!("acc extraction {}-th acc check: right {:?}", i, right);
            if left != right {
                return Err(snark_verifier::Error::AssertionFailure(format!(
                    "accumulator check failed {left:?} {right:?}, index {i}",
                )));
            }
            //assert_eq!(left, right, "accumulator check failed");
        }
    }

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

/// Subroutine for the witness generations.
/// Extract proof from previous snarks and check pairing for accumulation.
pub fn extract_proof_and_instances_with_pairing_check(
    params: &ParamsKZG<Bn256>,
    snarks: &[Snark],
    rng: impl Rng + Send,
) -> Result<(Vec<u8>, Vec<Fr>), snark_verifier::Error> {
    // (old_accumulator, public inputs) -> (new_accumulator, public inputs)
    let (accumulator, as_proof) =
        extract_accumulators_and_proof(params, snarks, rng, &params.g2(), &params.s_g2())?;

    // the instance for the outer circuit is
    // - new accumulator, consists of 12 elements
    // - inner circuit's instance, flattened (old accumulator is stripped out if exists)
    //
    // it is important that new accumulator is the first 12 elements
    // as specified in CircuitExt::accumulator_indices()
    let KzgAccumulator::<G1Affine, NativeLoader> { lhs, rhs } = accumulator;

    // sanity check on the accumulator
    {
        let left = Bn256::pairing(&lhs, &params.g2());
        let right = Bn256::pairing(&rhs, &params.s_g2());
        log::trace!("circuit acc check: left {:?}", left);
        log::trace!("circuit acc check: right {:?}", right);

        if left != right {
            return Err(snark_verifier::Error::AssertionFailure(format!(
                "accumulator check failed {left:?} {right:?}",
            )));
        }
    }

    let acc_instances = [lhs.x, lhs.y, rhs.x, rhs.y]
        .map(fe_to_limbs::<Fq, Fr, { LIMBS }, { BITS }>)
        .concat();

    Ok((as_proof, acc_instances))
}

/// Extracted hash cells. Including the padded ones so that the circuit is static.
pub(crate) struct ExtractedHashCells<const N_SNARKS: usize> {
    inputs: Vec<Vec<AssignedCell<Fr, Fr>>>,
    input_rlcs: Vec<AssignedCell<Fr, Fr>>,
    outputs: Vec<Vec<AssignedCell<Fr, Fr>>>,
    output_rlcs: Vec<AssignedCell<Fr, Fr>>,
    data_lens: Vec<AssignedCell<Fr, Fr>>,
    num_valid_snarks: AssignedCell<Fr, Fr>,
    chunks_are_padding: Vec<AssignedCell<Fr, Fr>>,
}

// Computed cells to be constrained against public input. These cells are processed into hi/lo format from ExtractedHashCells.
pub(crate) struct HashDerivedPublicInputCells(Vec<AssignedCell<Fr, Fr>>);

impl<const N_SNARKS: usize> ExtractedHashCells<N_SNARKS> {
    /// Assign the cells for hash input/outputs and their RLCs.
    /// Padded the number of hashes to N_SNARKS
    /// DOES NOT CONSTRAIN THE CORRECTNESS.
    /// Call `check_against_lookup_table` function to constrain the hash is correct.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assign_hash_cells(
        plonk_config: &RlcConfig,
        region: &mut Region<Fr>,
        offset: &mut usize,
        keccak_input_challenge: &AssignedCell<Fr, Fr>,
        evm_word_challenge: &AssignedCell<Fr, Fr>,
        num_valid_chunks: usize,
        preimages: &[Vec<u8>],
        chunk_is_valid_cell32s: &[AssignedCell<Fr, Fr>],
        num_valid_snarks: AssignedCell<Fr, Fr>,
        chunks_are_padding: Vec<AssignedCell<Fr, Fr>>,
    ) -> Result<Self, halo2_proofs::plonk::Error> {
        let mut inputs = vec![];
        let mut input_rlcs = vec![];
        let mut outputs = vec![];
        let mut output_rlcs = vec![];
        let mut data_lens = vec![];

        // preimages are padded as follows
        // - the first hash is batch_hash
        // - the next hashes are chunk\[i\].piHash, we padded it to N_SNARKS by repeating the last
        //   chunk
        // - the last hash is batch_data_hash, its input is padded to 32*N_SNARKS
        log::trace!("preimage len: {}", preimages.len());
        for preimage in preimages
            .iter()
            .take(num_valid_chunks + 1)
            .chain(repeat(&preimages[num_valid_chunks]).take(N_SNARKS - num_valid_chunks))
        {
            {
                let mut preimage_cells = vec![];
                for input in preimage.iter() {
                    let v = Fr::from(*input as u64);
                    let cell = plonk_config.load_private(region, &v, offset)?;
                    preimage_cells.push(cell);
                }
                let input_rlc =
                    plonk_config.rlc(region, &preimage_cells, keccak_input_challenge, offset)?;
                inputs.push(preimage_cells);
                input_rlcs.push(input_rlc);
            }
            {
                let mut digest_cells = vec![];
                let digest = keccak256(preimage);
                for output in digest.iter() {
                    let v = Fr::from(*output as u64);
                    let cell = plonk_config.load_private(region, &v, offset)?;
                    digest_cells.push(cell);
                }
                let output_rlc =
                    plonk_config.rlc(region, &digest_cells, evm_word_challenge, offset)?;
                outputs.push(digest_cells);
                output_rlcs.push(output_rlc)
            }

            data_lens.push(plonk_config.load_private(
                region,
                &Fr::from(preimage.len() as u64),
                offset,
            )?);
        }

        {
            let batch_data_hash_preimage = &preimages[N_SNARKS + 1];

            // batch_circuit_debug
            log::trace!("=> batch_data_hash_preimage idx: {:?}", N_SNARKS + 1);
            log::trace!("=> batch_data_hash_preimage: {:?}", batch_data_hash_preimage);

            let batch_data_hash_digest = keccak256(batch_data_hash_preimage);
            let batch_data_hash_padded_preimage = batch_data_hash_preimage
                .iter()
                .cloned()
                .chain(repeat(0).take(N_SNARKS * 32 - batch_data_hash_preimage.len()));

            {
                let mut preimage_cells = vec![];
                for input in batch_data_hash_padded_preimage {
                    let v = Fr::from(input as u64);
                    let cell = plonk_config.load_private(region, &v, offset)?;
                    preimage_cells.push(cell);
                }
                let input_rlc = plonk_config.rlc_with_flag(
                    region,
                    &preimage_cells,
                    keccak_input_challenge,
                    chunk_is_valid_cell32s,
                    offset,
                )?;
                inputs.push(preimage_cells);
                input_rlcs.push(input_rlc);
            }

            {
                let mut digest_cells = vec![];
                for output in batch_data_hash_digest.iter() {
                    let v = Fr::from(*output as u64);
                    let cell = plonk_config.load_private(region, &v, offset)?;
                    digest_cells.push(cell);
                }
                let output_rlc =
                    plonk_config.rlc(region, &digest_cells, evm_word_challenge, offset)?;
                outputs.push(digest_cells);
                output_rlcs.push(output_rlc)
            }

            data_lens.push(plonk_config.load_private(
                region,
                &Fr::from(batch_data_hash_preimage.len() as u64),
                offset,
            )?);
        }

        Ok(Self {
            inputs,
            input_rlcs,
            outputs,
            output_rlcs,
            data_lens,
            num_valid_snarks,
            chunks_are_padding,
        })
    }

    pub(crate) fn check_against_lookup_table(
        &self,
        plonk_config: &RlcConfig,
        region: &mut Region<Fr>,
        offset: &mut usize,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        for (input_rlcs, (output_rlcs, data_len)) in self
            .input_rlcs
            .iter()
            .zip_eq(self.output_rlcs.iter().zip_eq(self.data_lens.iter()))
        {
            plonk_config.lookup_keccak_rlcs(region, input_rlcs, output_rlcs, data_len, offset)?;
        }
        for (i, (input_rlcs, output_rlcs)) in self
            .input_rlcs
            .iter()
            .zip_eq(self.output_rlcs.iter())
            .enumerate()
        {
            log::debug!(
                "{}-th rlc {:?} {:?}",
                i,
                input_rlcs.value(),
                output_rlcs.value()
            );
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct ExpectedBlobCells {
    pub(crate) z: Vec<AssignedCell<Fr, Fr>>,
    pub(crate) y: Vec<AssignedCell<Fr, Fr>>,
    pub(crate) versioned_hash: Vec<AssignedCell<Fr, Fr>>,
    pub(crate) chunk_tx_data_digests: Vec<Vec<AssignedCell<Fr, Fr>>>,
}

pub(crate) struct AssignedBatchHash {
    pub(crate) hash_input: Vec<Vec<AssignedCell<Fr, Fr>>>,
    pub(crate) hash_input_rlcs: Vec<AssignedCell<Fr, Fr>>,
    pub(crate) hash_output: Vec<Vec<AssignedCell<Fr, Fr>>>,
    pub(crate) blob: ExpectedBlobCells,
    pub(crate) num_valid_snarks: AssignedCell<Fr, Fr>,
    pub(crate) chunks_are_padding: Vec<AssignedCell<Fr, Fr>>,
    pub(crate) hash_derived_public_input_cells: Vec<AssignedCell<Fr, Fr>>,
}

/// Input the hash input bytes,
/// assign the circuit for the hash function,
/// return
/// - cells of the hash digests
//
// This function asserts the following constraints on the hashes
//
// 1. batch_data_hash digest is reused for batch hash
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 4. chunks are continuous: they are linked via the state roots
// 5. batch and all its chunks use a same chain id
// 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
// padded
// 7. the hash input length are correct
// - hashes[0] has 200 bytes
// - hashes[1..N_SNARKS+1] has 168 bytes input
// - batch's data_hash length is 32 * number_of_valid_snarks
// 8. batch data hash is correct w.r.t. its RLCs
// 9. is_final_cells are set correctly
pub(crate) fn assign_batch_hashes<const N_SNARKS: usize>(
    keccak_config: &KeccakCircuitConfig<Fr>,
    rlc_config: &RlcConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    chunks_are_valid: &[bool],
    num_valid_chunks: usize,
    preimages: &[Vec<u8>],
    instance: Column<Instance>,
) -> Result<AssignedBatchHash, Error> {
    // assign the hash table
    assign_keccak_table(keccak_config, layouter, challenges, preimages)?;

    // 1. batch_data_hash digest is reused for public input hash
    // 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not
    // padded
    // 4. chunks are continuous: they are linked via the state roots
    // 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
    // padded
    // 7. batch data hash is correct w.r.t. its RLCs
    let (extracted_hash_cells, hash_derived_public_input_cells) =
        conditional_constraints::<N_SNARKS>(
            rlc_config,
            layouter,
            challenges,
            chunks_are_valid,
            num_valid_chunks,
            preimages,
            instance,
        )?;

    let batch_hash_input = &extracted_hash_cells.inputs[0]; //[0..INPUT_LEN_PER_ROUND * 2];
    let expected_blob_cells = ExpectedBlobCells {
        z: batch_hash_input[BATCH_Z_OFFSET..BATCH_Z_OFFSET + DIGEST_LEN].to_vec(),
        y: batch_hash_input[BATCH_Y_OFFSET..BATCH_Y_OFFSET + DIGEST_LEN].to_vec(),
        versioned_hash: batch_hash_input
            [BATCH_BLOB_VERSIONED_HASH_OFFSET..BATCH_BLOB_VERSIONED_HASH_OFFSET + DIGEST_LEN]
            .to_vec(),
        chunk_tx_data_digests: (0..N_SNARKS)
            .map(|i| {
                extracted_hash_cells.inputs[i + 1]
                    [CHUNK_TX_DATA_HASH_INDEX..CHUNK_TX_DATA_HASH_INDEX + DIGEST_LEN]
                    .to_vec()
            })
            .collect(),
    };

    Ok(AssignedBatchHash {
        hash_input: extracted_hash_cells.inputs,
        hash_input_rlcs: extracted_hash_cells.input_rlcs,
        hash_output: extracted_hash_cells.outputs,
        blob: expected_blob_cells,
        num_valid_snarks: extracted_hash_cells.num_valid_snarks,
        chunks_are_padding: extracted_hash_cells.chunks_are_padding,
        hash_derived_public_input_cells: hash_derived_public_input_cells.0,
    })
}

/// assign hash table
pub(crate) fn assign_keccak_table(
    config: &KeccakCircuitConfig<Fr>,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    preimages: &[Vec<u8>],
) -> Result<(), Error> {
    let keccak_capacity = KeccakCircuit::<Fr>::capacity_for_row(1 << LOG_DEGREE);

    let timer = start_timer!(|| ("multi keccak").to_string());
    // preimages consists of the following parts
    // (1) batchHash preimage =
    //      (version ||
    //      batch_index ||
    //      l1_message_popped ||
    //      total_l1_message_popped ||
    //      batch_data_hash ||
    //      versioned_hash ||
    //      parent_batch_hash ||
    //      last_block_timestamp ||
    //      z || y)
    // (2) chunk[i].piHash preimage =
    //      (chain id ||
    //      chunk[i].prevStateRoot || chunk[i].postStateRoot ||
    //      chunk[i].withdrawRoot || chunk[i].datahash || chunk[i].txdatahash)
    // (3) batchDataHash preimage =
    //      (chunk[0].dataHash || ... || chunk[k-1].dataHash)
    // each part of the preimage is mapped to image by Keccak256
    let witness = multi_keccak(preimages, challenges, keccak_capacity)
        .map_err(|e| Error::AssertionFailure(format!("multi keccak assignment failed: {e:?}")))?;
    end_timer!(timer);

    layouter
        .assign_region(
            || "assign keccak rows",
            |mut region| {
                let timer = start_timer!(|| "assign row");
                log::trace!("witness length: {}", witness.len());
                for (offset, keccak_row) in witness.iter().enumerate() {
                    let _row = config.set_row(&mut region, offset, keccak_row)?;
                }
                end_timer!(timer);
                Ok(())
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("assign keccak rows: {e}")))?;
    Ok(())
}

// Assert the following constraints
// This function asserts the following constraints on the hashes
// 1. batch_data_hash digest is reused for batch hash
// 3. batch_data_hash and chunk[i].pi_hash use a same chunk[i].data_hash when chunk[i] is not padded
// 4. chunks are continuous: they are linked via the state roots
// 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when chunk[i] is
// padded
// 7. the hash input length are correct
// - hashes[0] has 200 bytes
// - hashes[1..N_SNARKS+1] has 168 bytes input
// - batch's data_hash length is 32 * number_of_valid_snarks
// 8. batch data hash is correct w.r.t. its RLCs
// 9. is_final_cells are set correctly
#[allow(clippy::type_complexity)]
pub(crate) fn conditional_constraints<const N_SNARKS: usize>(
    rlc_config: &RlcConfig,
    layouter: &mut impl Layouter<Fr>,
    challenges: Challenges<Value<Fr>>,
    chunks_are_valid: &[bool],
    num_valid_chunks: usize,
    preimages: &[Vec<u8>],
    instance: Column<Instance>,
) -> Result<(ExtractedHashCells<N_SNARKS>, HashDerivedPublicInputCells), Error> {
    layouter
        .assign_region(
            || "rlc conditional constraints",
            |mut region| -> Result<
                (ExtractedHashCells<N_SNARKS>, HashDerivedPublicInputCells),
                halo2_proofs::plonk::Error,
            > {
                let mut offset = 0;
                rlc_config.init(&mut region)?;
                // ====================================================
                // build the flags to indicate the chunks are empty or not
                // ====================================================

                let keccak_input_challenge =
                    rlc_config.read_challenge1(&mut region, challenges, &mut offset)?;
                let evm_word_challenge =
                    rlc_config.read_challenge2(&mut region, challenges, &mut offset)?;
                let byte_accumulator =
                    rlc_config.load_private(&mut region, &Fr::from(256), &mut offset)?;

                let chunk_is_valid_cells = chunks_are_valid
                    .iter()
                    .map(|chunk_is_valid| -> Result<_, halo2_proofs::plonk::Error> {
                        rlc_config.load_private(
                            &mut region,
                            &Fr::from(*chunk_is_valid as u64),
                            &mut offset,
                        )
                    })
                    .collect::<Result<Vec<_>, halo2_proofs::plonk::Error>>()?;

                let chunk_is_valid_cell32s = chunk_is_valid_cells
                    .iter()
                    .flat_map(|cell: &AssignedCell<Fr, Fr>| vec![cell; 32])
                    .cloned()
                    .collect::<Vec<_>>();

                let chunks_are_padding = chunk_is_valid_cells
                    .iter()
                    .map(|chunk_is_valid| rlc_config.not(&mut region, chunk_is_valid, &mut offset))
                    .collect::<Result<Vec<_>, halo2_proofs::plonk::Error>>()?;

                let num_valid_snarks =
                    constrain_flags(rlc_config, &mut region, &chunk_is_valid_cells, &mut offset)?;

                log::trace!("number of valid chunks: {:?}", num_valid_snarks.value());

                // ====================================================
                // extract the hash cells from the witnesses and check against the lookup table
                // ====================================================
                let assigned_hash_cells = ExtractedHashCells::assign_hash_cells(
                    rlc_config,
                    &mut region,
                    &mut offset,
                    &keccak_input_challenge,
                    &evm_word_challenge,
                    num_valid_chunks,
                    preimages,
                    &chunk_is_valid_cell32s,
                    num_valid_snarks,
                    chunks_are_padding.clone(),
                )?;
                assigned_hash_cells.check_against_lookup_table(
                    rlc_config,
                    &mut region,
                    &mut offset,
                )?;

                // ====================================================
                // parse the hashes
                // ====================================================
                // preimages
                let (batch_hash_preimage, chunk_pi_hash_preimages, batch_data_hash_preimage) =
                    parse_hash_preimage_cells::<N_SNARKS>(&assigned_hash_cells.inputs);

                // ====================================================
                // start the actual statements
                // ====================================================
                //
                // ====================================================
                // 1. batch_data_hash digest is reused for batch hash
                // ====================================================
                //
                // batch_hash = keccak256(
                //      version ||
                //      batch_index ||
                //      l1_message_popped ||
                //      total_l1_message_popped ||
                //      batch_data_hash ||
                //      versioned_hash ||
                //      parent_batch_hash ||
                //      last_block_timestamp ||
                //      z || y)
                //
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)

                // the strategy here is to generate the RLCs of the batch_hash_preimage and
                // compare it with batchDataHash's input RLC
                let batch_data_hash_rlc = rlc_config.rlc(
                    &mut region,
                    batch_hash_preimage
                        [BATCH_DATA_HASH_OFFSET..BATCH_DATA_HASH_OFFSET + DIGEST_LEN]
                        .as_ref(),
                    &evm_word_challenge,
                    &mut offset,
                )?;

                log::debug!(
                    "batch data hash rlc recomputed: {:?}",
                    batch_data_hash_rlc.value()
                );
                log::debug!(
                    "batch data hash rlc from table: {:?}",
                    assigned_hash_cells.output_rlcs[N_SNARKS + 1].value()
                );

                // batch_circuit_debug
                region.constrain_equal(
                    batch_data_hash_rlc.cell(),
                    assigned_hash_cells.output_rlcs[N_SNARKS + 1].cell(),
                )?;

                // ====================================================
                // 1.a batch_parent_batch_hash is the same from public input
                // ====================================================
                let batch_parent_batch_hash_hi = rlc_config.rlc(
                    &mut region,
                    batch_hash_preimage
                        [BATCH_PARENT_BATCH_HASH..BATCH_PARENT_BATCH_HASH + DIGEST_LEN / 2]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;
                let batch_parent_batch_hash_lo = rlc_config.rlc(
                    &mut region,
                    batch_hash_preimage[BATCH_PARENT_BATCH_HASH + DIGEST_LEN / 2
                        ..BATCH_PARENT_BATCH_HASH + DIGEST_LEN]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;

                // ====================================================
                // 1.b result batch_hash is the same from public input
                // ====================================================
                let batch_hash_results = assigned_hash_cells.outputs[0].clone();
                let batch_hash_hi = rlc_config.rlc(
                    &mut region,
                    batch_hash_results[0..DIGEST_LEN / 2].as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;
                let batch_hash_lo = rlc_config.rlc(
                    &mut region,
                    batch_hash_results[DIGEST_LEN / 2..DIGEST_LEN].as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;

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
                //        chunk[i].datahash ||
                //        chunk[i].tx_data_hash
                //     )
                // the strategy here is to generate the RLCs of the chunk[i].dataHash and compare it
                // with batchDataHash's input RLC

                let batch_data_hash_reconstructed_rlc = {
                    let batch_data_hash_reconstructed = chunk_pi_hash_preimages
                        .iter()
                        .flat_map(|&chunk_pi_hash_preimage| {
                            chunk_pi_hash_preimage
                                [CHUNK_DATA_HASH_INDEX..CHUNK_DATA_HASH_INDEX + DIGEST_LEN]
                                .iter()
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    rlc_config.rlc_with_flag(
                        &mut region,
                        &batch_data_hash_reconstructed,
                        &keccak_input_challenge,
                        &chunk_is_valid_cell32s,
                        &mut offset,
                    )?
                };

                region.constrain_equal(
                    batch_data_hash_reconstructed_rlc.cell(),
                    assigned_hash_cells.input_rlcs[N_SNARKS + 1].cell(),
                )?;

                log::debug!(
                    "batch data hash rlc reconstructed: {:?}",
                    batch_data_hash_reconstructed_rlc.value()
                );
                log::debug!(
                    "batch data hash rlc from table: {:?}",
                    assigned_hash_cells.input_rlcs[N_SNARKS + 1].value()
                );

                // ====================================================
                // 4.a  __valid__ chunks are continuous: they are linked via the state roots
                // ====================================================
                // chunk[i].piHash =
                // keccak(
                //        chain id ||
                //        chunk[i].prevStateRoot || chunk[i].postStateRoot || chunk[i].withdrawRoot
                //        || chunk[i].datahash || chunk[i].tx_data_hash)
                for i in 0..N_SNARKS - 1 {
                    for j in 0..DIGEST_LEN {
                        // sanity check
                        assert_conditional_equal(
                            &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j],
                            &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j],
                            &chunk_is_valid_cells[i + 1],
                            format!(
                                "chunk_{i} is not continuous (state roots): {:?} {:?} {:?}",
                                &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j].value(),
                                &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j].value(),
                                &chunk_is_valid_cells[i + 1].value(),
                            )
                            .as_str(),
                        )?;
                        rlc_config.conditional_enforce_equal(
                            &mut region,
                            &chunk_pi_hash_preimages[i + 1][PREV_STATE_ROOT_INDEX + j],
                            &chunk_pi_hash_preimages[i][POST_STATE_ROOT_INDEX + j],
                            &chunk_is_valid_cells[i + 1],
                            &mut offset,
                        )?;
                    }
                }

                // ====================================================
                // 4.b  __valid__ chunks are continuous: chain_id are the same
                // ====================================================
                for i in 0..N_SNARKS - 1 {
                    for j in 0..CHAIN_ID_LEN {
                        // sanity check
                        assert_conditional_equal(
                            &chunk_pi_hash_preimages[i + 1][CHUNK_CHAIN_ID_INDEX + j],
                            &chunk_pi_hash_preimages[i][CHUNK_CHAIN_ID_INDEX + j],
                            &chunk_is_valid_cells[i + 1],
                            format!(
                                "chunk_{i} is not continuous (chain_id): {:?} {:?} {:?}",
                                &chunk_pi_hash_preimages[i + 1][CHUNK_CHAIN_ID_INDEX + j].value(),
                                &chunk_pi_hash_preimages[i][CHUNK_CHAIN_ID_INDEX + j].value(),
                                &chunk_is_valid_cells[i + 1].value(),
                            )
                            .as_str(),
                        )?;
                        rlc_config.conditional_enforce_equal(
                            &mut region,
                            &chunk_pi_hash_preimages[i + 1][CHUNK_CHAIN_ID_INDEX + j],
                            &chunk_pi_hash_preimages[i][CHUNK_CHAIN_ID_INDEX + j],
                            &chunk_is_valid_cells[i + 1],
                            &mut offset,
                        )?;
                    }
                }

                // ====================================================
                // 6. chunk[i]'s chunk_pi_hash_rlc_cells == chunk[i-1].chunk_pi_hash_rlc_cells when
                // chunk[i] is padded
                // ====================================================

                let chunk_pi_hash_rlc_cells = &assigned_hash_cells.input_rlcs[1..N_SNARKS + 1];

                for i in 1..N_SNARKS {
                    rlc_config.conditional_enforce_equal(
                        &mut region,
                        &chunk_pi_hash_rlc_cells[i - 1],
                        &chunk_pi_hash_rlc_cells[i],
                        &chunks_are_padding[i],
                        &mut offset,
                    )?;
                }

                for (i, (e, f)) in chunk_pi_hash_rlc_cells
                    .iter()
                    .zip(chunk_is_valid_cells.iter())
                    .enumerate()
                {
                    log::trace!("{i}-th chunk rlc:      {:?}", e.value());
                    log::trace!("{i}-th chunk is valid: {:?}", f.value());
                }

                // ====================================================
                // 7. batch data hash is correct w.r.t. its RLCs
                // ====================================================
                // batchDataHash = keccak(chunk[0].dataHash || ... || chunk[k-1].dataHash)
                let rlc_cell = rlc_config.rlc_with_flag(
                    &mut region,
                    batch_data_hash_preimage,
                    &keccak_input_challenge,
                    &chunk_is_valid_cell32s,
                    &mut offset,
                )?;

                // batch_circuit_debug
                // region.constrain_equal(
                //     rlc_cell.cell(),
                //     assigned_hash_cells.input_rlcs[N_SNARKS + 1].cell(),
                // )?;

                // =============================================================================
                // 8. state roots in public input corresponds correctly to chunk-level preimages
                // =============================================================================

                // Values in the public input are split into hi lo components
                // To compare byte-wise assigned hash pre-image cells on the chunk-level,
                // reconstruct two values for each pre-image.

                // chunk[i].piHash =
                //     keccak(
                //        &chain id ||
                //        chunk[i].prevStateRoot ||
                //        chunk[i].postStateRoot ||
                //        chunk[i].withdrawRoot  ||
                //        chunk[i].datahash ||
                //        chunk[i].tx_data_hash
                //     )

                // BatchCircuit PI
                // - parent state root (2 cells: hi, lo)
                // - parent batch hash ..
                // - current state root ..
                // - current batch hash ..
                // - chain id (1 Fr cell)
                // - current withdraw root ..

                // pi.parent_state_root = chunks[0].prev_state_root
                let chunk_prev_state_hi = rlc_config.rlc(
                    &mut region,
                    chunk_pi_hash_preimages[0]
                        [PREV_STATE_ROOT_INDEX..PREV_STATE_ROOT_INDEX + DIGEST_LEN / 2]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;
                let chunk_prev_state_lo = rlc_config.rlc(
                    &mut region,
                    chunk_pi_hash_preimages[0][PREV_STATE_ROOT_INDEX + DIGEST_LEN / 2
                        ..PREV_STATE_ROOT_INDEX + DIGEST_LEN]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;

                // pi.current_state_root = chunks[N_SNARKS - 1].post_state_root
                let chunk_current_state_hi = rlc_config.rlc(
                    &mut region,
                    chunk_pi_hash_preimages[N_SNARKS - 1]
                        [POST_STATE_ROOT_INDEX..POST_STATE_ROOT_INDEX + DIGEST_LEN / 2]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;
                let chunk_current_state_lo = rlc_config.rlc(
                    &mut region,
                    chunk_pi_hash_preimages[N_SNARKS - 1][POST_STATE_ROOT_INDEX + DIGEST_LEN / 2
                        ..POST_STATE_ROOT_INDEX + DIGEST_LEN]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;

                // pi.current_withdraw_root = chunks[N_SNARKS - 1].withdraw_root
                let chunk_current_withdraw_root_hi = rlc_config.rlc(
                    &mut region,
                    chunk_pi_hash_preimages[N_SNARKS - 1]
                        [WITHDRAW_ROOT_INDEX..WITHDRAW_ROOT_INDEX + DIGEST_LEN / 2]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;
                let chunk_current_withdraw_root_lo = rlc_config.rlc(
                    &mut region,
                    chunk_pi_hash_preimages[N_SNARKS - 1]
                        [WITHDRAW_ROOT_INDEX + DIGEST_LEN / 2..WITHDRAW_ROOT_INDEX + DIGEST_LEN]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;

                // pi.chain_id = chunks[N_SNARKS - 1].chain_id
                // Note: Chunk-chaining constraints in 4.b guarantee that previously assigned chain_id cells have the same values.
                let chunk_chain_id = rlc_config.rlc(
                    &mut region,
                    chunk_pi_hash_preimages[N_SNARKS - 1]
                        [CHUNK_CHAIN_ID_INDEX..CHUNK_CHAIN_ID_INDEX + CHAIN_ID_LEN]
                        .as_ref(),
                    &byte_accumulator,
                    &mut offset,
                )?;

                log::trace!("rlc chip uses {} rows", offset);

                Ok((
                    assigned_hash_cells,
                    HashDerivedPublicInputCells(vec![
                        batch_parent_batch_hash_hi,
                        batch_parent_batch_hash_lo,
                        batch_hash_hi,
                        batch_hash_lo,
                        chunk_prev_state_hi,
                        chunk_prev_state_lo,
                        chunk_current_state_hi,
                        chunk_current_state_lo,
                        chunk_current_withdraw_root_hi,
                        chunk_current_withdraw_root_lo,
                        chunk_chain_id,
                    ]),
                ))
            },
        )
        .map_err(|e| Error::AssertionFailure(format!("aggregation: {e}")))
}

/// Input a list of flags whether the snark is valid
///
/// Assert the following relations on the flags:
/// - all elements are binary
/// - the first element is 1
/// - for the next elements, if the element is 1, the previous element must also be 1
///
/// Return a cell for number of valid snarks
fn constrain_flags(
    rlc_config: &RlcConfig,
    region: &mut Region<Fr>,
    chunk_are_valid: &[AssignedCell<Fr, Fr>],
    offset: &mut usize,
) -> Result<AssignedCell<Fr, Fr>, halo2_proofs::plonk::Error> {
    assert!(!chunk_are_valid.is_empty());

    let one = {
        let one = rlc_config.load_private(region, &Fr::one(), offset)?;
        let one_cell = rlc_config.one_cell(chunk_are_valid[0].cell().region_index);
        region.constrain_equal(one.cell(), one_cell)?;
        one
    };

    // the first element is 1
    region.constrain_equal(chunk_are_valid[0].cell(), one.cell())?;

    let mut res = chunk_are_valid[0].clone();
    for (index, cell) in chunk_are_valid.iter().enumerate().skip(1) {
        rlc_config.enforce_binary(region, cell, offset)?;

        // if the element is 1, the previous element must also be 1
        rlc_config.conditional_enforce_equal(
            region,
            &chunk_are_valid[index - 1],
            &one,
            cell,
            offset,
        )?;

        res = rlc_config.add(region, &res, cell, offset)?;
    }
    Ok(res)
}
