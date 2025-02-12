use ark_std::test_rng;
use halo2_base::{
    gates::range::{RangeConfig, RangeStrategy},
    Context, ContextParams,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::Rng;
use std::fs;
use zkevm_circuits::{
    table::{KeccakTable, RangeTable, U8Table},
    util::Challenges,
};

use crate::{
    aggregation::{
        batch_data::N_BLOB_BYTES,
        witgen::{process, MultiBlockProcessResult},
        BatchData, RlcConfig,
    },
    blob_consistency::{
        eip4844::{
            blob::PointEvaluationAssignments, get_blob_bytes, get_coefficients, get_versioned_hash,
            AssignedBarycentricEvaluationConfig, BarycentricEvaluationConfig,
        },
        BlobDataConfig,
    },
    constants::N_BYTES_U256,
    decode_bytes,
    param::ConfigParams,
    BatchDataConfig, ChunkInfo, MAX_AGG_SNARKS,
};

#[derive(Default)]
struct BlobCircuit {
    data: BatchData<MAX_AGG_SNARKS>,

    overwrite_num_valid_chunks: bool,
    overwrite_challenge_digest: Option<usize>,
    overwrite_chunk_data_digests: Option<(usize, usize)>,
    overwrite_chunk_idx: Option<usize>,
    overwrite_accumulator: Option<usize>,
    overwrite_preimage_rlc: Option<usize>,
    overwrite_digest_rlc: Option<usize>,
    overwrite_is_boundary: Option<usize>,
    overwrite_is_padding: Option<usize>,
}

#[derive(Clone, Debug)]
struct BlobConfig {
    challenges: Challenges,

    keccak_table: KeccakTable,

    rlc: RlcConfig,
    batch_data_config: BatchDataConfig<MAX_AGG_SNARKS>,
    blob_data: BlobDataConfig<MAX_AGG_SNARKS>,
    barycentric: BarycentricEvaluationConfig,
}

impl Circuit<Fr> for BlobCircuit {
    type Config = BlobConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let u8_table = U8Table::construct(meta);
        let range_table = RangeTable::construct(meta);
        let challenges = Challenges::construct_p1(meta);
        let keccak_table = KeccakTable::construct(meta);

        let rlc = RlcConfig::configure(meta, &keccak_table, challenges);

        let parameters = ConfigParams::aggregation_param();
        let range = RangeConfig::<Fr>::configure(
            meta,
            RangeStrategy::Vertical,
            &parameters.num_advice,
            &parameters.num_lookup_advice,
            parameters.num_fixed,
            parameters.lookup_bits,
            0,
            parameters.degree.try_into().unwrap(),
        );
        let barycentric = BarycentricEvaluationConfig::construct(range);

        let challenge_expressions = challenges.exprs(meta);
        let batch_data_config = BatchDataConfig::configure(
            meta,
            &challenge_expressions,
            u8_table,
            range_table,
            &keccak_table,
        );
        let blob_data = BlobDataConfig::configure(meta, &challenge_expressions, u8_table);

        BlobConfig {
            challenges,

            keccak_table,

            rlc,
            batch_data_config,
            blob_data,
            barycentric,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let challenge_values = config.challenges.values(&layouter);

        let batch_bytes = self.data.get_batch_data_bytes();
        let blob_bytes = get_blob_bytes(&batch_bytes);
        let coeffs = get_coefficients(&blob_bytes);
        let versioned_hash = get_versioned_hash(&coeffs);

        config.keccak_table.dev_load(
            &mut layouter,
            &self.data.preimages(versioned_hash),
            &challenge_values,
        )?;

        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        let barycentric_assignments = layouter.assign_region(
            || "barycentric config",
            |region| -> Result<AssignedBarycentricEvaluationConfig, Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(AssignedBarycentricEvaluationConfig::default());
                }

                let gate = &config.barycentric.scalar.range.gate;
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        max_rows: gate.max_rows,
                        num_context_ids: 1,
                        fixed_columns: gate.constants.clone(),
                    },
                );

                let point_eval =
                    PointEvaluationAssignments::new(&self.data, &blob_bytes, versioned_hash);
                Ok(config
                    .barycentric
                    .assign(&mut ctx, &blob_bytes, point_eval.challenge_digest))
            },
        )?;

        let chunks_are_padding = layouter.assign_region(
            || "dev: chunks are padding or not",
            |mut region| -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
                let rlc_config = &config.rlc;
                rlc_config.init(&mut region)?;
                let mut rlc_config_offset = 0;

                let mut chunks_are_padding = Vec::with_capacity(MAX_AGG_SNARKS);
                for i in 0..MAX_AGG_SNARKS {
                    let is_padding = (i as u16) >= self.data.num_valid_chunks;
                    chunks_are_padding.push(rlc_config.load_private(
                        &mut region,
                        &Fr::from(is_padding as u64),
                        &mut rlc_config_offset,
                    )?);
                }

                Ok(chunks_are_padding)
            },
        )?;

        config.batch_data_config.load_range_tables(&mut layouter)?;

        config
            .blob_data
            .assign(&mut layouter, challenge_values, &config.rlc, &blob_bytes)?;

        layouter.assign_region(
            || "BatchDataConfig",
            |mut region| {
                let assigned_rows = config.batch_data_config.assign_rows(
                    &mut region,
                    challenge_values,
                    &self.data,
                    versioned_hash,
                )?;
                let assigned_batch_data_export = config.batch_data_config.assign_internal_checks(
                    &mut region,
                    challenge_values,
                    &config.rlc,
                    &chunks_are_padding,
                    &barycentric_assignments.barycentric_assignments,
                    &assigned_rows,
                )?;

                if let Some(i) = self.overwrite_chunk_idx {
                    increment_cell(&mut region, &assigned_rows[i].chunk_idx)?;
                }
                if let Some(i) = self.overwrite_accumulator {
                    increment_cell(&mut region, &assigned_rows[i].accumulator)?;
                }
                if let Some(i) = self.overwrite_preimage_rlc {
                    increment_cell(&mut region, &assigned_rows[i].preimage_rlc)?;
                }
                if let Some(i) = self.overwrite_digest_rlc {
                    increment_cell(&mut region, &assigned_rows[i].digest_rlc)?;
                }
                if let Some(i) = self.overwrite_is_boundary {
                    increment_cell(&mut region, &assigned_rows[i].is_boundary)?;
                }
                if let Some(i) = self.overwrite_is_padding {
                    increment_cell(&mut region, &assigned_rows[i].is_padding)?;
                }
                if self.overwrite_num_valid_chunks {
                    increment_cell(&mut region, &assigned_batch_data_export.num_valid_chunks)?;
                }
                if let Some(i) = self.overwrite_challenge_digest {
                    increment_cell(
                        &mut region,
                        &assigned_rows[BatchData::<MAX_AGG_SNARKS>::n_rows() - N_BYTES_U256 + i]
                            .byte,
                    )?;
                }
                if let Some((i, j)) = self.overwrite_chunk_data_digests {
                    increment_cell(
                        &mut region,
                        &assigned_batch_data_export.chunk_data_digests[i][j],
                    )?;
                }
                Ok(())
            },
        )
    }
}

fn increment_cell(
    region: &mut Region<Fr>,
    assigned_cell: &AssignedCell<Fr, Fr>,
) -> Result<AssignedCell<Fr, Fr>, Error> {
    let cell = assigned_cell.cell();
    region.assign_advice(
        || "incrementing previously assigned cell",
        cell.column.try_into().expect("assigned cell not advice"),
        cell.row_offset,
        || assigned_cell.value() + Value::known(Fr::one()),
    )
}

fn check_data(data: BatchData<MAX_AGG_SNARKS>) -> Result<(), Vec<VerifyFailure>> {
    let circuit = BlobCircuit {
        data,
        ..Default::default()
    };
    check_circuit(&circuit)
}

fn check_circuit(circuit: &BlobCircuit) -> Result<(), Vec<VerifyFailure>> {
    // TODO: check where rows were not sufficient that we had to increase k from 20 to 21.
    let k = 21;
    let mock_prover = MockProver::<Fr>::run(k, circuit, vec![]).expect("failed to run mock prover");
    mock_prover.verify_par()
}

#[test]
fn blob_circuit_completeness() {
    // now batch274 is an deterministic case of batch -> blob (fully packed).
    // Full blob test case
    // batch274 contains batch bytes that will produce a full blob
    let full_blob = hex::decode(
        fs::read_to_string("./data/test_batches/batch274.hex")
            .expect("file path exists")
            .trim(),
    )
    .expect("should load full blob batch bytes");

    // batch274 contains metadatas
    let segmented_full_blob_src = BatchData::<MAX_AGG_SNARKS>::segment_with_metadata(full_blob);

    let all_empty_chunks: Vec<Vec<u8>> = vec![vec![]; MAX_AGG_SNARKS];
    let one_chunk = vec![vec![2, 3, 4, 100, 1]];
    let two_chunks = vec![vec![100; 1000], vec![2, 3, 4, 100, 1]];
    let max_chunks: Vec<Vec<u8>> = (0..MAX_AGG_SNARKS)
        .map(|i| (10u8..10 + u8::try_from(i).unwrap()).collect())
        .collect();
    let empty_chunk_followed_by_nonempty_chunk = vec![vec![], vec![3, 100, 24, 30]];
    let nonempty_chunk_followed_by_empty_chunk = vec![vec![3, 100, 24, 30], vec![]];
    let empty_and_nonempty_chunks = vec![
        vec![3, 100, 24, 30],
        vec![],
        vec![],
        vec![100, 23, 34, 24, 10],
        vec![],
    ];
    let all_empty_except_last = std::iter::repeat(vec![])
        .take(MAX_AGG_SNARKS - 1)
        .chain(std::iter::once(vec![3, 100, 24, 30]))
        .collect::<Vec<_>>();

    for (idx, blob) in [
        segmented_full_blob_src,
        one_chunk,
        two_chunks,
        max_chunks,
        all_empty_chunks,
        empty_chunk_followed_by_nonempty_chunk,
        nonempty_chunk_followed_by_empty_chunk,
        empty_and_nonempty_chunks,
        all_empty_except_last,
    ]
    .into_iter()
    .enumerate()
    {
        let batch_data = BatchData::from(&blob);

        // First blob(batch274's blob data) is purposely constructed to take full blob space
        if idx == 0 {
            let batch_data_bytes = batch_data.get_batch_data_bytes();
            let blob_data_bytes = get_blob_bytes(&batch_data_bytes);
            let blob_data_bytes_len = blob_data_bytes.len();

            assert_eq!(
                blob_data_bytes_len, N_BLOB_BYTES,
                "should be full blob: expected={N_BLOB_BYTES}, got={blob_data_bytes_len}",
            );
        }

        assert_eq!(check_data(batch_data), Ok(()), "{:?}", blob);
    }
}

#[test]
#[ignore = "needs new test setup"]
fn zstd_encoding_consistency() {
    // Load test blob bytes
    let blob_bytes = hex::decode(
        fs::read_to_string("./data/test_blobs/blob005.hex")
            .expect("file path exists")
            .trim(),
    )
    .expect("should load blob bytes");

    // Leave out most significant byte for compressed data
    let mut compressed: Vec<u8> = vec![];
    for i in 0..blob_bytes.len() / 32 {
        for j in 1..32usize {
            compressed.push(blob_bytes[i * 32 + j]);
        }
    }

    // Decode into original batch bytes
    let MultiBlockProcessResult {
        witness_rows: _w,
        literal_bytes: _l,
        fse_aux_tables: _f,
        block_info_arr: _b,
        sequence_info_arr: _s,
        address_table_rows: _a,
        sequence_exec_results,
    } = process::<Fr>(&compressed, Value::known(Fr::from(123456789)));

    // The decoded batch data consists of:
    // - [0..182] bytes of metadata
    // - [182..] remaining bytes of chunk data
    let recovered_bytes = sequence_exec_results
        .into_iter()
        .flat_map(|r| r.recovered_bytes)
        .collect::<Vec<u8>>();
    let segmented_batch_data = BatchData::<MAX_AGG_SNARKS>::segment_with_metadata(recovered_bytes);

    // Re-encode into blob bytes
    let re_encoded_batch_data: BatchData<MAX_AGG_SNARKS> = BatchData::from(&segmented_batch_data);
    let batch_bytes = re_encoded_batch_data.get_batch_data_bytes();
    let blob_bytes = get_blob_bytes(&batch_bytes);

    assert_eq!(compressed, blob_bytes, "Blob bytes must match");
}

#[test]
#[ignore = "needs new test setup"]
fn zstd_encoding_consistency_from_batch() {
    // Load test batch bytes
    // batch274 contains batch bytes that will produce a full blob
    let batch_bytes = hex::decode(
        fs::read_to_string("./data/test_batches/batch274.hex")
            .expect("file path exists")
            .trim(),
    )
    .expect("should load batch bytes");
    let segmented_batch_bytes =
        BatchData::<MAX_AGG_SNARKS>::segment_with_metadata(batch_bytes.clone());

    // Re-encode into blob bytes
    let encoded_batch_data: BatchData<MAX_AGG_SNARKS> = BatchData::from(&segmented_batch_bytes);
    let batch_bytes = encoded_batch_data.get_batch_data_bytes();
    let blob_bytes = get_blob_bytes(&batch_bytes);

    // full blob len sanity check
    assert_eq!(
        blob_bytes.len(),
        N_BLOB_BYTES,
        "full blob is the correct len"
    );

    // Decode into original batch bytes
    let MultiBlockProcessResult {
        witness_rows: _w,
        literal_bytes: _l,
        fse_aux_tables: _f,
        block_info_arr: _b,
        sequence_info_arr: _s,
        address_table_rows: _a,
        sequence_exec_results,
    } = process::<Fr>(&blob_bytes, Value::known(Fr::from(123456789)));

    let decoded_batch_bytes = sequence_exec_results
        .into_iter()
        .flat_map(|r| r.recovered_bytes)
        .collect::<Vec<u8>>();

    assert_eq!(batch_bytes, decoded_batch_bytes, "batch bytes must match");
}

fn generic_batch_data() -> BatchData<MAX_AGG_SNARKS> {
    BatchData::from(&vec![
        vec![3, 100, 24, 30],
        vec![],
        vec![100; 300],
        vec![100, 23, 34, 24, 10],
        vec![200; 20],
        vec![],
        vec![200; 20],
    ])
}

#[test]
fn generic_batch_data_is_valid() {
    assert_eq!(check_data(generic_batch_data()), Ok(()));
}

#[test]
fn inconsistent_chunk_size() {
    let mut blob_data = generic_batch_data();
    blob_data.chunk_sizes[4] += 1;
    assert!(check_data(blob_data).is_err());
}

#[test]
fn too_many_empty_chunks() {
    let mut blob_data = generic_batch_data();
    blob_data.num_valid_chunks += 1;
    assert!(check_data(blob_data).is_err());
}

#[test]
fn too_few_empty_chunks() {
    let mut blob_data = generic_batch_data();
    blob_data.num_valid_chunks -= 1;
    assert!(check_data(blob_data).is_err());
}

#[test]
fn inconsistent_chunk_bytes() {
    let mut blob_data = generic_batch_data();
    blob_data.chunk_data[0].push(128);
    assert!(check_data(blob_data).is_err());
}

#[test]
fn overwrite_num_valid_chunks() {
    let circuit = BlobCircuit {
        data: generic_batch_data(),
        overwrite_num_valid_chunks: true,
        ..Default::default()
    };
    assert!(check_circuit(&circuit).is_err())
}

#[test]
fn overwrite_challenge_digest_byte() {
    for i in [0, 1, 10, 31] {
        let circuit = BlobCircuit {
            data: generic_batch_data(),
            overwrite_challenge_digest: Some(i),
            ..Default::default()
        };
        assert!(check_circuit(&circuit).is_err())
    }
}

#[test]
fn overwrite_chunk_data_digest_byte() {
    for indices in [(0, 0), (4, 30), (10, 31), (MAX_AGG_SNARKS - 1, 2)] {
        let circuit = BlobCircuit {
            data: generic_batch_data(),
            overwrite_chunk_data_digests: Some(indices),
            ..Default::default()
        };
        assert!(check_circuit(&circuit).is_err())
    }
}

const OVERWRITE_ROWS: [usize; 6] = [
    0,
    10,
    BatchData::<MAX_AGG_SNARKS>::n_rows_metadata() - 1,
    BatchData::<MAX_AGG_SNARKS>::n_rows_metadata(),
    BatchData::<MAX_AGG_SNARKS>::n_rows_metadata() + 100,
    BatchData::<MAX_AGG_SNARKS>::n_rows_metadata() + BatchData::<MAX_AGG_SNARKS>::n_rows_data() - 1,
];

#[test]
fn overwrite_chunk_idx() {
    for row in OVERWRITE_ROWS {
        let circuit = BlobCircuit {
            data: generic_batch_data(),
            overwrite_chunk_idx: Some(row),
            ..Default::default()
        };
        assert!(check_circuit(&circuit).is_err())
    }
}

#[test]
fn overwrite_accumulator() {
    for row in OVERWRITE_ROWS {
        let circuit = BlobCircuit {
            data: generic_batch_data(),
            overwrite_accumulator: Some(row),
            ..Default::default()
        };
        assert!(check_circuit(&circuit).is_err())
    }
}

#[test]
fn overwrite_preimage_rlc() {
    for row in OVERWRITE_ROWS {
        let circuit = BlobCircuit {
            data: generic_batch_data(),
            overwrite_preimage_rlc: Some(row),
            ..Default::default()
        };
        assert!(check_circuit(&circuit).is_err())
    }
}

#[test]
fn overwrite_digest_rlc() {
    for row in OVERWRITE_ROWS {
        let circuit = BlobCircuit {
            data: generic_batch_data(),
            overwrite_digest_rlc: Some(row),
            ..Default::default()
        };
        assert!(check_circuit(&circuit).is_err())
    }
}

#[test]
fn overwrite_is_boundary() {
    for row in OVERWRITE_ROWS {
        let circuit = BlobCircuit {
            data: generic_batch_data(),
            overwrite_is_boundary: Some(row),
            ..Default::default()
        };
        assert!(check_circuit(&circuit).is_err())
    }
}

#[test]
fn overwrite_is_padding() {
    for row in OVERWRITE_ROWS {
        let circuit = BlobCircuit {
            data: generic_batch_data(),
            overwrite_is_padding: Some(row),
            ..Default::default()
        };
        assert!(check_circuit(&circuit).is_err())
    }
}

#[test]
fn test_decode_blob() {
    let mut rng = test_rng();

    let num_chunks = rng.gen_range(0..MAX_AGG_SNARKS);
    let mut chunks = (0..num_chunks)
        .map(|_| ChunkInfo::mock_random_chunk_info_for_testing(&mut rng))
        .collect::<Vec<_>>();
    for i in 0..num_chunks - 1 {
        chunks[i + 1].prev_state_root = chunks[i].post_state_root;
    }
    let padded_chunk = ChunkInfo::mock_padded_chunk_info_for_testing(&chunks[num_chunks - 1]);
    let padded_chunks = [chunks, vec![padded_chunk; MAX_AGG_SNARKS - num_chunks]].concat();

    let batch_data = BatchData::<MAX_AGG_SNARKS>::new(num_chunks, &padded_chunks);
    let batch_bytes = batch_data.get_batch_data_bytes();

    let conditional_encode = |bytes: &[u8], encode: bool| -> Vec<u8> {
        let mut encoded_bytes = crate::witgen::zstd_encode(bytes);
        if !encode {
            encoded_bytes = batch_bytes.to_vec();
        }
        encoded_bytes.insert(0, encode as u8);
        encoded_bytes
    };

    // case 1: no encode
    assert_eq!(
        conditional_encode(batch_bytes.as_slice(), false)[1..],
        batch_bytes,
    );

    // case 2: yes encode
    assert_eq!(
        decode_bytes(&conditional_encode(batch_bytes.as_slice(), true)).expect("should decode"),
        batch_bytes,
    );
}

use super::*;

#[test]
fn test_conversions() {
    let scalar = Scalar::one();
    let word = U256::one();
    let mut digest = H256::zero();
    digest.0[31] = 1;

    assert_eq!(digest_from_word(word), digest);
    assert_eq!(digest_from_scalar(scalar), digest);
    assert_eq!(scalar_from_word(word), scalar);
    assert_eq!(scalar_from_digest(digest), scalar);
    assert_eq!(word_from_digest(digest), word);
}
