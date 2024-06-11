use crate::{
    aggregation::{
        AssignedBarycentricEvaluationConfig, BarycentricEvaluationConfig, BlobDataConfig, RlcConfig,
    },
    blob::{BatchData, PointEvaluationAssignments, N_BYTES_U256},
    param::ConfigParams,
    BatchDataConfig, MAX_AGG_SNARKS,
};
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
use zkevm_circuits::{
    table::{KeccakTable, RangeTable, U8Table},
    util::Challenges,
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

        config
            .keccak_table
            .dev_load(&mut layouter, &self.data.preimages(), &challenge_values)?;

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

                let point_eval = PointEvaluationAssignments::from(&self.data);
                Ok(config.barycentric.assign(
                    &mut ctx,
                    &point_eval.coefficients,
                    point_eval.challenge_digest,
                    point_eval.evaluation,
                ))
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

        config.blob_data.assign(
            &mut layouter,
            challenge_values,
            &config.rlc,
            &self.data,
            &barycentric_assignments.barycentric_assignments,
        )?;

        layouter.assign_region(
            || "BatchDataConfig",
            |mut region| {
                let assigned_rows = config.batch_data_config.assign_rows(
                    &mut region,
                    challenge_values,
                    &self.data,
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
    // single chunk in batch, but the chunk has a size of N_ROWS_DATA
    let full_blob = vec![vec![123; BatchData::<MAX_AGG_SNARKS>::n_rows_data()]];
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

    for blob in [
        full_blob,
        one_chunk,
        two_chunks,
        max_chunks,
        all_empty_chunks,
        empty_chunk_followed_by_nonempty_chunk,
        nonempty_chunk_followed_by_empty_chunk,
        empty_and_nonempty_chunks,
        all_empty_except_last,
    ] {
        assert_eq!(check_data(BatchData::from(&blob)), Ok(()), "{:?}", blob);
    }
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
