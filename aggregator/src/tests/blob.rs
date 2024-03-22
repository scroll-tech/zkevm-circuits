use crate::{
    aggregation::{BlobDataConfig, RlcConfig},
    barycentric::{BarycentricEvaluationCells, BarycentricEvaluationConfig},
    batch::BlobData,
    blob::{Blob, BlobAssignments},
    param::ConfigParams,
    MAX_AGG_SNARKS,
};
use halo2_base::{
    gates::range::{RangeConfig, RangeStrategy},
    Context, ContextParams,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use zkevm_circuits::{
    table::{KeccakTable, RangeTable, U8Table},
    util::Challenges,
};

struct BlobCircuit {
    data: BlobData,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct BlobConfig {
    challenges: Challenges,

    keccak_table: KeccakTable,

    rlc: RlcConfig,
    blob_data: BlobDataConfig,
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
        let challenges = Challenges::construct(meta);
        let keccak_table = KeccakTable::construct(meta);

        let rlc = RlcConfig::configure(meta, challenges);

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
        let blob_data = BlobDataConfig::configure(
            meta,
            challenge_expressions,
            u8_table,
            range_table,
            &keccak_table,
        );

        BlobConfig {
            challenges,

            keccak_table,

            rlc,
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
            |region| -> Result<BarycentricEvaluationCells, Error> {
                if first_pass {
                    first_pass = false;
                    return Ok(BarycentricEvaluationCells::default());
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

                let blob = BlobAssignments::from(self.data.clone());
                Ok(config.barycentric.assign2(
                    &mut ctx,
                    blob.coefficients,
                    blob.challenge_digest,
                    blob.evaluation,
                ))
            },
        )?;

        config.blob_data.assign(
            &mut layouter,
            challenge_values,
            &config.rlc,
            &self.data,
            &barycentric_assignments.barycentric_assignments,
        )?;

        Ok(())
    }
}

fn check_circuit(data: BlobData) -> Result<(), Vec<VerifyFailure>> {
    let k = 20;
    let mock_prover =
        MockProver::<Fr>::run(k, &BlobCircuit { data }, vec![]).expect("failed to run mock prover");
    mock_prover.verify_par()
}

#[test]
fn blob_circuit_completeness() {
    let all_empty_chunks = Blob(vec![vec![]; MAX_AGG_SNARKS]);
    let one_chunk = Blob(vec![vec![2, 3, 4, 100, 1]]);
    let two_chunks = Blob(vec![vec![100; 1000], vec![2, 3, 4, 100, 1]]);
    let max_chunks = Blob(
        (0..MAX_AGG_SNARKS)
            .map(|i| (10u8..10 + u8::try_from(i).unwrap()).collect())
            .collect(),
    );
    let empty_chunk_followed_by_nonempty_chunk = Blob(vec![vec![], vec![3, 100, 24, 30]]);
    let nonempty_chunk_followed_by_empty_chunk = Blob(vec![vec![3, 100, 24, 30], vec![]]);
    let empty_and_nonempty_chunks = Blob(vec![
        vec![3, 100, 24, 30],
        vec![],
        vec![],
        vec![100, 23, 34, 24, 10],
        vec![],
    ]);

    for blob in [
        one_chunk,
        two_chunks,
        max_chunks,
        all_empty_chunks,
        empty_chunk_followed_by_nonempty_chunk,
        nonempty_chunk_followed_by_empty_chunk,
        empty_and_nonempty_chunks,
    ] {
        assert_eq!(
            check_circuit(BlobData::from(blob.clone())),
            Ok(()),
            "{:?}",
            blob
        );
    }
}

#[test]
#[ignore = "TODO: enable later"]
fn blob_circuit_soundness() {
    let padding_chunk_with_bytes = BlobData::default();

    assert_eq!(check_circuit(padding_chunk_with_bytes), Ok(()));
}
