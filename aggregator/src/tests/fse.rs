use std::collections::BTreeMap;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, ConstraintSystem, Error, Fixed},
};
use zkevm_circuits::table::{BitwiseOpTable, Pow2Table, RangeTable, U8Table};

use crate::{
    decoder::tables::{FixedTable, FseTable},
    witgen::{FseAuxiliaryTableData, FseTableKind},
};

#[derive(Clone)]
struct TestFseConfig {
    /// Fixed column to mark all enabled rows.
    q_enable: Column<Fixed>,
    /// Range table for [0, 8).
    range8_table: RangeTable<8>,
    /// Range table for [0, 256).
    u8_table: U8Table,
    /// Range table for [0, 512).
    range512_table: RangeTable<512>,
    /// Power of two table for (exponent, exponentiation) where exponentiation = 2^exponent.
    pow2_table: Pow2Table<20>,
    /// Bitwise operation table for AND.
    bitwise_op_table: BitwiseOpTable<1, 256, 256>,
    /// Fixed table for all decoder related requirements.
    fixed_table: FixedTable,
    /// FseTable with AL <= 7, i.e. table_size <= 256.
    fse_table: FseTable<256, 256>,
}

impl TestFseConfig {
    fn unusable_rows() -> usize {
        64
    }
}

#[derive(Default)]
struct TestFseCircuit {
    /// Degree for the test circuit, i.e. 1 << k number of rows.
    k: u32,
    /// List of reconstructed FSE tables.
    data: Vec<FseAuxiliaryTableData>,
}

impl Circuit<Fr> for TestFseCircuit {
    type Config = TestFseConfig;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let q_enable = meta.fixed_column();
        let u8_table = U8Table::construct(meta);
        let range8_table = RangeTable::construct(meta);
        let range512_table = RangeTable::construct(meta);
        let pow2_table = Pow2Table::construct(meta);
        let bitwise_op_table = BitwiseOpTable::construct(meta);
        let fixed_table = FixedTable::construct(meta);

        let fse_table = FseTable::configure(
            meta,
            q_enable,
            &fixed_table,
            u8_table,
            range8_table,
            range512_table,
            pow2_table,
            bitwise_op_table,
        );

        Self::Config {
            q_enable,
            range8_table,
            u8_table,
            range512_table,
            pow2_table,
            bitwise_op_table,
            fixed_table,
            fse_table,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let n_enabled = (1 << self.k) - Self::Config::unusable_rows();

        config.range8_table.load(&mut layouter)?;
        config.u8_table.load(&mut layouter)?;
        config.range512_table.load(&mut layouter)?;
        config.pow2_table.load(&mut layouter)?;
        config.bitwise_op_table.load(&mut layouter)?;
        config.fixed_table.load(&mut layouter)?;

        config
            .fse_table
            .assign(&mut layouter, &self.data, n_enabled)?;

        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        layouter.assign_region(
            || "TestFseCircuit",
            |mut region| {
                if first_pass {
                    first_pass = false;
                    return Ok(());
                }

                for offset in 0..n_enabled {
                    region.assign_fixed(
                        || "q_enable",
                        config.q_enable,
                        offset,
                        || Value::known(Fr::one()),
                    )?;
                }

                Ok(())
            },
        )?;

        layouter.assign_region(|| "TestFseCircuit: malicious assignments", |_region| Ok(()))
    }
}

enum DataInput {
    /// Inner vector represents the normalised distribution of symbols in the FSE table.
    Distribution(Vec<i32>, u8),
    /// Inner vector represents the raw source bytes from which the normalised distribution needs
    /// to be decoded.
    SourceBytes(Vec<u8>, usize),
}

fn run(input: DataInput, is_predefined: bool) -> Result<(), Vec<VerifyFailure>> {
    let k = 18;

    let fse_table = match input {
        DataInput::Distribution(distribution, accuracy_log) => {
            let normalised_probs = {
                let mut normalised_probs = BTreeMap::new();
                for (i, &prob) in distribution.iter().enumerate() {
                    normalised_probs.insert(i as u64, prob);
                }
                normalised_probs
            };
            let (state_map, sorted_state_map) =
                FseAuxiliaryTableData::transform_normalised_probs(&normalised_probs, accuracy_log);
            FseAuxiliaryTableData {
                block_idx: 1,
                table_kind: FseTableKind::LLT,
                table_size: 1 << accuracy_log,
                is_predefined: true,
                normalised_probs,
                sym_to_states: state_map,
                sym_to_sorted_states: sorted_state_map,
            }
        }
        DataInput::SourceBytes(src, byte_offset) => {
            let (_, _, fse_table) = FseAuxiliaryTableData::reconstruct(
                &src,
                1,
                FseTableKind::LLT,
                byte_offset,
                is_predefined,
            )
            .expect("unexpected failure: FseTable::reconstruct");
            fse_table
        }
    };

    let test_circuit = TestFseCircuit {
        k,
        data: vec![fse_table],
    };

    let prover =
        MockProver::run(k, &test_circuit, vec![]).expect("unexpected failure: MockProver::run");
    prover.verify_par()
}

#[test]
fn test_fse_dist_ok() {
    let distribution = vec![
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1,
        1, 1, -1, -1, -1, -1,
    ];
    assert!(run(DataInput::Distribution(distribution, 6), true).is_ok())
}

#[test]
fn test_fse_src_ok() {
    let src = vec![
        0x21, 0x9d, 0x51, 0xcc, 0x18, 0x42, 0x44, 0x81, 0x8c, 0x94, 0xb4, 0x50, 0x1e,
    ];
    assert!(run(DataInput::SourceBytes(src, 0), false).is_ok())
}
