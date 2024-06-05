use crate::aggregation::{
    decoder::tables::LiteralsHeaderTable,
    witgen::{init_zstd_encoder, process, MultiBlockProcessResult, ZstdTag, ZstdWitnessRow},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, ConstraintSystem, Error, Fixed},
};
use rand::{self, Rng};
use std::{fs, io::Write};
use zkevm_circuits::table::RangeTable;

#[derive(Clone)]
struct TestLiteralsHeaderConfig {
    /// Fixed column to mark all enabled rows.
    q_enable: Column<Fixed>,
    /// Range Table for [0, 8).
    range8: RangeTable<8>,
    /// Range Table for [0, 16).
    range16: RangeTable<16>,
    /// Helper table for decoding the regenerated size from LiteralsHeader.
    literals_header_table: LiteralsHeaderTable,
}

impl TestLiteralsHeaderConfig {
    fn unusable_rows() -> usize {
        64
    }
}

#[derive(Default)]
struct TestLiteralsHeaderCircuit {
    /// Degree for the test circuit, i.e. 1 << k number of rows.
    k: u32,
    /// Compressed bytes
    compressed: Vec<u8>,
    /// Variant of possible unsound case.
    case: UnsoundCase,
}

impl Circuit<Fr> for TestLiteralsHeaderCircuit {
    type Config = TestLiteralsHeaderConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let q_enable = meta.fixed_column();

        // Helper tables
        let range8 = RangeTable::construct(meta);
        let range16 = RangeTable::construct(meta);
        let literals_header_table = LiteralsHeaderTable::configure(meta, q_enable, range8, range16);

        Self::Config {
            q_enable,
            range8,
            range16,
            literals_header_table,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let n_enabled = (1 << self.k) - Self::Config::unusable_rows();

        let MultiBlockProcessResult {
            witness_rows,
            literal_bytes: _l,
            fse_aux_tables: _f,
            block_info_arr: _b,
            sequence_info_arr: _s,
            address_table_rows: _a,
            sequence_exec_results: _seq,
        } = process(&self.compressed, Value::known(Fr::from(12345)));

        // Load auxiliary tables
        config.range8.load(&mut layouter)?;
        config.range16.load(&mut layouter)?;

        /////////////////////////////////////////
        ///// Assign LiteralHeaderTable  ////////
        /////////////////////////////////////////
        let mut literal_headers: Vec<(u64, u64, (u64, u64, u64))> = vec![]; // (block_idx, byte_offset, (byte0, byte1, byte2))
        let literal_header_rows = witness_rows
            .iter()
            .filter(|r| r.state.tag == ZstdTag::ZstdBlockLiteralsHeader)
            .cloned()
            .collect::<Vec<ZstdWitnessRow<Fr>>>();
        let max_block_idx = witness_rows
            .iter()
            .last()
            .expect("Last row of witness exists.")
            .state
            .block_idx;
        for curr_block_idx in 1..=max_block_idx {
            let byte_idx = literal_header_rows
                .iter()
                .find(|r| r.state.block_idx == curr_block_idx)
                .unwrap()
                .encoded_data
                .byte_idx;

            let literal_bytes = literal_header_rows
                .iter()
                .filter(|&r| r.state.block_idx == curr_block_idx)
                .map(|r| r.encoded_data.value_byte as u64)
                .collect::<Vec<u64>>();

            literal_headers.push((
                curr_block_idx,
                byte_idx,
                (
                    literal_bytes[0],
                    if literal_bytes.len() > 1 {
                        literal_bytes[1]
                    } else {
                        0
                    },
                    if literal_bytes.len() > 2 {
                        literal_bytes[2]
                    } else {
                        0
                    },
                ),
            ));
        }

        #[cfg(feature = "soundness-tests")]
        let (assigned_literals_header_table_rows, assigned_padding_cells) = config
            .literals_header_table
            .assign(&mut layouter, literal_headers, n_enabled)?;

        #[cfg(not(feature = "soundness-tests"))]
        let _ = config
            .literals_header_table
            .assign(&mut layouter, literal_headers, n_enabled)?;

        // Modify assigned witness values
        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        layouter.assign_region(
            || "TestLiteralsHeaderCircuit: potentially unsound assignments",
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

                let mut rng = rand::thread_rng();

                #[cfg(feature = "soundness-tests")]
                match self.case {
                    // sound case
                    UnsoundCase::None => {}

                    // First block index is not 1
                    UnsoundCase::IncorrectInitialBlockIdx => {
                        let block_idx_cell = assigned_literals_header_table_rows[0]
                            .clone()
                            .block_idx
                            .expect("cell is assigned")
                            .cell();
                        let _modified_cell = region.assign_advice(
                            || "Change the first block index value",
                            block_idx_cell
                                .column
                                .try_into()
                                .expect("assigned cell col is valid"),
                            block_idx_cell.row_offset,
                            || Value::known(Fr::from(2)),
                        )?;
                    }

                    // Block index should increment by 1 with each valid row
                    UnsoundCase::IncorrectBlockIdxTransition => {
                        let row_idx: usize =
                            rng.gen_range(0..assigned_literals_header_table_rows.len());
                        let block_idx_cell = assigned_literals_header_table_rows[row_idx]
                            .clone()
                            .block_idx
                            .expect("cell is assigned");
                        let _modified_cell = region.assign_advice(
                            || "Corrupt the block index value at a random location",
                            block_idx_cell
                                .cell()
                                .column
                                .try_into()
                                .expect("assigned cell col is valid"),
                            block_idx_cell.cell().row_offset,
                            || block_idx_cell.value() + Value::known(Fr::one()),
                        )?;
                    }

                    // Padding indicator transitions from 1 -> 0
                    UnsoundCase::IrregularPaddingTransition => {
                        let row_idx: usize = rng.gen_range(0..assigned_padding_cells.len());
                        let is_padding_cell = assigned_padding_cells[row_idx].clone();

                        let _modified_cell = region.assign_advice(
                            || "Flip is_padding value in the padding section",
                            is_padding_cell
                                .cell()
                                .column
                                .try_into()
                                .expect("assigned cell col is valid"),
                            is_padding_cell.cell().row_offset,
                            || Value::known(Fr::zero()),
                        )?;
                    }

                    // Regen size is not calculated correctly
                    UnsoundCase::IncorrectRegenSize => {
                        let row_idx: usize =
                            rng.gen_range(0..assigned_literals_header_table_rows.len());
                        let regen_size_cell = assigned_literals_header_table_rows[row_idx]
                            .clone()
                            .regen_size
                            .expect("cell is assigned");

                        let _modified_cell = region.assign_advice(
                            || "Invalidate the regen_size value at a random location",
                            regen_size_cell
                                .cell()
                                .column
                                .try_into()
                                .expect("assigned cell col is valid"),
                            regen_size_cell.cell().row_offset,
                            || regen_size_cell.value() + Value::known(Fr::one()),
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}

enum UnsoundCase {
    /// sound case.
    None,
    /// First block index is not 1
    IncorrectInitialBlockIdx,
    /// Block index should increment by 1 with each valid row
    IncorrectBlockIdxTransition,
    /// Padding indicator transitions from 1 -> 0
    IrregularPaddingTransition,
    /// Regen size is not calculated correctly
    IncorrectRegenSize,
}

impl Default for UnsoundCase {
    fn default() -> Self {
        Self::None
    }
}

fn run(case: UnsoundCase) -> Result<(), Vec<VerifyFailure>> {
    let mut batch_files = fs::read_dir("./data/test_blobs/multi")
        .expect("batch data dir exits")
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<Vec<_>, std::io::Error>>()
        .expect("batch files handle successfully");
    batch_files.sort();

    let mut multi_batch_data = Vec::with_capacity(500_000);

    for batch_file in batch_files {
        let batch_data = fs::read(batch_file).expect("batch file reads successfully");
        multi_batch_data.extend_from_slice(&batch_data);
    }

    let encoded_multi_batch_data = {
        // compression level = 0 defaults to using level=3, which is zstd's default.
        let mut encoder = init_zstd_encoder(None);

        // set source length, which will be reflected in the frame header.
        encoder
            .set_pledged_src_size(Some(multi_batch_data.len() as u64))
            .expect("Encoder src_size: raw.len()");

        encoder
            .write_all(&multi_batch_data)
            .expect("Encoder wirte_all");
        encoder.finish().expect("Encoder success")
    };

    println!("len(multi_batch_data)={:?}", multi_batch_data.len());
    println!(
        "len(encoded_multi_batch_data)={:?}",
        encoded_multi_batch_data.len()
    );

    let k = 18;

    let test_circuit = TestLiteralsHeaderCircuit {
        k,
        compressed: encoded_multi_batch_data,
        case,
    };

    let prover =
        MockProver::run(k, &test_circuit, vec![]).expect("unexpected failure: MockProver::run");
    prover.verify_par()
}

#[test]
fn test_literals_header_ok() {
    assert!(run(UnsoundCase::None).is_ok())
}

#[test]
fn test_incorrect_initial_block_idx() {
    assert!(run(UnsoundCase::IncorrectInitialBlockIdx).is_err())
}

#[test]
fn test_incorrect_block_idx_transition() {
    assert!(run(UnsoundCase::IncorrectBlockIdxTransition).is_err())
}

#[test]
fn test_irregular_padding_transition() {
    assert!(run(UnsoundCase::IrregularPaddingTransition).is_err())
}

#[test]
fn test_incorrect_regen_size() {
    assert!(run(UnsoundCase::IncorrectRegenSize).is_err())
}
