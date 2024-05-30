use std::collections::BTreeMap;

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
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
struct TestBitstringConfig {
    /// Fixed column to mark all enabled rows.
    q_enable: Column<Fixed>,
    /// Range table for [0, 128kb).
    range_block_len: RangeTable<{ N_BLOCK_SIZE_TARGET as usize }>,
    /// Helper table for decoding bitstreams that span over 1 byte.
    bitstring_table_1: BitstringTable<1>,
    /// Helper table for decoding bitstreams that span over 2 bytes.
    bitstring_table_2: BitstringTable<2>,
    /// Helper table for decoding bitstreams that span over 3 bytes.
    bitstring_table_3: BitstringTable<3>,
}

impl TestBitstringConfig {
    fn unusable_rows() -> usize {
        64
    }
}

#[derive(Default)]
struct TestBitstringCircuit {
    /// Degree for the test circuit, i.e. 1 << k number of rows.
    k: u32,
    /// Compressed bytes
    compressed: Vec<u8>,
    /// Variant of possible unsound case.
    case: UnsoundCase,
}

impl Circuit<Fr> for TestBitstringCircuit {
    type Config = TestBitstringConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let q_enable = meta.fixed_column();
        let range_block_len = RangeTable::construct(meta);
        let bitstring_table_1 = BitstringTable::configure(meta, q_enable, range_block_len);
        let bitstring_table_2 = BitstringTable::configure(meta, q_enable, range_block_len);
        let bitstring_table_3 = BitstringTable::configure(meta, q_enable, range_block_len);
        
        Self::Config {
            q_enable,
            range_block_len,
            bitstring_table_1,
            bitstring_table_2,
            bitstring_table_3,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let n_enabled = (1 << self.k) - Self::Config::unusable_rows();
        let challenges = challenge.values(&layouter);

        let MultiBlockProcessResult {
            witness_rows,
            literal_bytes: decoded_literals,
            fse_aux_tables,
            block_info_arr,
            sequence_info_arr,
            address_table_rows: address_table_arr,
            sequence_exec_results,
        } = process(&self.compressed, challenges.keccak_input());

        self.range_block_len.load(layouter)?;

        let assigned_bitstring_table_1_rows = config.bitstring_table_1
            .assign(layouter, &block_info_arr, &witness_rows, n_enabled)?;
        let assigned_bitstring_table_2_rows = config.bitstring_table_2
            .assign(layouter, &block_info_arr, &witness_rows, n_enabled)?;
        let assigned_bitstring_table_3_rows = config.bitstring_table_3
            .assign(layouter, &block_info_arr, &witness_rows, n_enabled)?;

        let mut first_pass = halo2_base::SKIP_FIRST_PASS;
        layouter.assign_region(
            || "TestBitstringCircuit: potentially unsound assignments",
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

                // let (fse_rows, _fse_sorted_rows) =
                //     config
                //         .fse_table
                //         .assign(&mut layouter, &self.data, n_enabled)?;

                match self.case {
                    UnsoundCase::None => {}
                    // UnsoundCase::MismatchNumStates => {
                    //     // The last row represents the last "un-padded" row, i.e. the idx is
                    //     // expected to be table_size.
                    //     let idx_cell = &fse_rows.last().expect("len(fse_rows)=0").idx;
                    //     increment_cell(&mut region, idx_cell)?;
                    // }
                    IncorrectBitDecomposition => {

                    },
                    IncorrectBitDecompositionEndianness => {

                    },
                    IrregularTransitionByteIdx => {

                    },
                    IrregularValueFromStart => {

                    },
                    IrregularValueUntilEnd => {

                    },
                    IrregularTransitionFromStart => {

                    },
                    IrregularTransitionUntilEnd => {

                    },
                    InconsistentBitstringValue => {

                    },
                    InconsistentEndBitstringAccValue => {

                    },
                }

                Ok(())
            },
        )
    }
}

enum UnsoundCase {
    /// sound case.
    None,
    /// bits are not the correct representation of byte_1/byte_2/byte_3
    IncorrectBitDecomposition,
    /// bits are not the correct representation of byte_1/byte_2/byte_3 due to incorrect endianness (wrong is_reverse)
    IncorrectBitDecompositionEndianness,
    /// byte_idx_1/2/3 delta value is not boolean
    IrregularTransitionByteIdx,
    /// The boolean from_start does not start at bit_idx = 0
    IrregularValueFromStart,
    /// The boolean until_end does not end at bit_idx = 7/15/23
    IrregularValueUntilEnd,
    /// The boolean from_start flips from 0 -> 1
    IrregularTransitionFromStart,
    /// The boolean until_end flips from 1 -> 0
    IrregularTransitionUntilEnd,
    /// The bitstring_value is not constant for a bitstring
    InconsistentBitstringValue,
    /// The bitstring_value and bitstring_value_acc do not agree at the last set bit
    InconsistentEndBitstringAccValue,
}

impl Default for UnsoundCase {
    fn default() -> Self {
        Self::None
    }
}

// fn increment_cell(
//     region: &mut Region<Fr>,
//     assigned_cell: &AssignedCell<Fr, Fr>,
// ) -> Result<AssignedCell<Fr, Fr>, Error> {
//     let cell = assigned_cell.cell();
//     region.assign_advice(
//         || "incrementing previously assigned cell",
//         cell.column.try_into().expect("assigned cell not advice"),
//         cell.row_offset,
//         || assigned_cell.value() + Value::known(Fr::one()),
//     )
// }

// fn run(input: DataInput, is_predefined: bool, case: UnsoundCase) -> Result<(), Vec<VerifyFailure>> {
//     let k = 18;

//     let fse_table = match input {
//         DataInput::Distribution(distribution, accuracy_log) => {
//             let normalised_probs = {
//                 let mut normalised_probs = BTreeMap::new();
//                 for (i, &prob) in distribution.iter().enumerate() {
//                     normalised_probs.insert(i as u64, prob);
//                 }
//                 normalised_probs
//             };
//             let (state_map, sorted_state_map) =
//                 FseAuxiliaryTableData::transform_normalised_probs(&normalised_probs, accuracy_log);
//             FseAuxiliaryTableData {
//                 block_idx: 1,
//                 table_kind: FseTableKind::LLT,
//                 table_size: 1 << accuracy_log,
//                 is_predefined: true,
//                 normalised_probs,
//                 sym_to_states: state_map,
//                 sym_to_sorted_states: sorted_state_map,
//             }
//         }
//         DataInput::SourceBytes(src, byte_offset) => {
//             let (_, _, fse_table) = FseAuxiliaryTableData::reconstruct(
//                 &src,
//                 1,
//                 FseTableKind::LLT,
//                 byte_offset,
//                 is_predefined,
//             )
//             .expect("unexpected failure: FseTable::reconstruct");
//             fse_table
//         }
//     };

//     let test_circuit = TestFseCircuit {
//         k,
//         data: vec![fse_table],
//         case,
//     };

//     let prover =
//         MockProver::run(k, &test_circuit, vec![]).expect("unexpected failure: MockProver::run");
//     prover.verify_par()
// }

// #[test]
// fn test_fse_ok_1() {
//     let distribution = vec![
//         4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1,
//         1, 1, -1, -1, -1, -1,
//     ];
//     assert!(run(
//         DataInput::Distribution(distribution, 6),
//         true,
//         UnsoundCase::None
//     )
//     .is_ok())
// }

// #[test]
// fn test_fse_not_ok_mismatch_num_states() {
//     let src = vec![
//         0x21, 0x9d, 0x51, 0xcc, 0x18, 0x42, 0x44, 0x81, 0x8c, 0x94, 0xb4, 0x50, 0x1e,
//     ];
//     assert!(run(
//         DataInput::SourceBytes(src, 0),
//         false,
//         UnsoundCase::MismatchNumStates
//     )
//     .is_err())
// }
