use crate::{
    aggregation::decoder::tables::BitstringTable,
    witgen::{init_zstd_encoder, process, MultiBlockProcessResult, N_BLOCK_SIZE_TARGET},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
    plonk::{Circuit, Column, ConstraintSystem, Error, Fixed},
};
use rand::Rng;
use std::io::Write;
use zkevm_circuits::table::RangeTable;

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

        let MultiBlockProcessResult {
            witness_rows,
            literal_bytes: _l,
            fse_aux_tables: _f,
            block_info_arr,
            sequence_info_arr: _s,
            address_table_rows: _a,
            sequence_exec_results: _seq,
        } = process(&self.compressed, Value::known(Fr::from(12345)));

        config.range_block_len.load(&mut layouter)?;

        let assigned_bitstring_table_1_rows = config.bitstring_table_1.assign(
            &mut layouter,
            &block_info_arr,
            &witness_rows,
            n_enabled,
        )?;
        let table_1_padding_start_offset = assigned_bitstring_table_1_rows
            .iter()
            .position(|row| row.bit.is_none())
            .expect("table within capacity");

        let assigned_bitstring_table_2_rows = config.bitstring_table_2.assign(
            &mut layouter,
            &block_info_arr,
            &witness_rows,
            n_enabled,
        )?;
        let table_2_padding_start_offset = assigned_bitstring_table_2_rows
            .iter()
            .position(|row| row.bit.is_none())
            .expect("table within capacity");

        let assigned_bitstring_table_3_rows = config.bitstring_table_3.assign(
            &mut layouter,
            &block_info_arr,
            &witness_rows,
            n_enabled,
        )?;
        let table_3_padding_start_offset = assigned_bitstring_table_3_rows
            .iter()
            .position(|row| row.bit.is_none())
            .expect("table within capacity");

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

                let mut rng = rand::thread_rng();

                match self.case {
                    // sound case
                    UnsoundCase::None => {},

                    // bits are not the correct representation of byte_1/byte_2/byte_3
                    UnsoundCase::IncorrectBitDecomposition => {
                        for (assigned_rows, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, table_3_padding_start_offset),
                        ] {
                            // Note: For some input data, especially for BitstringTable<3>, 
                            // the assigned rows will be all padding as there were no 3-byte read operations performed during decoding.
                            if padding_start_offset > 0 {
                                let row_idx: usize = rng.gen_range(0..padding_start_offset);
                                let bit_cell = assigned_rows[row_idx].bit.clone().expect("cell is assigned");
                                let bit_value = assigned_rows[row_idx].bit_f.expect("bit value exits");

                                region.assign_advice(
                                    || "corrupt bit decomposition at a random location in the assigned witness",
                                    bit_cell.cell().column.try_into().expect("assigned cell col is valid"),
                                    bit_cell.cell().row_offset,
                                    || if bit_value > Fr::zero() {
                                        Value::known(Fr::zero())
                                    } else {
                                        Value::known(Fr::one())
                                    },
                                )?;
                            }
                        }
                    },

                    // bits are not the correct representation of byte_1/byte_2/byte_3 due to incorrect endianness (wrong is_reverse)
                    UnsoundCase::IncorrectBitDecompositionEndianness => {
                        for (assigned_rows, end_idx, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, 7, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, 15, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, 23, table_3_padding_start_offset),
                        ] {
                            if padding_start_offset > 0 {
                                // Sample the first index of a multi-byte operation
                                let row_idx = (rng.gen_range(0..(padding_start_offset/(end_idx + 1))) - 1) * (end_idx + 1);
                                let is_reverse = assigned_rows[row_idx].is_reverse.clone().expect("cell is assigned");
                                let is_reverse_f = assigned_rows[row_idx].is_reverse_f.expect("is_reverse value exists");

                                for bit_idx in 0..end_idx {
                                    region.assign_advice(
                                        || "inject incorrect is_reverse to a read operation",
                                        is_reverse.cell().column.try_into().expect("assigned cell col is valid"),
                                        row_idx + bit_idx,
                                        || if is_reverse_f > Fr::zero() {
                                            Value::known(Fr::zero())
                                        } else {
                                            Value::known(Fr::one())
                                        },
                                    )?;
                                }
                            }
                        }
                    },

                    // byte_idx_1/2/3 delta value is not boolean
                    UnsoundCase::IrregularTransitionByteIdx => {
                        for (assigned_rows, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, table_3_padding_start_offset),
                        ] {
                            if padding_start_offset > 0 {
                                let row_idx: usize = rng.gen_range(0..padding_start_offset);
                                let byte_idx_1_cell = assigned_rows[row_idx].byte_idx_1.clone().expect("cell is assigned");
                                let _byte_idx_2_cell = assigned_rows[row_idx].byte_idx_2.clone().expect("cell is assigned");
                                let byte_idx_3_cell = assigned_rows[row_idx].byte_idx_3.clone().expect("cell is assigned");

                                region.assign_advice(
                                    || "corrupt byte_idx at a random location in the assigned witness (+1 for byte_idx_1)",
                                    byte_idx_1_cell.cell().column.try_into().expect("assigned cell col is valid"),
                                    byte_idx_1_cell.cell().row_offset,
                                    || byte_idx_1_cell.value() + Value::known(Fr::one()),
                                )?;
                                region.assign_advice(
                                    || "corrupt byte_idx at a random location in the assigned witness",
                                    byte_idx_3_cell.cell().column.try_into().expect("assigned cell col is valid"),
                                    byte_idx_3_cell.cell().row_offset,
                                    || byte_idx_3_cell.value() + Value::known(Fr::one()),
                                )?;
                            }
                        }
                    },

                    // The boolean from_start does not start at bit_idx = 0
                    UnsoundCase::IrregularValueFromStart => {
                        for (assigned_rows, end_idx, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, 7, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, 15, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, 23, table_3_padding_start_offset),
                        ] {
                            if padding_start_offset > 0 {
                                // Sample the first index of a multi-byte operation
                                let read_idx: usize = (rng.gen_range(0..(padding_start_offset/(end_idx + 1))) - 1) * (end_idx + 1);
                                let from_start = assigned_rows[read_idx].from_start.clone().expect("cell is assigned");

                                region.assign_advice(
                                    || "Make from_start at bit_index=0 zero",
                                    from_start.cell().column.try_into().expect("assigned cell col is valid"),
                                    read_idx,
                                    || Value::known(Fr::zero()),
                                )?;
                            }
                        }
                    },

                    // The boolean until_end does not end at bit_idx = 7/15/23
                    UnsoundCase::IrregularValueUntilEnd => {
                        for (assigned_rows, end_idx, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, 7, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, 15, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, 23, table_3_padding_start_offset),
                        ] {
                            if padding_start_offset > 0 {
                                // Sample the first index of a multi-byte operation
                                let read_idx: usize = (rng.gen_range(0..(padding_start_offset/(end_idx + 1))) - 1) * (end_idx + 1);
                                let until_end = assigned_rows[read_idx + end_idx].until_end.clone().expect("cell is assigned");

                                region.assign_advice(
                                    || "Make until_end at bit_index=end_index zero",
                                    until_end.cell().column.try_into().expect("assigned cell col is valid"),
                                    read_idx + end_idx,
                                    || Value::known(Fr::zero()),
                                )?;
                            }
                        }
                    },

                    // The boolean from_start flips from 0 -> 1
                    UnsoundCase::IrregularTransitionFromStart => {
                        for (assigned_rows, end_idx, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, 7, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, 15, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, 23, table_3_padding_start_offset),
                        ] {
                            if padding_start_offset > 0 {
                                // Sample the first index of a multi-byte operation
                                let read_idx: usize = (rng.gen_range(0..(padding_start_offset/(end_idx + 1))) - 1) * (end_idx + 1);
                                let from_start = assigned_rows[read_idx + end_idx].from_start.clone().expect("cell is assigned");

                                region.assign_advice(
                                    || "Make from_start at bit_index=end_index one",
                                    from_start.cell().column.try_into().expect("assigned cell col is valid"),
                                    read_idx + end_idx,
                                    || Value::known(Fr::one()),
                                )?;
                            }
                        }
                    },

                    // The boolean until_end flips from 1 -> 0
                    UnsoundCase::IrregularTransitionUntilEnd => {
                        for (assigned_rows, end_idx, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, 7, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, 15, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, 23, table_3_padding_start_offset),
                        ] {
                            if padding_start_offset > 0 {
                                // Sample the first index of a multi-byte operation
                                let read_idx: usize = (rng.gen_range(0..(padding_start_offset/(end_idx + 1))) - 1) * (end_idx + 1);
                                let until_end = assigned_rows[read_idx + end_idx].until_end.clone().expect("cell is assigned");

                                region.assign_advice(
                                    || "Make until_end at bit_index=end_index zero",
                                    until_end.cell().column.try_into().expect("assigned cell col is valid"),
                                    read_idx + end_idx,
                                    || Value::known(Fr::zero()),
                                )?;
                            }
                        }
                    },

                    // The bitstring_value is not constant for a bitstring
                    UnsoundCase::InconsistentBitstringValue => {
                        for (assigned_rows, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, table_3_padding_start_offset),
                        ] {
                            if padding_start_offset > 0 {
                                let row_idx: usize = rng.gen_range(0..padding_start_offset);
                                let bitstring_value_cell = assigned_rows[row_idx].bitstring_value.clone().expect("cell is assigned");

                                region.assign_advice(
                                    || "corrupt bitstring_value at a random location in the assigned witness",
                                    bitstring_value_cell.cell().column.try_into().expect("assigned cell col is valid"),
                                    bitstring_value_cell.cell().row_offset,
                                    || bitstring_value_cell.value() + Value::known(Fr::one()),
                                )?;
                            }
                        }
                    },

                    // The bitstring_value and bitstring_value_acc do not agree at the last set bit
                    UnsoundCase::InconsistentEndBitstringAccValue => {
                        for (assigned_rows, end_idx, padding_start_offset) in [
                            (&assigned_bitstring_table_1_rows, 7, table_1_padding_start_offset),
                            (&assigned_bitstring_table_2_rows, 15, table_2_padding_start_offset),
                            (&assigned_bitstring_table_3_rows, 23, table_3_padding_start_offset),
                        ] {
                            if padding_start_offset > 0 {
                                // Sample the first index of a multi-byte operation
                                let read_idx: usize = (rng.gen_range(0..(padding_start_offset/(end_idx + 1))) - 1) * (end_idx + 1);
                                let bitstring_value_acc = assigned_rows[read_idx + end_idx].bitstring_value_acc.clone().expect("cell is assigned");

                                region.assign_advice(
                                    || "Make end bitstring_value_acc value different at bit_index=end_index",
                                    bitstring_value_acc.cell().column.try_into().expect("assigned cell col is valid"),
                                    read_idx + end_idx,
                                    || bitstring_value_acc.value() + Value::known(Fr::one()),
                                )?;
                            }
                        }
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
    /// bits are not the correct representation of byte_1/byte_2/byte_3 due to incorrect endianness
    /// (wrong is_reverse)
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

fn run(case: UnsoundCase) -> Result<(), Vec<VerifyFailure>> {
    let k = 18;

    // Batch 127
    let raw = hex::decode("00000073f8718302d9848422551000827b0c94f565295eddcc0682bb16376c742e9bc9dbb32512880429d069189e01fd8083104ec3a02b10f9f3bbaa927b805b9b225f04d90a9994da49f309fb1e029312c661ffb68ea065de06a6d34dadf1af4f80d9133a67cf7753c925f5bfd785f56c20c11280ede0000000aef8ac10841c9c38008305d0a594ec53c830f4444a8a56455c6836b5d2aa794289aa80b844f2b9fdb8000000000000000000000000b6966083c7b68175b4bf77511608aee9a80d2ca4000000000000000000000000000000000000000000000000003d83508c36cdb583104ec4a0203dff6f72962bb8aa5a9bc365c705818ad2ae51485a8c831e453668d4b75d1fa03de15a7b705a8ad59f8437b4ca717f1e8094c77c5459ee57b0cae8b6c4ebdf5e000002d7f902d402841c9c38008302c4589480e38291e06339d10aab483c65695d004dbd5c69870334ae29914c90b902642cc4081e000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000001e9dd10000000000000000000000000000000000000000000000000000000065b3f7550000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000334ae29914c9000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000814a23b053fd0f102aeeda0459215c2444799c700000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000530000000000000000000000000000000000000400000000000000000000000097af7be0b94399f9dd54a984e8498ce38356f0380000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000083104ec3a039a8970ba5ef7fb1cfe8d5db8e293b9837e298fd55faab853f56b66322c8ef80a0523ceb389a544389f6775b8ff982feac3f05b092869e35fed509e828d5e5759900000170f9016d03841c9c38008302a98f9418b71386418a9fca5ae7165e31c385a5130011b680b9010418cbafe5000000000000000000000000000000000000000000000000000000000091855b000000000000000000000000000000000000000000000000000e9f352b7fc38100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000006fd71e5088bdaaed42efd384fede02a76dca87f00000000000000000000000000000000000000000000000000000000065b3cd55000000000000000000000000000000000000000000000000000000000000000200000000000000000000000006efdbff2a14a7c8e15944d1f4a48f9f95f663a4000000000000000000000000530000000000000000000000000000000000000483104ec4a097411c6aad88135b8918b29d318898808fc04e933379c6d5da9f267315af2300a0265e6b38e475244e2639ea6eb42ae0d7f4f227a9dd9dd5328744bcd9f5f25bd2000000aff8ad82077a841c9c3800826716940a88bc5c32b684d467b43c06d9e0899efeaf59df86d12f0c4c832ab83e646174613a2c7b2270223a226c61796572322d3230222c226f70223a22636c61696d222c227469636b223a22244c32222c22616d74223a2231303030227d83104ec3a0bef600f17b5037519044f2296d1181abf140b986a7d43b7472e93b6be8378848a03c951790ad335a2d1947b3913e2280e506b17463c5f3b61849595a94b37439b3").expect("Decoding hex data should not fail");

    let compressed = {
        // compression level = 0 defaults to using level=3, which is zstd's default.
        let mut encoder = init_zstd_encoder(None);

        // set source length, which will be reflected in the frame header.
        encoder
            .set_pledged_src_size(Some(raw.len() as u64))
            .expect("Encoder src_size: raw.len()");
        // include the content size to know at decode time the expected size of decoded data.

        encoder.write_all(&raw).expect("Encoder write_all");
        encoder.finish().expect("Encoder success")
    };

    let test_circuit = TestBitstringCircuit {
        k,
        compressed,
        case,
    };

    let prover =
        MockProver::run(k, &test_circuit, vec![]).expect("unexpected failure: MockProver::run");

    prover.verify_par()
}

#[test]
fn test_bitstring_ok() {
    assert!(run(UnsoundCase::None).is_ok())
}

#[test]
fn test_incorrect_bit_decomposition() {
    assert!(run(UnsoundCase::IncorrectBitDecomposition).is_err())
}

#[test]
fn test_incorrect_bit_decomposition_endianness() {
    assert!(run(UnsoundCase::IncorrectBitDecompositionEndianness).is_err())
}

#[test]
fn test_irregular_transition_byte_idx() {
    assert!(run(UnsoundCase::IrregularTransitionByteIdx).is_err())
}

#[test]
fn test_irregular_value_from_start() {
    assert!(run(UnsoundCase::IrregularValueFromStart).is_err())
}

#[test]
fn test_irregular_value_until_end() {
    assert!(run(UnsoundCase::IrregularValueUntilEnd).is_err())
}

#[test]
fn test_irregular_transition_from_start() {
    assert!(run(UnsoundCase::IrregularTransitionFromStart).is_err())
}

#[test]
fn test_irregular_transition_until_end() {
    assert!(run(UnsoundCase::IrregularTransitionUntilEnd).is_err())
}

#[test]
fn test_inconsistent_bitstring_value() {
    assert!(run(UnsoundCase::InconsistentBitstringValue).is_err())
}

#[test]
fn test_inconsistent_end_bitstring_acc_value() {
    assert!(run(UnsoundCase::InconsistentEndBitstringAccValue).is_err())
}
