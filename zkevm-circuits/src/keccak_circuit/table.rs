use super::param::*;
use super::util::*;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Error, TableColumn},
};
use itertools::Itertools;

/// Loads a normalization table with the given parameters and KECCAK_DEGREE.
pub(crate) fn load_normalize_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    name: &str,
    tables: &[TableColumn; 2],
    range: u64,
) -> Result<(), Error> {
    let log_height = get_degree();
    load_normalize_table_impl(layouter, name, tables, range, log_height)
}

// Implementation of the above without environment dependency.
fn load_normalize_table_impl<F: Field>(
    layouter: &mut impl Layouter<F>,
    name: &str,
    tables: &[TableColumn; 2],
    range: u64,
    log_height: usize,
) -> Result<(), Error> {
    assert!(range <= BIT_SIZE as u64);
    let part_size = get_num_bits_per_lookup_impl(range as usize, log_height);
    layouter.assign_table(
        || format!("{} table", name),
        |mut table| {
            // Iterate over all combinations of parts, each taking values in the range.
            for (offset, perm) in (0..part_size)
                .map(|_| 0u64..range)
                .multi_cartesian_product()
                .enumerate()
            {
                let mut input = 0u64;
                let mut output = 0u64;
                let mut factor = 1u64;
                for input_part in perm.iter() {
                    input += input_part * factor;
                    output += (input_part & 1) * factor;
                    factor *= BIT_SIZE as u64;
                }
                table.assign_cell(
                    || format!("{} input", name),
                    tables[0],
                    offset,
                    || Value::known(F::from(input)),
                )?;
                table.assign_cell(
                    || format!("{} output", name),
                    tables[1],
                    offset,
                    || Value::known(F::from(output)),
                )?;
            }
            Ok(())
        },
    )
}

/// Loads the byte packing table
pub(crate) fn load_pack_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    tables: &[TableColumn; 2],
) -> Result<(), Error> {
    layouter.assign_table(
        || "pack table",
        |mut table| {
            for (offset, idx) in (0u64..256).enumerate() {
                table.assign_cell(
                    || "unpacked",
                    tables[0],
                    offset,
                    || Value::known(F::from(idx)),
                )?;
                let packed: F = pack(&into_bits(&[idx as u8]));
                table.assign_cell(|| "packed", tables[1], offset, || Value::known(packed))?;
            }
            Ok(())
        },
    )
}

/// Loads a lookup table
pub(crate) fn load_lookup_table<F: Field>(
    layouter: &mut impl Layouter<F>,
    name: &str,
    tables: &[TableColumn; 2],
    part_size: usize,
    lookup_table: &[u8],
) -> Result<(), Error> {
    layouter.assign_table(
        || format!("{} table", name),
        |mut table| {
            for (offset, perm) in (0..part_size)
                .map(|_| 0..lookup_table.len() as u64)
                .multi_cartesian_product()
                .enumerate()
            {
                let mut input = 0u64;
                let mut output = 0u64;
                let mut factor = 1u64;
                for input_part in perm.iter() {
                    input += input_part * factor;
                    output += (lookup_table[*input_part as usize] as u64) * factor;
                    factor *= BIT_SIZE as u64;
                }
                table.assign_cell(
                    || format!("{} input", name),
                    tables[0],
                    offset,
                    || Value::known(F::from(input)),
                )?;
                table.assign_cell(
                    || format!("{} output", name),
                    tables[1],
                    offset,
                    || Value::known(F::from(output)),
                )?;
            }
            Ok(())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_proofs::dev::{CellValue, MockProver};
    use halo2_proofs::halo2curves::bn256::Fr as F;
    use halo2_proofs::plonk::{Circuit, ConstraintSystem};
    use itertools::Itertools;
    use std::iter::zip;

    #[test]
    fn normalize_table() {
        normalize_table_impl(3, 10);
        normalize_table_impl(4, 10);
        normalize_table_impl(6, 10);
        normalize_table_impl(6, 19);
    }

    fn normalize_table_impl(range: usize, log_height: usize) {
        let table = build_table(&TableTestCircuit {
            range,
            log_height,
            normalize_else_chi: true,
        });

        // On all rows, all inputs/outputs are correct, i.e. they have the same low bit.
        assert_eq!(BIT_COUNT, 3, "this test assumes BIT_COUNT=3");
        for (inp, out) in table.iter() {
            for pos in (0..64).step_by(BIT_COUNT) {
                assert_eq!((inp >> pos) & 1, (out >> pos) & 0b111);
            }
        }
    }

    #[test]
    fn chi_table() {
        // Check the base pattern for all combinations of bits.
        for i in 0..16_usize {
            let (a, b, c, d) = (i & 1, (i >> 1) & 1, (i >> 2) & 1, (i >> 3) & 1);
            assert_eq!(
                CHI_BASE_LOOKUP_TABLE[3 - 2 * a + b - c],
                (a ^ ((!b) & c)) as u8
            );
            assert_eq!(
                CHI_EXT_LOOKUP_TABLE[5 - 2 * a - b + c - 2 * d],
                (a ^ ((!b) & c) ^ d) as u8
            );
        }

        // Check the table with multiple parts per row.
        chi_table_impl(10);
        chi_table_impl(19);
    }

    fn chi_table_impl(log_height: usize) {
        let range = 5; // CHI_BASE_LOOKUP_RANGE
        let table = build_table(&TableTestCircuit {
            range,
            log_height,
            normalize_else_chi: false,
        });

        // On all rows, all input/output pairs match the base table.
        for (inp, out) in table.iter() {
            for pos in (0..64).step_by(BIT_COUNT) {
                let inp = ((inp >> pos) & 7) as usize;
                let out = ((out >> pos) & 7) as u8;
                assert_eq!(out, CHI_BASE_LOOKUP_TABLE[inp]);
            }
        }
    }

    // ---- Helpers ----

    fn build_table(circuit: &TableTestCircuit) -> Vec<(u64, u64)> {
        let prover = MockProver::<F>::run(circuit.log_height as u32, circuit, vec![]).unwrap();

        let columns = prover.fixed();
        assert_eq!(columns.len(), 2);
        let unused_rows = 6; // What MockProver uses on this test circuit.
        let used_rows = (1 << circuit.log_height) - unused_rows;

        // Check the unused rows.
        for io in zip(&columns[0], &columns[1]).skip(used_rows) {
            assert_eq!(io, (&CellValue::Unassigned, &CellValue::Unassigned));
        }

        // Get the generated lookup table with the form: table[row] = (input, output).
        let table = zip(&columns[0], &columns[1])
            .take(used_rows)
            .map(|(inp, out)| (unwrap_u64(inp), unwrap_u64(out)))
            .collect::<Vec<_>>();

        // All possible combinations of inputs are there.
        let unique_rows = table.iter().unique().count();
        assert_eq!(unique_rows, circuit.expected_num_entries());

        table
    }

    #[derive(Clone)]
    struct TableTestCircuit {
        range: usize,
        log_height: usize,
        normalize_else_chi: bool,
    }

    impl TableTestCircuit {
        fn expected_num_entries(&self) -> usize {
            let num_bits = get_num_bits_per_lookup_impl(self.range, self.log_height);
            self.range.pow(num_bits as u32)
        }
    }

    impl Circuit<F> for TableTestCircuit {
        type Config = [TableColumn; 2];
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            self.clone()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            array_init::array_init(|_| meta.lookup_table_column())
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            if self.normalize_else_chi {
                load_normalize_table_impl(
                    &mut layouter,
                    "normalize",
                    &config,
                    self.range as u64,
                    self.log_height,
                )?;
            } else {
                let num_bits = get_num_bits_per_lookup_impl(self.range, self.log_height);
                load_lookup_table(
                    &mut layouter,
                    "chi base",
                    &config,
                    num_bits,
                    &CHI_BASE_LOOKUP_TABLE,
                )?;
            }
            Ok(())
        }
    }

    fn unwrap_u64<F: Field>(cv: &CellValue<F>) -> u64 {
        match *cv {
            CellValue::Assigned(f) => {
                let f = f.get_lower_128();
                assert_eq!(f >> 64, 0);
                f as u64
            }
            _ => panic!("the cell should be assigned"),
        }
    }
}
