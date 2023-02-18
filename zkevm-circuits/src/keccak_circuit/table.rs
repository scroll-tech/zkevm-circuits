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
