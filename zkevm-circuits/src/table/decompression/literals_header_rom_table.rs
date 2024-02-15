use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Any, Column, ConstraintSystem, Error, Fixed},
};

use crate::table::LookupTable;

/// Read-only memory table for zstd block's literals header.
#[derive(Clone, Copy, Debug)]
pub struct LiteralsHeaderRomTable {
    /// Block type first bit.
    block_type_bit0: Column<Fixed>,
    /// Block type second bit.
    block_type_bit1: Column<Fixed>,
    /// Size format first bit.
    size_format_bit0: Column<Fixed>,
    /// Size format second bit.
    size_format_bit1: Column<Fixed>,
    /// Number of bytes occupied by the literals header.
    n_bytes_header: Column<Fixed>,
    /// Number of literal streams to be decoded.
    n_lstreams: Column<Fixed>,
    /// The branch we take to decompose the literals header. There are a total of 7 branches that
    /// can be used to decompose the literals header, namely:
    ///
    /// - block_type == Raw/RLE and size_format == 00 or 10
    /// - block_type == Raw/RLE and size_format == 01
    /// - block_type == Raw/RLE and size_format == 11
    /// - block_type == Compressed and size_format == 00 or 01
    /// - block_type == Compressed and size_format == 10
    /// - block_type == Compressed and size_format == 11
    branch: Column<Fixed>,
    // size format == 0b11?
    is_size_format_0b11: Column<Fixed>,
}

impl<F: Field> LookupTable<F> for LiteralsHeaderRomTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.block_type_bit0.into(),
            self.block_type_bit1.into(),
            self.size_format_bit0.into(),
            self.size_format_bit1.into(),
            self.n_bytes_header.into(),
            self.n_lstreams.into(),
            self.branch.into(),
            self.is_size_format_0b11.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("block_type_bit0"),
            String::from("block_type_bit1"),
            String::from("size_format_bit0"),
            String::from("size_format_bit1"),
            String::from("n_bytes_header"),
            String::from("n_lstreams"),
            String::from("branch"),
            String::from("is_size_format_0b11"),
        ]
    }
}

impl LiteralsHeaderRomTable {
    /// Construct the ROM table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            block_type_bit0: meta.fixed_column(),
            block_type_bit1: meta.fixed_column(),
            size_format_bit0: meta.fixed_column(),
            size_format_bit1: meta.fixed_column(),
            n_bytes_header: meta.fixed_column(),
            n_lstreams: meta.fixed_column(),
            branch: meta.fixed_column(),
            is_size_format_0b11: meta.fixed_column(),
        }
    }

    /// Load the ROM table.
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "LiteralsHeader ROM table",
            |mut region| {
                // Refer: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#literals_section_header
                for (i, row) in [
                    [0, 0, 0, 0, 1, 0, 0, 0], // Raw: 1 byte header
                    [0, 0, 0, 1, 1, 0, 0, 0], // Raw: 1 byte header
                    [0, 0, 1, 0, 2, 0, 1, 0], // Raw: 2 bytes header
                    [0, 0, 1, 1, 3, 0, 2, 1], // Raw: 3 bytes header
                    [1, 0, 0, 0, 1, 0, 0, 0], // RLE: 1 byte header
                    [1, 0, 0, 1, 1, 0, 0, 0], // RLE: 1 byte header
                    [1, 0, 1, 0, 2, 0, 1, 0], // RLE: 2 bytes header
                    [1, 0, 1, 1, 3, 0, 2, 1], // RLE: 3 bytes header
                    [0, 1, 0, 0, 3, 0, 3, 0], // Compressed: 3 bytes header
                    [0, 1, 1, 0, 3, 1, 3, 0], // Compressed: 3 bytes header
                    [0, 1, 0, 1, 4, 1, 4, 0], // Compressed: 4 bytes header
                    [0, 1, 1, 1, 5, 1, 5, 1], // Compressed: 5 bytes header
                ]
                .iter()
                .enumerate()
                {
                    for (&column, (&value, annotation)) in
                        <Self as LookupTable<F>>::fixed_columns(self).iter().zip(
                            row.iter()
                                .zip(<Self as LookupTable<F>>::annotations(self).iter()),
                        )
                    {
                        region.assign_fixed(
                            || format!("{annotation} at offset={i}"),
                            column,
                            i,
                            || Value::known(F::from(value)),
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}
