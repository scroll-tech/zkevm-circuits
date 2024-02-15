use eth_types::Field;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Any, Column, ConstraintSystem, Error, Fixed},
};

use crate::{table::LookupTable, witness::TagRomTableRow};

/// Read-only Memory table for the Decompression circuit. This table allows us a lookup argument
/// from the Decompression circuit to check if a given row can occur depending on the row's tag,
/// next tag and tag length.
#[derive(Clone, Copy, Debug)]
pub struct TagRomTable {
    /// Tag of the current field being decoded.
    pub tag: Column<Fixed>,
    /// Tag of the following field when the current field is finished decoding.
    pub tag_next: Column<Fixed>,
    /// The maximum length in terms of number of bytes that the current tag can take up.
    pub max_len: Column<Fixed>,
    /// Whether this tag outputs a decoded byte or not.
    pub is_output: Column<Fixed>,
    /// Whether this tag belongs to a ``block`` in zstd or not.
    pub is_block: Column<Fixed>,
    /// Whether this tag is processed back-to-front, i.e. in reverse order.
    pub is_reverse: Column<Fixed>,
}

impl<F: Field> LookupTable<F> for TagRomTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.tag.into(),
            self.tag_next.into(),
            self.max_len.into(),
            self.is_output.into(),
            self.is_block.into(),
            self.is_reverse.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag"),
            String::from("tag_next"),
            String::from("max_len"),
            String::from("is_output"),
            String::from("is_block"),
            String::from("is_reverse"),
        ]
    }
}

impl TagRomTable {
    /// Construct the ROM table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            tag_next: meta.fixed_column(),
            max_len: meta.fixed_column(),
            is_output: meta.fixed_column(),
            is_block: meta.fixed_column(),
            is_reverse: meta.fixed_column(),
        }
    }

    /// Load the ROM table.
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "Zstd ROM table",
            |mut region| {
                for (offset, row) in TagRomTableRow::rows().iter().enumerate() {
                    for (&column, (value, annotation)) in
                        <Self as LookupTable<F>>::fixed_columns(self).iter().zip(
                            row.values::<F>()
                                .into_iter()
                                .zip(<Self as LookupTable<F>>::annotations(self).iter()),
                        )
                    {
                        region.assign_fixed(
                            || format!("{annotation} at offset={offset}"),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}
