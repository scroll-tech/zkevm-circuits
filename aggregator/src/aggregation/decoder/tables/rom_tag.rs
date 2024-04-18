use halo2_proofs::{
    circuit::Layouter,
    halo2curves::bn256::Fr,
    plonk::{Any, Column, ConstraintSystem, Error, Fixed},
};
use itertools::Itertools;
use zkevm_circuits::table::LookupTable;

use crate::aggregation::decoder::witgen::RomTagTableRow;

/// Read-only Memory table for the Decompression circuit. This table allows us a lookup argument
/// from the Decompression circuit to check if a given row can occur depending on the row's tag,
/// next tag and tag length.
#[derive(Clone, Copy, Debug)]
pub struct RomTagTable {
    /// Tag of the current field being decoded.
    pub tag: Column<Fixed>,
    /// Tag of the following field when the current field is finished decoding.
    pub tag_next: Column<Fixed>,
    /// The maximum length in terms of number of bytes that the current tag can take up.
    pub max_len: Column<Fixed>,
    /// Whether this tag outputs a decoded byte or not.
    pub is_output: Column<Fixed>,
    /// Whether this tag is processed back-to-front, i.e. in reverse order.
    pub is_reverse: Column<Fixed>,
    /// Whether this tag belongs to a ``block`` in zstd or not.
    pub is_block: Column<Fixed>,
}

impl LookupTable<Fr> for RomTagTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.tag.into(),
            self.tag_next.into(),
            self.max_len.into(),
            self.is_output.into(),
            self.is_reverse.into(),
            self.is_block.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag"),
            String::from("tag_next"),
            String::from("max_len"),
            String::from("is_output"),
            String::from("is_reverse"),
            String::from("is_block"),
        ]
    }
}

impl RomTagTable {
    /// Construct the Tag ROM table.
    pub fn construct(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            tag: meta.fixed_column(),
            tag_next: meta.fixed_column(),
            max_len: meta.fixed_column(),
            is_output: meta.fixed_column(),
            is_reverse: meta.fixed_column(),
            is_block: meta.fixed_column(),
        }
    }

    /// Load the Tag ROM table.
    pub fn load(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || "(ROM): Zstd tag table",
            |mut region| {
                for (offset, row) in RomTagTableRow::rows().iter().enumerate() {
                    for (&column, (value, annotation)) in
                        <Self as LookupTable<Fr>>::fixed_columns(self).iter().zip(
                            row.values::<Fr>()
                                .into_iter()
                                .zip_eq(<Self as LookupTable<Fr>>::annotations(self).iter()),
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
