use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Any, Column, ConstraintSystem, Error, Fixed},
};

use crate::{table::LookupTable, witness::ZstdTag};

/// Read-only Memory table for the Decompression circuit. This table allows us a lookup argument
/// from the Decompression circuit to check if the next tag is correct based on which block type we
/// have encountered in the block header. Block type is denoted by 2 bits in the block header.
#[derive(Clone, Copy, Debug)]
pub struct BlockTypeRomTable {
    /// Current tag.
    tag: Column<Fixed>,
    /// Lower bit.
    lo_bit: Column<Fixed>,
    /// Higher bit.
    hi_bit: Column<Fixed>,
    /// Tag that follows.
    tag_next: Column<Fixed>,
}

impl<F: Field> LookupTable<F> for BlockTypeRomTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.tag.into(),
            self.lo_bit.into(),
            self.hi_bit.into(),
            self.tag_next.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag"),
            String::from("lo_bit"),
            String::from("hi_bit"),
            String::from("tag_next"),
        ]
    }
}

impl BlockTypeRomTable {
    /// Construct the ROM table.
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            tag: meta.fixed_column(),
            lo_bit: meta.fixed_column(),
            hi_bit: meta.fixed_column(),
            tag_next: meta.fixed_column(),
        }
    }

    /// Load the ROM table.
    pub fn load<F: Field>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "Zstd BlockType ROM table",
            |mut region| {
                for (i, &(tag, lo_bit, hi_bit, tag_next)) in [
                    (ZstdTag::BlockHeader, 0, 0, ZstdTag::RawBlockBytes),
                    (ZstdTag::BlockHeader, 0, 1, ZstdTag::RleBlockBytes),
                    (ZstdTag::BlockHeader, 1, 0, ZstdTag::ZstdBlockLiteralsHeader),
                    (
                        ZstdTag::ZstdBlockLiteralsHeader,
                        0,
                        0,
                        ZstdTag::ZstdBlockLiteralsRawBytes,
                    ),
                    (
                        ZstdTag::ZstdBlockLiteralsHeader,
                        0,
                        1,
                        ZstdTag::ZstdBlockLiteralsRleBytes,
                    ),
                    (
                        ZstdTag::ZstdBlockLiteralsHeader,
                        1,
                        0,
                        ZstdTag::ZstdBlockFseCode,
                    ),
                ]
                .iter()
                .enumerate()
                {
                    region.assign_fixed(
                        || "tag",
                        self.tag,
                        i,
                        || Value::known(F::from(tag as u64)),
                    )?;
                    region.assign_fixed(
                        || "lo_bit",
                        self.lo_bit,
                        i,
                        || Value::known(F::from(lo_bit)),
                    )?;
                    region.assign_fixed(
                        || "hi_bit",
                        self.hi_bit,
                        i,
                        || Value::known(F::from(hi_bit)),
                    )?;
                    region.assign_fixed(
                        || "tag_next",
                        self.tag_next,
                        i,
                        || Value::known(F::from(tag_next as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}
