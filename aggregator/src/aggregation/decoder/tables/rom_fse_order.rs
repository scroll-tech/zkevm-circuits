use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Column, ConstraintSystem, Error, Fixed},
};
use zkevm_circuits::table::LookupTable;

use crate::aggregation::decoder::witgen::ZstdTag::{
    // TODO: update to the correct tags once witgen code is merged.
    ZstdBlockFseCode as ZstdBlockSequenceFseCode,
    ZstdBlockLstream as ZstdBlockSequenceData,
    ZstdBlockSequenceHeader,
};

/// Read-only table that allows us to check the correct assignment of FSE table kind.
///
/// The possible orders are:
/// - [ZstdBlockSequenceHeader, ZstdBlockSequenceFseCode, ZstdBlockSequenceFseCode, LLT]
/// - [ZstdBlockSequenceFseCode, ZstdBlockSequenceFseCode, ZstdBlockSequenceFseCode, MOT]
/// - [ZstdBlockSequenceFseCode, ZstdBlockSequenceFseCode, ZstdBlockSequenceData, MLT]
#[derive(Clone, Debug)]
pub struct RomFseOrderTable {
    /// The tag that occurred previously.
    tag_prev: Column<Fixed>,
    /// The current tag, expected to be ZstdBlockSequenceFseCode.
    tag_cur: Column<Fixed>,
    /// The tag that follows the current tag.
    tag_next: Column<Fixed>,
    /// The FSE table kind, possible values: LLT=1, MOT=2, MLT=3.
    table_kind: Column<Fixed>,
}

impl RomFseOrderTable {
    pub fn construct(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            tag_prev: meta.fixed_column(),
            tag_cur: meta.fixed_column(),
            tag_next: meta.fixed_column(),
            table_kind: meta.fixed_column(),
        }
    }

    /// Load the FSE order ROM table.
    pub fn load(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || "(ROM): FSE order table",
            |mut region| {
                for (offset, row) in [
                    (
                        ZstdBlockSequenceHeader,
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceFseCode,
                        1u64,
                    ),
                    (
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceFseCode,
                        2u64,
                    ),
                    (
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceData,
                        3u64,
                    ),
                ]
                .iter()
                .enumerate()
                {
                    region.assign_fixed(
                        || format!("tag_prev at offset={offset}"),
                        self.tag_prev,
                        offset,
                        || Value::known(Fr::from(row.0 as u64)),
                    )?;
                    region.assign_fixed(
                        || format!("tag_cur at offset={offset}"),
                        self.tag_cur,
                        offset,
                        || Value::known(Fr::from(row.1 as u64)),
                    )?;
                    region.assign_fixed(
                        || format!("tag_next at offset={offset}"),
                        self.tag_next,
                        offset,
                        || Value::known(Fr::from(row.2 as u64)),
                    )?;
                    region.assign_fixed(
                        || format!("table_kind at offset={offset}"),
                        self.table_kind,
                        offset,
                        || Value::known(Fr::from(row.3)),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl LookupTable<Fr> for RomFseOrderTable {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![
            self.tag_prev.into(),
            self.tag_cur.into(),
            self.tag_next.into(),
            self.table_kind.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("tag_prev"),
            String::from("tag_cur"),
            String::from("tag_next"),
            String::from("table_kind"),
        ]
    }
}
