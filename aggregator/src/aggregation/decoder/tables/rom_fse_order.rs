use eth_types::Field;
use gadgets::impl_expr;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed},
};
use zkevm_circuits::table::LookupTable;

use crate::aggregation::decoder::witgen::ZstdTag::{
    // TODO: update to the correct tags once witgen code is merged.
    ZstdBlockFseCode as ZstdBlockSequenceFseCode,
    ZstdBlockLstream as ZstdBlockSequenceData,
    ZstdBlockSequenceHeader,
};

/// FSE table variants that we observe in the sequences section.
#[derive(Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
pub enum FseTableKind {
    /// Literal length FSE table.
    LLT = 1,
    /// Match offset FSE table.
    MOT,
    /// Match length FSE table.
    MLT,
}

impl_expr!(FseTableKind);

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
                        FseTableKind::LLT,
                    ),
                    (
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceFseCode,
                        FseTableKind::MOT,
                    ),
                    (
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceFseCode,
                        ZstdBlockSequenceData,
                        FseTableKind::MLT,
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
                        || Value::known(Fr::from(row.3 as u64)),
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

#[derive(Clone, Debug)]
pub struct RomFseTableTransition {
    /// The block index on the previous FSE table.
    block_idx_prev: Column<Fixed>,
    /// The block index on the current FSE table.
    block_idx_curr: Column<Fixed>,
    /// The FSE table previously decoded.
    table_kind_prev: Column<Fixed>,
    /// The FSE table currently decoded.
    table_kind_curr: Column<Fixed>,
}

impl RomFseTableTransition {
    pub fn construct(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            block_idx_prev: meta.fixed_column(),
            block_idx_curr: meta.fixed_column(),
            table_kind_prev: meta.fixed_column(),
            table_kind_curr: meta.fixed_column(),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || "ROM: fse table transition",
            |mut region| {
                // assign for the preliminary transition.
                region.assign_fixed(
                    || "block_idx_prev",
                    self.block_idx_prev,
                    0,
                    || Value::known(Fr::zero()),
                )?;
                region.assign_fixed(
                    || "block_idx_curr",
                    self.block_idx_curr,
                    0,
                    || Value::known(Fr::one()),
                )?;
                region.assign_fixed(
                    || "table_kind_prev",
                    self.table_kind_prev,
                    0,
                    || Value::known(Fr::zero()),
                )?;
                region.assign_fixed(
                    || "table_kind_curr",
                    self.table_kind_curr,
                    0,
                    || Value::known(Fr::from(FseTableKind::LLT as u64)),
                )?;

                // assign for the other transitons.
                for (i, &(block_idx_prev, block_idx_curr, table_kind_prev, table_kind_curr)) in [
                    (1, 1, FseTableKind::LLT, FseTableKind::MOT),
                    (1, 1, FseTableKind::MOT, FseTableKind::MLT),
                    // TODO: add more for multi-block scenario
                ]
                .iter()
                .enumerate()
                {
                    region.assign_fixed(
                        || "block_idx_prev",
                        self.block_idx_prev,
                        i + 1,
                        || Value::known(Fr::from(block_idx_prev)),
                    )?;
                    region.assign_fixed(
                        || "block_idx_curr",
                        self.block_idx_curr,
                        i + 1,
                        || Value::known(Fr::from(block_idx_curr)),
                    )?;
                    region.assign_fixed(
                        || "table_kind_prev",
                        self.table_kind_prev,
                        i + 1,
                        || Value::known(Fr::from(table_kind_prev as u64)),
                    )?;
                    region.assign_fixed(
                        || "table_kind_curr",
                        self.table_kind_curr,
                        i + 1,
                        || Value::known(Fr::from(table_kind_curr as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl LookupTable<Fr> for RomFseTableTransition {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![
            self.block_idx_prev.into(),
            self.block_idx_curr.into(),
            self.table_kind_prev.into(),
            self.table_kind_curr.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("block_idx_prev"),
            String::from("block_idx_curr"),
            String::from("table_kind_prev"),
            String::from("table_kind_curr"),
        ]
    }
}
