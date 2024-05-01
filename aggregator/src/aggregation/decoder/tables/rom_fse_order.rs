use eth_types::Field;
use gadgets::impl_expr;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed},
};
use itertools::Itertools;
use once_cell::sync::Lazy;
use zkevm_circuits::table::LookupTable;

use crate::aggregation::decoder::witgen::ZstdTag::{
    // TODO: update to the correct tags once witgen code is merged.
    ZstdBlockFseCode as ZstdBlockSequenceFseCode,
    ZstdBlockLstream as ZstdBlockSequenceData,
    ZstdBlockSequenceHeader,
};

/// FSE table variants that we observe in the sequences section.
#[derive(Clone, Copy, Debug)]
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

#[derive(Clone, Debug)]
pub struct RomSequencesDataInterleavedOrder {
    /// FSE table used in the previous bitstring.
    table_kind_prev: Column<Fixed>,
    /// FSE table used in the current bitstring.
    table_kind_curr: Column<Fixed>,
    /// Boolean flag to indicate whether we are initialising the FSE state.
    is_init_state: Column<Fixed>,
    /// Boolean flag to indicate whether we are updating the FSE state.
    is_update_state: Column<Fixed>,
}

impl RomSequencesDataInterleavedOrder {
    pub fn construct(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            table_kind_prev: meta.fixed_column(),
            table_kind_curr: meta.fixed_column(),
            is_init_state: meta.fixed_column(),
            is_update_state: meta.fixed_column(),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || "(ROM): sequences data interleaved order",
            |mut region| {
                // handle the first row, i.e. (None, LLT, init_state=true, update_state=false).
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
                region.assign_fixed(
                    || "is_init_state",
                    self.is_init_state,
                    0,
                    || Value::known(Fr::one()),
                )?;
                region.assign_fixed(
                    || "is_update_state",
                    self.is_update_state,
                    0,
                    || Value::known(Fr::zero()),
                )?;

                for (i, &(table_kind_prev, table_kind_curr, is_init_state, is_update_state)) in [
                    (FseTableKind::LLT, FseTableKind::MOT, true, false), // init state (MOT)
                    (FseTableKind::MOT, FseTableKind::MLT, true, false), // init state (MLT)
                    (FseTableKind::MLT, FseTableKind::MOT, false, false),
                    (FseTableKind::MOT, FseTableKind::MLT, false, false),
                    (FseTableKind::MLT, FseTableKind::LLT, false, false),
                    (FseTableKind::LLT, FseTableKind::LLT, false, true),
                    (FseTableKind::LLT, FseTableKind::MLT, false, true),
                    (FseTableKind::MLT, FseTableKind::MOT, false, true),
                    (FseTableKind::MOT, FseTableKind::MOT, false, false),
                ]
                .iter()
                .enumerate()
                {
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
                    region.assign_fixed(
                        || "is_init_state",
                        self.is_init_state,
                        i + 1,
                        || Value::known(Fr::from(is_init_state as u64)),
                    )?;
                    region.assign_fixed(
                        || "is_update_state",
                        self.is_update_state,
                        i + 1,
                        || Value::known(Fr::from(is_update_state as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl LookupTable<Fr> for RomSequencesDataInterleavedOrder {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![
            self.table_kind_prev.into(),
            self.table_kind_curr.into(),
            self.is_init_state.into(),
            self.is_update_state.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("table_kind_prev"),
            String::from("table_kind_curr"),
            String::from("is_init_state"),
            String::from("is_update_state"),
        ]
    }
}

trait FsePredefinedTable {
    /// Get the number of states in the FSE table.
    fn table_size(&self) -> u64;
    /// Get the symbol in the FSE table for the given state.
    fn symbol(&self, state: u64) -> u64;
    /// Get the baseline in the FSE table for the given state.
    fn baseline(&self, state: u64) -> u64;
    /// Get the number of bits (nb) to read from bitstream in the FSE table for the given state.
    fn nb(&self, state: u64) -> u64;
}

impl FsePredefinedTable for FseTableKind {
    fn table_size(&self) -> u64 {
        match self {
            Self::LLT => 64,
            Self::MOT => 32,
            Self::MLT => 64,
        }
    }

    fn symbol(&self, state: u64) -> u64 {
        match self {
            Self::LLT => match state {
                0..=1 => 0,
                2 => 1,
                3 => 3,
                4 => 4,
                5 => 6,
                6 => 7,
                7 => 9,
                8 => 10,
                9 => 12,
                10 => 14,
                11 => 16,
                12 => 18,
                13 => 19,
                14 => 21,
                15 => 22,
                16 => 24,
                17 => 25,
                18 => 26,
                19 => 27,
                20 => 29,
                21 => 31,
                22 => 0,
                23 => 1,
                24 => 2,
                25 => 4,
                26 => 5,
                27 => 7,
                28 => 8,
                29 => 10,
                30 => 11,
                31 => 13,
                32 => 16,
                33 => 17,
                34 => 19,
                35 => 20,
                36 => 22,
                37 => 23,
                38 => 25,
                39 => 25,
                40 => 26,
                41 => 28,
                42 => 30,
                43 => 0,
                44 => 1,
                45 => 2,
                46 => 3,
                47 => 5,
                48 => 6,
                49 => 8,
                50 => 9,
                51 => 11,
                52 => 12,
                53 => 15,
                54 => 17,
                55 => 18,
                56 => 20,
                57 => 21,
                58 => 23,
                59 => 24,
                60 => 35,
                61 => 34,
                62 => 33,
                63 => 32,
                _ => unreachable!(),
            },
            _ => unimplemented!(),
        }
    }

    fn baseline(&self, state: u64) -> u64 {
        match self {
            Self::LLT => match state {
                0 => 0,
                1 => 16,
                2 => 32,
                3..=16 => 0,
                17 => 32,
                18..=21 | 23..=24 => 0,
                22 | 25 | 27 | 29 | 32 | 34 | 36 | 40 => 32,
                26 | 28 | 30..=31 | 33 | 35 | 37..=38 | 41..=42 | 53 | 60..=63 => 0,
                39 | 44 => 16,
                43 => 48,
                45..=52 | 54..=59 => 32,
                _ => unreachable!(),
            },
            _ => unimplemented!(),
        }
    }

    fn nb(&self, state: u64) -> u64 {
        match self {
            Self::LLT => match state {
                0..=1 | 22..=23 | 38..=39 | 43..=44 => 4,
                2..=9 | 11..=18 | 24..=30 | 32..=37 | 40 | 45..=52 | 54..=59 => 5,
                10 | 19..=21 | 31 | 41..=42 | 53 | 60..=63 => 6,
                _ => unreachable!(),
            },
            _ => unimplemented!(),
        }
    }
}

pub fn predefined_table(table_kind: FseTableKind) -> Vec<(u64, u64, u64, u64)> {
    let table_size = table_kind.table_size();
    (0..table_size)
        .map(|state| {
            (
                state,
                table_kind.symbol(state),
                table_kind.baseline(state),
                table_kind.nb(state),
            )
        })
        .collect()
}

pub fn predefined_table_values(table_kind: FseTableKind) -> Vec<[Value<Fr>; 6]> {
    let table_size = table_kind.table_size();
    (0..table_size)
        .map(|state| {
            let symbol = table_kind.symbol(state);
            let baseline = table_kind.baseline(state);
            let nb = table_kind.nb(state);
            [
                Value::known(Fr::from(table_kind as u64)),
                Value::known(Fr::from(table_size)),
                Value::known(Fr::from(state)),
                Value::known(Fr::from(symbol)),
                Value::known(Fr::from(baseline)),
                Value::known(Fr::from(nb)),
            ]
        })
        .collect()
}

/// The Predefined Literal Length FSE table, as per default distributions.
///
/// - https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#literals-length
/// - https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#literal-length-code
pub static FSE_PREDEFINED_LLT: Lazy<Vec<[Value<Fr>; 6]>> =
    Lazy::new(|| predefined_table_values(FseTableKind::LLT));

/// The Predefined Match Length FSE table, as per default distributions.
///
/// - https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#match-length
/// - https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#match-length-code
pub static FSE_PREDEFINED_MLT: Lazy<Vec<[Value<Fr>; 6]>> =
    Lazy::new(|| predefined_table_values(FseTableKind::MLT));

/// The Predefined Match Offset FSE table, as per default distributions.
///
/// - https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#offset-codes-1
/// - https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#offset-code
pub static FSE_PREDEFINED_MOT: Lazy<Vec<[Value<Fr>; 6]>> =
    Lazy::new(|| predefined_table_values(FseTableKind::MOT));

#[derive(Clone, Debug)]
pub struct RomFsePredefinedTable {
    table_kind: Column<Fixed>,
    table_size: Column<Fixed>,
    state: Column<Fixed>,
    symbol: Column<Fixed>,
    baseline: Column<Fixed>,
    nb: Column<Fixed>,
}

impl RomFsePredefinedTable {
    pub fn construct(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            table_kind: meta.fixed_column(),
            table_size: meta.fixed_column(),
            state: meta.fixed_column(),
            symbol: meta.fixed_column(),
            baseline: meta.fixed_column(),
            nb: meta.fixed_column(),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || "ROM: fse predefined",
            |mut region| {
                for (offset, row) in [
                    FSE_PREDEFINED_LLT.as_slice(),
                    FSE_PREDEFINED_MLT.as_slice(),
                    FSE_PREDEFINED_MOT.as_slice(),
                ]
                .concat()
                .iter()
                .enumerate()
                {
                    for ((&column, annotation), &value) in Self::fixed_columns(self)
                        .iter()
                        .zip_eq(Self::annotations(self))
                        .zip_eq(row.iter())
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

impl LookupTable<Fr> for RomFsePredefinedTable {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![
            self.table_kind.into(),
            self.table_size.into(),
            self.state.into(),
            self.symbol.into(),
            self.baseline.into(),
            self.nb.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("table_kind"),
            String::from("table_size"),
            String::from("state"),
            String::from("symbol"),
            String::from("baseline"),
            String::from("nb"),
        ]
    }
}
