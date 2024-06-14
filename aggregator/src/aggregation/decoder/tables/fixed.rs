use gadgets::impl_expr;
use gadgets::Field;
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed},
};
use itertools::Itertools;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use zkevm_circuits::table::LookupTable;

mod fse_table_transition;
use fse_table_transition::RomFseTableTransition;

pub mod predefined_fse;
use predefined_fse::RomPredefinedFse;

mod seq_code_to_value;
use seq_code_to_value::RomSeqCodeToValue;

mod seq_data_interleaved_order;
use seq_data_interleaved_order::RomSeqDataInterleavedOrder;

mod seq_tag_order;
use seq_tag_order::RomSeqTagOrder;

mod tag_transition;
use tag_transition::RomTagTransition;

mod variable_bit_packing;
use variable_bit_packing::RomVariableBitPacking;

pub trait FixedLookupValues {
    fn values() -> Vec<[Value<Fr>; 7]>;
}

#[derive(Clone, Copy, Debug, EnumIter)]
pub enum FixedLookupTag {
    /// Properties used to describe the ZstdTag of the chunk of bytes.
    TagTransition = 1,
    /// Depending on the compression modes used in the sequences header, we experience different
    /// tag transitions and an FSE table for each tag=ZstdTagSequencesFseCode.
    SeqTagOrder,
    /// The bitstream which sequences are decoded from is interleaved with multiple variants. All
    /// those variants are handled here.
    SeqDataInterleavedOrder,
    /// The predefined code-to-value table that allows us to compute "value" from the "code"
    /// decoded.
    SeqCodeToValue,
    /// The FSE table's layout is assigned such that tables from different blocks appear in a
    /// specific order, which is handled here.
    FseTableTransition,
    /// Represents the FSE table reconstructed from the default distributions, i.e. Predefined FSE
    /// table.
    PredefinedFse,
    /// Represents read and decoded values for the variable bit-packing as specified in the [zstd
    /// comopression format][doclink]:
    ///
    /// doclink: https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#fse-table-description
    VariableBitPacking,
}

impl_expr!(FixedLookupTag);

impl FixedLookupTag {
    fn values(&self) -> Vec<[Value<Fr>; 7]> {
        match self {
            Self::TagTransition => RomTagTransition::values(),
            Self::SeqTagOrder => RomSeqTagOrder::values(),
            Self::SeqDataInterleavedOrder => RomSeqDataInterleavedOrder::values(),
            Self::SeqCodeToValue => RomSeqCodeToValue::values(),
            Self::FseTableTransition => RomFseTableTransition::values(),
            Self::PredefinedFse => RomPredefinedFse::values(),
            Self::VariableBitPacking => RomVariableBitPacking::values(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FixedTable {
    lookup_tag: Column<Fixed>,
    fixed1: Column<Fixed>,
    fixed2: Column<Fixed>,
    fixed3: Column<Fixed>,
    fixed4: Column<Fixed>,
    fixed5: Column<Fixed>,
    fixed6: Column<Fixed>,
}

impl FixedTable {
    pub fn construct(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            lookup_tag: meta.fixed_column(),
            fixed1: meta.fixed_column(),
            fixed2: meta.fixed_column(),
            fixed3: meta.fixed_column(),
            fixed4: meta.fixed_column(),
            fixed5: meta.fixed_column(),
            fixed6: meta.fixed_column(),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || "Fixed lookup table",
            |mut region| {
                for (i, row) in FixedLookupTag::iter()
                    .flat_map(|lookup_tag| lookup_tag.values())
                    .enumerate()
                {
                    for ((&column, annotation), &value) in self
                        .fixed_columns()
                        .iter()
                        .zip_eq(self.annotations())
                        .zip_eq(row.iter())
                    {
                        region.assign_fixed(
                            || format!("{} at offset={i}", annotation),
                            column,
                            i,
                            || value,
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl LookupTable<Fr> for FixedTable {
    fn columns(&self) -> Vec<Column<halo2_proofs::plonk::Any>> {
        vec![
            self.lookup_tag.into(),
            self.fixed1.into(),
            self.fixed2.into(),
            self.fixed3.into(),
            self.fixed4.into(),
            self.fixed5.into(),
            self.fixed6.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("lookup_tag"),
            String::from("fixed1"),
            String::from("fixed2"),
            String::from("fixed3"),
            String::from("fixed4"),
            String::from("fixed5"),
            String::from("fixed6"),
        ]
    }
}
