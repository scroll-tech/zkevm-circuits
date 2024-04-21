use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::Fr,
    plonk::{Any, Column, ConstraintSystem, Error, Fixed},
};
use std::marker::PhantomData;
use zkevm_circuits::table::LookupTable;

pub struct CodeFseRow {
    pub code: u64,
    pub baseline: u64,
    pub nb: u64,
}

impl From<(u64, u64, u64)> for CodeFseRow {
    fn from(v: (u64, u64, u64)) -> Self {
        Self {
            code: v.0,
            baseline: v.1,
            nb: v.2,
        }
    }
}

pub trait SequenceCodeTable {
    const NAME: &'static str;

    fn code_table() -> Vec<CodeFseRow>;
}

#[derive(Clone, Debug)]
pub struct RomSequenceCodes<T> {
    code: Column<Fixed>,
    baseline: Column<Fixed>,
    nb: Column<Fixed>,
    _marker: PhantomData<T>,
}

impl<T: SequenceCodeTable> RomSequenceCodes<T> {
    pub fn construct(meta: &mut ConstraintSystem<Fr>) -> Self {
        Self {
            code: meta.fixed_column(),
            baseline: meta.fixed_column(),
            nb: meta.fixed_column(),
            _marker: PhantomData,
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        layouter.assign_region(
            || format!("(ROM): Sequence Code: {}", T::NAME),
            |mut region| {
                for (offset, row) in T::code_table().iter().enumerate() {
                    region.assign_fixed(
                        || "code",
                        self.code,
                        offset,
                        || Value::known(Fr::from(row.code)),
                    )?;
                    region.assign_fixed(
                        || "baseline",
                        self.baseline,
                        offset,
                        || Value::known(Fr::from(row.baseline)),
                    )?;
                    region.assign_fixed(
                        || "nb",
                        self.nb,
                        offset,
                        || Value::known(Fr::from(row.nb)),
                    )?;
                }

                Ok(())
            },
        )
    }
}

impl<T> LookupTable<Fr> for RomSequenceCodes<T> {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![self.code.into(), self.baseline.into(), self.nb.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("code"),
            String::from("baseline"),
            String::from("nb"),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct LiteralLengthCodes;
#[derive(Clone, Debug)]
pub struct MatchLengthCodes;
#[derive(Clone, Debug)]
pub struct MatchOffsetCodes;

impl SequenceCodeTable for LiteralLengthCodes {
    const NAME: &'static str = "Literal Length Codes";

    fn code_table() -> Vec<CodeFseRow> {
        (0..16)
            .map(|i| (i, i, 0))
            .chain([
                (16, 16, 1),
                (17, 18, 1),
                (18, 20, 1),
                (19, 22, 1),
                (20, 24, 2),
                (21, 28, 2),
                (22, 32, 3),
                (23, 40, 3),
                (24, 48, 4),
                (25, 64, 6),
                (26, 128, 7),
                (27, 256, 8),
                (28, 512, 9),
                (29, 1024, 10),
                (30, 2048, 11),
                (31, 4096, 12),
                (32, 8192, 13),
                (33, 16384, 14),
                (34, 32768, 15),
                (35, 65536, 16),
            ])
            .map(|tuple| tuple.into())
            .collect()
    }
}

impl SequenceCodeTable for MatchLengthCodes {
    const NAME: &'static str = "Match Length Codes";

    fn code_table() -> Vec<CodeFseRow> {
        (0..32)
            .map(|i| (i, i + 3, 0))
            .chain([
                (32, 35, 1),
                (33, 37, 1),
                (34, 39, 1),
                (35, 41, 1),
                (36, 43, 2),
                (37, 47, 2),
                (38, 51, 3),
                (39, 59, 3),
                (40, 67, 4),
                (41, 83, 4),
                (42, 99, 5),
                (43, 131, 7),
                (44, 259, 8),
                (45, 515, 9),
                (46, 1027, 10),
                (47, 2051, 11),
                (48, 4099, 12),
                (49, 8195, 13),
                (50, 16387, 14),
                (51, 32771, 15),
                (52, 65539, 16),
            ])
            .map(|tuple| tuple.into())
            .collect()
    }
}

impl SequenceCodeTable for MatchOffsetCodes {
    const NAME: &'static str = "Match Offset Codes";

    // N <- 31 for Match Offset Codes.
    fn code_table() -> Vec<CodeFseRow> {
        (0..32).map(|i| (i, 1 << i, i).into()).collect()
    }
}
