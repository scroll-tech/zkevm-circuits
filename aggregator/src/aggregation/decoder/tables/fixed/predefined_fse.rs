use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::witgen::FseTableKind;

use super::{FixedLookupTag, FixedLookupValues};

pub struct RomPredefinedFse {
    pub table_kind: FseTableKind,
    pub table_size: u64,
    pub state: u64,
    pub symbol: u64,
    pub baseline: u64,
    pub nb: u64,
}

pub trait PredefinedFse {
    /// Get the accuracy log of the predefined table.
    fn accuracy_log(&self) -> u8;
    /// Get the number of states in the FSE table.
    fn table_size(&self) -> u64 {
        1 << self.accuracy_log()
    }
    /// Get the symbol in the FSE table for the given state.
    fn symbol(&self, state: u64) -> u64;
    /// Get the baseline in the FSE table for the given state.
    fn baseline(&self, state: u64) -> u64;
    /// Get the number of bits (nb) to read from bitstream in the FSE table for the given state.
    fn nb(&self, state: u64) -> u64;
}

impl PredefinedFse for FseTableKind {
    fn accuracy_log(&self) -> u8 {
        match self {
            Self::LLT => 6,
            Self::MOT => 5,
            Self::MLT => 6,
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
            Self::MOT => match state {
                0 => 0,
                1 => 6,
                2 => 9,
                3 => 15,
                4 => 21,
                5 => 3,
                6 => 7,
                7 => 12,
                8 => 18,
                9 => 23,
                10 => 5,
                11 => 8,
                12 => 14,
                13 => 20,
                14 => 2,
                15 => 7,
                16 => 11,
                17 => 17,
                18 => 22,
                19 => 4,
                20 => 8,
                21 => 13,
                22 => 19,
                23 => 1,
                24 => 6,
                25 => 10,
                26 => 16,
                27 => 28,
                28 => 27,
                29 => 26,
                30 => 25,
                31 => 24,
                _ => unreachable!(),
            },
            Self::MLT => match state {
                0..=3 => state,
                4..=5 => state + 1,
                6 => 8,
                7 => 10,
                8 => 13,
                9 => 16,
                10 => 19,
                11 => 22,
                12 => 25,
                13 => 28,
                14 => 31,
                15 => 33,
                16 => 35,
                17 => 37,
                18 => 39,
                19 => 41,
                20 => 43,
                21 => 45,
                22..=25 => state - 21,
                26..=27 => state - 20,
                28 => 9,
                29 => 12,
                30 => 15,
                31 => 18,
                32 => 21,
                33 => 24,
                34 => 27,
                35 => 30,
                36 => 32,
                37 => 34,
                38 => 36,
                39 => 38,
                40 => 40,
                41 => 42,
                42 => 44,
                43..=44 => 1,
                45 => 2,
                46..=47 => state - 42,
                48 => 7,
                49 => 8,
                50 => 11,
                51 => 14,
                52 => 17,
                53 => 20,
                54 => 23,
                55 => 26,
                56 => 29,
                57 => 52,
                58 => 51,
                59 => 50,
                60 => 49,
                61 => 48,
                62 => 47,
                63 => 46,
                _ => unreachable!(),
            },
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
            Self::MOT => match state {
                0..=14 | 16..=19 | 21..=23 | 25..=31 => 0,
                15 | 20 | 24 => 16,
                _ => unreachable!(),
            },
            Self::MLT => match state {
                0..=1 | 3..=21 | 23 | 25 | 27..=42 | 50..=63 => 0,
                2 | 24 | 26 | 43 | 46..=49 => 32,
                22 | 45 => 16,
                44 => 48,
                _ => unreachable!(),
            },
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
            Self::MOT => match state {
                0 | 2..=5 | 7..=10 | 12..=14 | 16..=19 | 21..=23 | 25..=31 => 5,
                1 | 6 | 11 | 15 | 20 | 24 => 4,
                _ => unreachable!(),
            },
            Self::MLT => match state {
                0 | 7..=21 | 28..=42 | 50..=63 => 6,
                1 | 22..=23 | 43..=45 => 4,
                2..=6 | 24..=27 | 46..=49 => 5,
                _ => unreachable!(),
            },
        }
    }
}

pub fn predefined_fse(table_kind: FseTableKind) -> Vec<RomPredefinedFse> {
    let table_size = table_kind.table_size();
    (0..table_size)
        .map(|state| RomPredefinedFse {
            table_kind,
            table_size,
            state,
            symbol: table_kind.symbol(state),
            baseline: table_kind.baseline(state),
            nb: table_kind.nb(state),
        })
        .collect()
}

impl FixedLookupValues for RomPredefinedFse {
    fn values() -> Vec<[Value<Fr>; 7]> {
        [FseTableKind::LLT, FseTableKind::MOT, FseTableKind::MLT]
            .map(predefined_fse)
            .iter()
            .flatten()
            .map(|row| {
                [
                    Value::known(Fr::from(FixedLookupTag::PredefinedFse as u64)),
                    Value::known(Fr::from(row.table_kind as u64)),
                    Value::known(Fr::from(row.table_size)),
                    Value::known(Fr::from(row.state)),
                    Value::known(Fr::from(row.symbol)),
                    Value::known(Fr::from(row.baseline)),
                    Value::known(Fr::from(row.nb)),
                ]
            })
            .collect()
    }
}
