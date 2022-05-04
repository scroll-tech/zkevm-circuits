use crate::arith_helpers::{convert_b13_coef, convert_b9_coef, f_from_radix_be, B13, B2, B9};
use crate::common::LANE_SIZE;
use crate::gate_helpers::f_to_biguint;
use crate::permutation::rho_helpers::{get_overflow_detector, BASE_NUM_OF_CHUNKS};
use eth_types::Field;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, Error, TableColumn},
};
use itertools::Itertools;
use std::convert::TryInto;
use std::marker::PhantomData;

const MAX_CHUNKS: usize = 64;
const NUM_OF_BINARY_CHUNKS: usize = 16;
const NUM_OF_B9_CHUNKS: usize = 5;

#[derive(Debug, Clone)]
pub struct RangeCheckConfig<F, const K: u64> {
    pub range: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: Field, const K: u64> RangeCheckConfig<F, K> {
    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "range",
            |mut table| {
                for i in 0..=K {
                    table.assign_cell(
                        || "range",
                        self.range,
                        i as usize,
                        || Ok(F::from_u128(i.into())),
                    )?;
                }
                Ok(())
            },
        )
    }

    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            range: meta.lookup_table_column(),
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Base13toBase9TableConfig<F> {
    pub base13: TableColumn,
    pub base9: TableColumn,
    pub overflow_detector: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: Field> Base13toBase9TableConfig<F> {
    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "13 -> 9",
            |mut table| {
                // Iterate over all possible 13-ary values of size 4
                for (i, b13_chunks) in (0..BASE_NUM_OF_CHUNKS)
                    .map(|_| 0..B13)
                    .multi_cartesian_product()
                    .enumerate()
                {
                    table.assign_cell(
                        || "base 13",
                        self.base13,
                        i,
                        || Ok(f_from_radix_be::<F>(&b13_chunks, B13)),
                    )?;

                    table.assign_cell(
                        || "base 9",
                        self.base9,
                        i,
                        || {
                            let converted_chunks: Vec<u8> = b13_chunks
                                .iter()
                                .map(|&x| convert_b13_coef(x))
                                .collect_vec();
                            Ok(f_from_radix_be::<F>(&converted_chunks, B9))
                        },
                    )?;
                    table.assign_cell(
                        || "overflow_detector",
                        self.overflow_detector,
                        i,
                        || {
                            Ok(F::from_u128(
                                get_overflow_detector(b13_chunks.clone().try_into().unwrap())
                                    .into(),
                            ))
                        },
                    )?;
                }
                Ok(())
            },
        )
    }

    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            base13: meta.lookup_table_column(),
            base9: meta.lookup_table_column(),
            overflow_detector: meta.lookup_table_column(),
            _marker: PhantomData,
        }
    }
}

/// The table describes all possible combinations of these two variables:
/// - The last input accumulator: `high_value`*(13**64) + `low_value`, and
/// - The last output coef: `convert_b13_coef(high_value + low_value)`
#[derive(Debug, Clone)]
pub struct SpecialChunkTableConfig<F> {
    pub last_chunk: TableColumn,
    pub output_coef: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: Field> SpecialChunkTableConfig<F> {
    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "Special Chunks",
            |mut table| {
                // Iterate over all possible values less than 13 for both low
                // and high
                let mut offset = 0;
                for i in 0..B13 {
                    for j in 0..(B13 - i) {
                        let (low, high) = (i, j);
                        let last_chunk = F::from_u128(low.into())
                            + F::from_u128(high.into())
                                * F::from_u128(B13.into()).pow(&[LANE_SIZE as u64, 0, 0, 0]);
                        let output_coef = F::from_u128(convert_b13_coef(low + high).into());
                        table.assign_cell(
                            || "last chunk",
                            self.last_chunk,
                            offset,
                            || Ok(last_chunk),
                        )?;
                        table.assign_cell(
                            || "output coef",
                            self.output_coef,
                            offset,
                            || Ok(output_coef),
                        )?;
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }

    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            last_chunk: meta.lookup_table_column(),
            output_coef: meta.lookup_table_column(),
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BaseInfo<F> {
    input_base: u8,
    output_base: u8,
    // How many chunks we perform in a lookup?
    num_chunks: usize,
    // How many chunks in total
    pub max_chunks: usize,
    pub input_tc: TableColumn,
    pub output_tc: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: Field> BaseInfo<F> {
    pub fn input_pob(&self) -> F {
        F::from_u128(self.input_base.into()).pow(&[self.num_chunks as u64, 0, 0, 0])
    }
    pub fn output_pob(&self) -> F {
        F::from_u128(self.output_base.into()).pow(&[self.num_chunks as u64, 0, 0, 0])
    }

    pub fn slice_count(self) -> usize {
        // Just want the `self.max_chunks.div_ceil(self.num_chunks)`
        (0..self.max_chunks)
            .chunks(self.num_chunks)
            .into_iter()
            .map(|_| 0)
            .collect_vec()
            .len()
    }

    pub fn compute_coefs(&self, input: F) -> Result<(Vec<F>, Vec<F>, F), Error> {
        // big-endian
        let input_chunks: Vec<u8> = {
            let raw = f_to_biguint(input);
            let mut v = raw.to_radix_le(self.input_base.into());
            debug_assert!(v.len() <= self.max_chunks);
            // fill 0 to max chunks
            v.resize(self.max_chunks, 0);
            // v is big-endian now
            v.reverse();
            v
        };
        // Use rchunks + rev so that the remainder chunks stay at the big-endian
        // side
        let input_coefs: Vec<F> = input_chunks
            .rchunks(self.num_chunks)
            .rev()
            .map(|chunks| f_from_radix_be(chunks, self.input_base))
            .collect();
        let convert_chunk = match self.input_base {
            B2 => |x| x,
            B13 => convert_b13_coef,
            B9 => convert_b9_coef,
            _ => unreachable!(),
        };
        let output: F = {
            let converted_chunks: Vec<u8> =
                input_chunks.iter().map(|&x| convert_chunk(x)).collect_vec();
            f_from_radix_be(&converted_chunks, self.output_base)
        };

        let output_coefs: Vec<F> = input_chunks
            .rchunks(self.num_chunks)
            .rev()
            .map(|chunks| {
                let converted_chunks: Vec<u8> =
                    chunks.iter().map(|&x| convert_chunk(x)).collect_vec();
                f_from_radix_be(&converted_chunks, self.output_base)
            })
            .collect();
        Ok((input_coefs, output_coefs, output))
    }
}

#[derive(Debug, Clone)]
pub struct FromBinaryTableConfig<F> {
    base2: TableColumn,
    base9: TableColumn,
    base13: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: Field> FromBinaryTableConfig<F> {
    pub(crate) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "2 -> (9 and 13)",
            |mut table| {
                // Iterate over all possible binary values of size 16
                for (i, b2_chunks) in (0..NUM_OF_BINARY_CHUNKS)
                    .map(|_| 0..B2)
                    .multi_cartesian_product()
                    .enumerate()
                {
                    table.assign_cell(
                        || "base 2",
                        self.base2,
                        i,
                        || Ok(f_from_radix_be::<F>(&b2_chunks, B2)),
                    )?;

                    table.assign_cell(
                        || "base 9",
                        self.base9,
                        i,
                        || Ok(f_from_radix_be::<F>(&b2_chunks, B9)),
                    )?;
                    table.assign_cell(
                        || "base 13",
                        self.base13,
                        i,
                        || Ok(f_from_radix_be::<F>(&b2_chunks, B13)),
                    )?;
                }
                Ok(())
            },
        )
    }

    pub(crate) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            base2: meta.lookup_table_column(),
            base9: meta.lookup_table_column(),
            base13: meta.lookup_table_column(),
            _marker: PhantomData,
        }
    }

    pub(crate) fn get_base_info(&self, output_b9: bool) -> BaseInfo<F> {
        BaseInfo {
            input_base: B2,
            output_base: if output_b9 { B9 } else { B13 },
            num_chunks: NUM_OF_BINARY_CHUNKS,
            max_chunks: MAX_CHUNKS,
            input_tc: self.base2,
            output_tc: if output_b9 { self.base9 } else { self.base13 },
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FromBase9TableConfig<F> {
    base9: TableColumn,
    base13: TableColumn,
    base2: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: Field> FromBase9TableConfig<F> {
    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "9 -> (2 and 13)",
            |mut table| {
                // Iterate over all possible base 9 values of size 5
                for (i, b9_chunks) in (0..NUM_OF_B9_CHUNKS)
                    .map(|_| 0..B9)
                    .multi_cartesian_product()
                    .enumerate()
                {
                    table.assign_cell(
                        || "base 9",
                        self.base9,
                        i,
                        || Ok(f_from_radix_be::<F>(&b9_chunks, B9)),
                    )?;
                    let converted_chunks: Vec<u8> =
                        b9_chunks.iter().map(|&x| convert_b9_coef(x)).collect_vec();
                    table.assign_cell(
                        || "base 13",
                        self.base13,
                        i,
                        || Ok(f_from_radix_be::<F>(&converted_chunks, B13)),
                    )?;
                    table.assign_cell(
                        || "base 2",
                        self.base2,
                        i,
                        || Ok(f_from_radix_be::<F>(&converted_chunks, B2)),
                    )?;
                }
                Ok(())
            },
        )
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            base2: meta.lookup_table_column(),
            base9: meta.lookup_table_column(),
            base13: meta.lookup_table_column(),
            _marker: PhantomData,
        }
    }

    pub(crate) fn get_base_info(&self, output_b2: bool) -> BaseInfo<F> {
        BaseInfo {
            input_base: B9,
            output_base: if output_b2 { B2 } else { B13 },
            num_chunks: NUM_OF_B9_CHUNKS,
            max_chunks: MAX_CHUNKS,
            input_tc: self.base9,
            output_tc: if output_b2 { self.base2 } else { self.base13 },
            _marker: PhantomData,
        }
    }
}
