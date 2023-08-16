//! Specialized version to replace LtChip for u32/u64/u128 check
//!
//! only constrain input expressions to be in given range
//! do not output the result
//!
//! u8 check can either use U8Table
//! u16 check can use U16Table directly

use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, TableColumn, VirtualCells},
    poly::Rotation,
};

/// Instruction that the Range chip needs to implement.
pub trait UIntRangeCheckInstruction<F: FieldExt, const N_2BYTE: usize, const N_EXPR: usize> {
    /// Assign the expr and u16 le repr witnesses to the Comparator chip's region.
    fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        values: [F; N_EXPR],
    ) -> Result<(), Error>;
}

/// Config for the UIntRange chip.
///
/// `N_2BYTE` is size of range in (u16) 2-byte.
/// for u32, N_2BYTE = 2; for u64, N_2BYTE = 4; for u128, N_2BYTE = 8
///
/// `N_EXPR` is the number of lookup expressions to check.
#[derive(Clone, Copy, Debug)]
pub struct UIntRangeCheckConfig<F, const N_2BYTE: usize, const N_EXPR: usize> {
    /// Denotes the little-endian representation of expression in u16.
    pub u16_repr: [Column<Advice>; N_2BYTE],
    /// Denotes the u16 lookup table.
    pub u16_table: TableColumn,
    _marker: std::marker::PhantomData<F>,
}

/// Chip that checks if expressions are in range.
#[derive(Clone, Debug)]
pub struct UIntRangeCheckChip<F, const N_2BYTE: usize, const N_EXPR: usize> {
    config: UIntRangeCheckConfig<F, N_2BYTE, N_EXPR>,
}

impl UIntRangeCheckChip<(), 0, 0> {
    /// constant value of `N_2BYTE` for u32 check
    pub const SIZE_U32: usize = 2;
    /// constant value of `N_2BYTE` for u64 check
    pub const SIZE_U64: usize = 4;
    /// constant value of `N_2BYTE` for u128 check
    pub const SIZE_U128: usize = 8;
}

impl<F: Field, const N_2BYTE: usize, const N_EXPR: usize> UIntRangeCheckChip<F, N_2BYTE, N_EXPR> {
    /// Configures the range chip.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<F>) -> Expression<F> + Clone,
        expressions: impl FnOnce(&mut VirtualCells<F>) -> [Expression<F>; N_EXPR],
        u16_table: TableColumn,
    ) -> UIntRangeCheckConfig<F, N_2BYTE, N_EXPR> {
        let u16_repr = [(); N_2BYTE].map(|_| meta.advice_column());

        meta.create_gate("range gate", |meta| {
            let q_enable = q_enable.clone()(meta);
            expressions(meta)
                .into_iter()
                .enumerate()
                .map(|(row_idx, expr)| {
                    let acc = (0..N_2BYTE)
                        .rev()
                        .map(|col_idx| {
                            meta.query_advice(u16_repr[col_idx], Rotation(row_idx as i32))
                        })
                        .fold(0.expr(), |acc, cell| acc * 0x10000.expr() + cell);
                    q_enable.clone() * (expr - acc)
                })
                .collect::<Vec<_>>()
        });

        for column in u16_repr {
            meta.lookup(concat!("u16 cell range check"), |meta| {
                let cell = meta.query_advice(column, Rotation::cur());
                vec![(cell, u16_table)]
            });
        }

        UIntRangeCheckConfig {
            u16_repr,
            u16_table,
            _marker: Default::default(),
        }
    }

    /// Constructs a range chip.
    pub fn construct(config: UIntRangeCheckConfig<F, N_2BYTE, N_EXPR>) -> Self {
        Self { config }
    }
}

impl<F: Field, const N_2BYTE: usize, const N_EXPR: usize>
    UIntRangeCheckInstruction<F, N_2BYTE, N_EXPR> for UIntRangeCheckChip<F, N_2BYTE, N_EXPR>
{
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        values: [F; N_EXPR],
    ) -> Result<(), Error> {
        let config = self.config();

        // assign u16 repr
        for (row_idx, value) in values.into_iter().enumerate() {
            let repr: [u8; 32] = value.to_repr();
            for (col_idx, (column, value)) in config
                .u16_repr
                .iter()
                .copied()
                .zip(repr.chunks(2).take(N_2BYTE))
                .enumerate()
            {
                region.assign_advice(
                    || format!("range expr[{row_idx}] u16_cell[{col_idx}]"),
                    column,
                    offset + row_idx,
                    || Value::known(F::from((value[0] as u16 | ((value[1] as u16) << 8)) as u64)),
                )?;
            }
        }

        Ok(())
    }
}

impl<F: Field, const N_2BYTE: usize, const N_EXPR: usize> Chip<F>
    for UIntRangeCheckChip<F, N_2BYTE, N_EXPR>
{
    type Config = UIntRangeCheckConfig<F, N_2BYTE, N_EXPR>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
