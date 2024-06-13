//! Comparator can be used to compare LT, EQ (and indirectly GT) for two
//! expressions LHS and RHS.

use crate::Field;
use halo2_proofs::{
    circuit::{Chip, Region, Value},
    plonk::{ConstraintSystem, Error, Expression, TableColumn, VirtualCells},
    poly::Rotation,
};

use crate::{
    is_equal::{IsEqualChip, IsEqualInstruction},
    less_than::{LtChip, LtInstruction},
};

/// Instruction that the Comparator chip needs to implement.
pub trait ComparatorInstruction<F: Field> {
    /// Assign the lhs and rhs witnesses to the Comparator chip's region.
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(), Error>;
}

/// Config for the Comparator chip.
#[derive(Clone, Debug)]
pub struct ComparatorConfig<F, const N_BYTES: usize> {
    /// Config for the LessThan chip.
    pub lt_chip: LtChip<F, N_BYTES>,
    /// Config for the IsEqual chip.
    pub eq_chip: IsEqualChip<F>,
}

impl<F: Field, const N_BYTES: usize> ComparatorConfig<F, N_BYTES> {
    /// Returns (lt, eq) for a comparison between lhs and rhs at the current rotation.
    pub fn expr(&self, meta: &mut VirtualCells<F>) -> (Expression<F>, Expression<F>) {
        (
            self.lt_chip.config.is_lt(meta, Rotation::cur()),
            self.eq_chip.config.is_equal_expression.clone(),
        )
    }

    /// Returns (lt, eq) for a comparison between lhs and rhs at a given rotation
    pub fn expr_at(
        &self,
        meta: &mut VirtualCells<F>,
        at: Rotation,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) -> (Expression<F>, Expression<F>) {
        (
            self.lt_chip.config.is_lt(meta, at),
            self.eq_chip.config.expr_at(meta, at, lhs, rhs),
        )
    }
}

/// Chip to compare two expressions.
#[derive(Clone, Debug)]
pub struct ComparatorChip<F, const N_BYTES: usize> {
    config: ComparatorConfig<F, N_BYTES>,
}

impl<F: Field, const N_BYTES: usize> ComparatorChip<F, N_BYTES> {
    /// Configure the comparator chip. Returns the config.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<F>) -> Expression<F> + Clone,
        lhs: impl FnOnce(&mut VirtualCells<F>) -> Expression<F> + Clone,
        rhs: impl FnOnce(&mut VirtualCells<F>) -> Expression<F> + Clone,
        u8_table: TableColumn,
    ) -> ComparatorConfig<F, N_BYTES> {
        let lt_config =
            LtChip::configure(meta, q_enable.clone(), lhs.clone(), rhs.clone(), u8_table);
        let eq_config = IsEqualChip::configure(meta, q_enable, lhs, rhs);

        ComparatorConfig {
            lt_chip: LtChip::construct(lt_config),
            eq_chip: IsEqualChip::construct(eq_config),
        }
    }

    /// Constructs a comparator chip given its config.
    pub fn construct(config: ComparatorConfig<F, N_BYTES>) -> ComparatorChip<F, N_BYTES> {
        ComparatorChip { config }
    }
}

impl<F: Field, const N_BYTES: usize> ComparatorInstruction<F> for ComparatorChip<F, N_BYTES> {
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        lhs: F,
        rhs: F,
    ) -> Result<(), Error> {
        self.config().lt_chip.assign(region, offset, lhs, rhs)?;
        self.config()
            .eq_chip
            .assign(region, offset, Value::known(lhs), Value::known(rhs))?;

        Ok(())
    }
}

impl<F: Field, const N_BYTES: usize> Chip<F> for ComparatorChip<F, N_BYTES> {
    type Config = ComparatorConfig<F, N_BYTES>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
