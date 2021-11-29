use crate::util::Expr;
use halo2::{
    arithmetic::FieldExt,
    circuit::{self, Region},
    plonk::{Advice, Column, Error, Expression, VirtualCells},
    poly::Rotation,
};

pub(crate) mod constraint_builder;
pub(crate) mod math_gadget;

#[derive(Clone, Debug)]
pub(crate) struct Cell<F> {
    // expression for constraint
    expression: Expression<F>,
    column: Column<Advice>,
    // relative position to selector for synthesis
    rotation: usize,
}

impl<F: FieldExt> Cell<F> {
    pub(crate) fn new(
        meta: &mut VirtualCells<F>,
        column: Column<Advice>,
        rotation: usize,
    ) -> Self {
        Self {
            expression: meta.query_advice(column, Rotation(rotation as i32)),
            column,
            rotation,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Option<F>,
    ) -> Result<circuit::Cell, Error> {
        region.assign_advice(
            || {
                format!(
                    "Cell column: {:?} and rotation: {}",
                    self.column, self.rotation
                )
            },
            self.column,
            offset + self.rotation,
            || value.ok_or(Error::SynthesisError),
        )
    }
}

impl<F: FieldExt> Expr<F> for Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RandomLinearCombination<F, const N: usize> {
    // random linear combination expression of cells
    expression: Expression<F>,
    // inner cells in little-endian for synthesis
    pub(crate) cells: [Cell<F>; N],
}

impl<F: FieldExt, const N: usize> RandomLinearCombination<F, N> {
    const NUM_BYTES: usize = N;

    pub(crate) fn random_linear_combine(bytes: [u8; N], randomness: F) -> F {
        bytes.iter().rev().fold(F::zero(), |acc, byte| {
            acc * randomness + F::from_u64(*byte as u64)
        })
    }

    pub(crate) fn random_linear_combine_expr(
        bytes: [Expression<F>; N],
        randomness: Expression<F>,
    ) -> Expression<F> {
        bytes.iter().rev().fold(0.expr(), |acc, byte| {
            acc * randomness.clone() + byte.clone()
        })
    }

    pub(crate) fn new(cells: [Cell<F>; N], randomness: Expression<F>) -> Self {
        Self {
            expression: Self::random_linear_combine_expr(
                cells.clone().map(|cell| cell.expr()),
                randomness,
            ),
            cells,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        word: Option<[u8; N]>,
    ) -> Result<Vec<circuit::Cell>, Error> {
        word.map_or(Err(Error::SynthesisError), |word| {
            self.cells
                .iter()
                .zip(word.iter())
                .map(|(cell, byte)| {
                    cell.assign(region, offset, Some(F::from_u64(*byte as u64)))
                })
                .collect()
        })
    }
}

impl<F: FieldExt, const N: usize> Expr<F> for RandomLinearCombination<F, N> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

pub(crate) type Word<F> = RandomLinearCombination<F, 32>;
pub(crate) type MemoryAddress<F> = RandomLinearCombination<F, 5>;

/// Returns the sum of the passed in cells
pub(crate) mod sum {
    use crate::{evm_circuit::util::Cell, util::Expr};
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(cells: &[Cell<F>]) -> Expression<F> {
        cells.iter().fold(0.expr(), |acc, cell| acc + cell.expr())
    }

    pub(crate) fn value<F: FieldExt>(values: &[u8]) -> F {
        values
            .iter()
            .fold(F::zero(), |acc, value| acc + F::from_u64(*value as u64))
    }
}

/// Returns `1` when `expr[0] && expr[1] && ... == 1`, and returns `0` otherwise.
/// Inputs need to be boolean
pub(crate) mod and {
    use crate::util::Expr;
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(
        inputs: Vec<Expression<F>>,
    ) -> Expression<F> {
        inputs
            .iter()
            .fold(1.expr(), |acc, input| acc * input.clone())
    }

    pub(crate) fn value<F: FieldExt>(inputs: Vec<F>) -> F {
        inputs.iter().fold(F::one(), |acc, input| acc * input)
    }
}

/// Returns `when_true` when `selector == 1`, and returns `when_false` when `selector == 0`.
/// `selector` needs to be boolean.
pub(crate) mod select {
    use crate::util::Expr;
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(
        selector: Expression<F>,
        when_true: Expression<F>,
        when_false: Expression<F>,
    ) -> Expression<F> {
        selector.clone() * when_true + (1.expr() - selector) * when_false
    }

    pub(crate) fn value<F: FieldExt>(
        selector: F,
        when_true: F,
        when_false: F,
    ) -> F {
        selector * when_true + (F::one() - selector) * when_false
    }

    pub(crate) fn value_word<F: FieldExt>(
        selector: F,
        when_true: [u8; 32],
        when_false: [u8; 32],
    ) -> [u8; 32] {
        if selector == F::one() {
            when_true
        } else {
            when_false
        }
    }
}

/// Decodes a field element from its byte representation
pub(crate) mod from_bytes {
    use crate::{
        evm_circuit::{param::MAX_BYTES_FIELD, util::Cell},
        util::Expr,
    };
    use halo2::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(bytes: Vec<Cell<F>>) -> Expression<F> {
        assert!(bytes.len() <= MAX_BYTES_FIELD, "number of bytes too large");
        let mut value = 0.expr();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value = value + byte.expr() * multiplier;
            multiplier *= F::from_u64(256);
        }
        value
    }

    pub(crate) fn value<F: FieldExt>(bytes: Vec<u8>) -> F {
        assert!(bytes.len() <= MAX_BYTES_FIELD, "number of bytes too large");
        let mut value = F::zero();
        let mut multiplier = F::one();
        for byte in bytes.iter() {
            value += F::from_u64(*byte as u64) * multiplier;
            multiplier *= F::from_u64(256);
        }
        value
    }
}

/// Returns 2**num_bits
pub(crate) fn get_range<F: FieldExt>(num_bits: usize) -> F {
    F::from_u64(2).pow(&[num_bits as u64, 0, 0, 0])
}
