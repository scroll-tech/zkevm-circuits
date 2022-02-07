//! Reusable gadgets for the zk_evm circuits.
use halo2::circuit::Cell;
use pairing::arithmetic::FieldExt;

/// An assigned cell in the circuit.
#[derive(Clone, Debug)]
pub(crate) struct Variable<T, F: FieldExt> {
    pub(crate) cell: Cell,
    pub(crate) field_elem: Option<F>,
    pub(crate) value: Option<T>,
}

impl<T, F: FieldExt> Variable<T, F> {
    pub(crate) fn new(cell: Cell, field_elem: Option<F>, value: Option<T>) -> Self {
        Self {
            cell,
            field_elem,
            value,
        }
    }
}

pub(crate) mod evm_word;
pub(crate) mod is_zero;
pub(crate) mod monotone;
