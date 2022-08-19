//! Exponentiation verification circuit.

use gadgets::mul_add::MulAddConfig;
use halo2_proofs::plonk::{Advice, Column, Selector};

use crate::table::ExpTable;

/// Layout for the Exponentiation circuit.
#[derive(Clone, Debug)]
pub struct ExpCircuit<F> {
    /// Whether the row is enabled or not.
    pub q_enable: Selector,
    /// The incremental index in the circuit.
    pub idx: Column<Advice>,
    /// Whether this row is the last row in the circuit.
    pub is_last: Column<Advice>,
    /// The Exponentiation circuit's table.
    pub exp_table: ExpTable,
    /// Multiplication gadget for verification of each step.
    pub mul_gadget: MulAddConfig<F>,
}
