use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Fixed, SecondPhase, Selector},
    poly::Rotation,
};

#[cfg(test)]
use halo2_proofs::plonk::FirstPhase;

/// This config is used to compute RLCs for bytes.
/// It requires a phase 2 column
#[derive(Debug, Clone, Copy)]
pub struct RlcConfig {
    #[cfg(test)]
    // Test requires a phase 1 column before proceed to phase 2.
    pub(crate) _phase_1_column: Column<Advice>,
    pub(crate) phase_2_column: Column<Advice>,
    pub(crate) selector: Selector,
    pub(crate) fixed: Column<Fixed>,
}

impl RlcConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let selector = meta.complex_selector();

        #[cfg(test)]
        // CS requires existence of at least one phase 1 column if we operate on phase 2 columns.
        // This column is not really used.
        let _phase_1_column = {
            let column = meta.advice_column_in(FirstPhase);
            meta.enable_equality(column);
            column
        };

        let phase_2_column = meta.advice_column_in(SecondPhase);
        meta.enable_equality(phase_2_column);

        let fixed = meta.fixed_column();
        meta.enable_equality(fixed);

        // phase_2_column | advice
        // ---------------|-------
        // a              | q
        // b              | 0
        // c              | 0
        // d              | 0
        //
        // constraint: q*(a*b+c-d) = 0

        meta.create_gate("rlc_gate", |meta| {
            let a = meta.query_advice(phase_2_column, Rotation(0));
            let b = meta.query_advice(phase_2_column, Rotation(1));
            let c = meta.query_advice(phase_2_column, Rotation(2));
            let d = meta.query_advice(phase_2_column, Rotation(3));
            let q = meta.query_selector(selector);
            vec![q * (a * b + c - d)]
        });
        Self {
            #[cfg(test)]
            _phase_1_column,
            phase_2_column,
            selector,
            fixed,
        }
    }
}
