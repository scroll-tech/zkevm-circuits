use gadgets::util::Expr;
use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Expression, VirtualCells},
    poly::Rotation,
};
use zkevm_circuits::util::Field;

#[derive(Clone, Copy, Debug)]
pub struct BooleanAdvice {
    pub column: Column<Advice>,
}

impl BooleanAdvice {
    pub fn construct<F: Field>(
        meta: &mut ConstraintSystem<F>,
        enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) -> Self {
        let advice = Self {
            column: meta.advice_column(),
        };
        meta.create_gate("BooleanAdvice: main gate", |meta| {
            let bool_val = meta.query_advice(advice.column, Rotation::cur());
            vec![enable(meta) * bool_val.expr() * (1.expr() - bool_val)]
        });
        advice
    }

    pub fn expr_at<F: Field>(&self, meta: &mut VirtualCells<F>, at: Rotation) -> Expression<F> {
        meta.query_advice(self.column, at)
    }
}
