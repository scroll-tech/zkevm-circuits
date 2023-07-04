use halo2_proofs::{
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Fixed, Instance},
    poly::Rotation,
};
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::halo2_proofs;

#[derive(Clone, Copy)]
pub(crate) struct MockPlonkConfig {
    pub(crate) a: Column<Advice>,
    pub(crate) b: Column<Advice>,
    pub(crate) c: Column<Advice>,
    pub(crate) q_a: Column<Fixed>,
    pub(crate) q_b: Column<Fixed>,
    pub(crate) q_c: Column<Fixed>,
    pub(crate) q_ab: Column<Fixed>,
    pub(crate) constant: Column<Fixed>,
    #[allow(dead_code)]
    pub(crate) instance: Column<Instance>,
}

impl MockPlonkConfig {
    pub(crate) fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let [a, b, c] = [(); 3].map(|_| meta.advice_column());
        let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
        let instance = meta.instance_column();

        [a, b, c].map(|column| meta.enable_equality(column));

        meta.create_gate(
            "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
            |meta| {
                let [a, b, c] = [a, b, c].map(|column| meta.query_advice(column, Rotation::cur()));
                let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                    .map(|column| meta.query_fixed(column, Rotation::cur()));
                let instance = meta.query_instance(instance, Rotation::cur());
                Some(
                    q_a * a.clone()
                        + q_b * b.clone()
                        + q_c * c
                        + q_ab * a * b
                        + constant
                        + instance,
                )
            },
        );

        MockPlonkConfig {
            a,
            b,
            c,
            q_a,
            q_b,
            q_c,
            q_ab,
            constant,
            instance,
        }
    }
}
