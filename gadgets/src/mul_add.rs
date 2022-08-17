//! Chip that implements instructions to check: a * b + c == d (mod 2^256) where
//! a, b, c and d are all 256-bit words.

use eth_types::{Field, ToLittleEndian, Word};
use halo2_proofs::{
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use crate::util::{expr_from_bytes, pow_of_two, split_u256, split_u256_limb64, Expr};

/// Config for the MulAddChip.
#[derive(Clone)]
pub struct MulAddConfig<F> {
    /// Radix of contributions to the low 128-bit of the product.
    pub carry_lo: [Column<Advice>; 9],
    /// Radix of contributions to the low 256-bit of the product.
    pub carry_hi: [Column<Advice>; 9],
    /// Sum of the parts higher than 256-bit in the product.
    pub overflow: Expression<F>,
}

/// Chip to constrain a * b + c == d (mod 2^256).
#[derive(Clone)]
pub struct MulAddChip<F> {
    /// Config for the chip.
    pub config: MulAddConfig<F>,
}

impl<F: Field> MulAddChip<F> {
    /// Configure the MulAdd chip.
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        a_limbs: impl FnOnce(&mut VirtualCells<F>) -> [Expression<F>; 4],
        b_limbs: impl FnOnce(&mut VirtualCells<F>) -> [Expression<F>; 4],
        c_lo: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
        c_hi: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
        d_lo: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
        d_hi: impl FnOnce(&mut VirtualCells<F>) -> Expression<F>,
    ) -> MulAddConfig<F> {
        let carry_lo = [(); 9].map(|_| meta.advice_column());
        let carry_hi = [(); 9].map(|_| meta.advice_column());
        let mut overflow = 0.expr();

        meta.create_gate("mul add gate", |meta| {
            let q_enable = q_enable(meta);
            let carry_los = carry_lo
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect::<Vec<Expression<F>>>();
            let carry_his = carry_hi
                .iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect::<Vec<Expression<F>>>();

            let c_lo = c_lo(meta);
            let c_hi = c_hi(meta);
            let d_lo = d_lo(meta);
            let d_hi = d_hi(meta);

            let a_limbs = a_limbs(meta);
            let b_limbs = b_limbs(meta);

            let carry_lo_expr = expr_from_bytes(&carry_los);
            let carry_hi_expr = expr_from_bytes(&carry_his);

            let t0 = a_limbs[0].clone() * b_limbs[0].clone();
            let t1 =
                a_limbs[0].clone() * b_limbs[1].clone() + a_limbs[1].clone() * b_limbs[0].clone();
            let t2 = a_limbs[0].clone() * b_limbs[2].clone()
                + a_limbs[1].clone() * b_limbs[1].clone()
                + a_limbs[2].clone() * b_limbs[0].clone();
            let t3 = a_limbs[0].clone() * b_limbs[3].clone()
                + a_limbs[1].clone() * b_limbs[2].clone()
                + a_limbs[2].clone() * b_limbs[1].clone()
                + a_limbs[3].clone() * b_limbs[0].clone();
            overflow = carry_hi_expr.clone()
                + a_limbs[1].clone() * b_limbs[3].clone()
                + a_limbs[2].clone() * b_limbs[2].clone()
                + a_limbs[3].clone() * b_limbs[2].clone()
                + a_limbs[2].clone() * b_limbs[3].clone()
                + a_limbs[3].clone() * b_limbs[2].clone()
                + a_limbs[3].clone() * b_limbs[3].clone();

            let check_a = t0.expr() + t1.expr() * pow_of_two::<F>(64) + c_lo
                - (d_lo + carry_lo_expr.clone() * pow_of_two::<F>(128));
            let check_b = t2.expr() + t3.expr() * pow_of_two::<F>(64) + c_hi + carry_lo_expr
                - (d_hi + carry_hi_expr * pow_of_two::<F>(128));

            [check_a, check_b]
                .into_iter()
                .map(move |poly| q_enable.clone() * poly)
        });

        MulAddConfig {
            carry_lo,
            carry_hi,
            overflow,
        }
    }

    /// Construct the MulAdd chip given a configuration.
    pub fn construct(config: MulAddConfig<F>) -> Self {
        Self { config }
    }

    /// Assign witness data to the MulAdd chip.
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        words: [Word; 4],
    ) -> Result<(), Error> {
        let (a, b, c, d) = (words[0], words[1], words[2], words[3]);

        let a_limbs = split_u256_limb64(&a);
        let b_limbs = split_u256_limb64(&b);
        let (c_lo, c_hi) = split_u256(&c);
        let (d_lo, d_hi) = split_u256(&d);

        let t0 = a_limbs[0] * b_limbs[0];
        let t1 = a_limbs[0] * b_limbs[1] + a_limbs[1] * b_limbs[0];
        let t2 = a_limbs[0] * b_limbs[2] + a_limbs[1] * b_limbs[1] + a_limbs[2] * b_limbs[0];
        let t3 = a_limbs[0] * b_limbs[3]
            + a_limbs[1] * b_limbs[2]
            + a_limbs[2] * b_limbs[1]
            + a_limbs[3] * b_limbs[0];

        let (c_lo_minus_d_lo, _) = c_lo.overflowing_sub(d_lo);
        let temp = t0 + (t1 << 64);
        let (carry_lo, _) = temp.overflowing_add(c_lo_minus_d_lo);
        let carry_lo = carry_lo >> 128;
        let (carry_lo_minus_d_hi, _) = carry_lo.overflowing_sub(d_hi);
        let temp = t2 + (t3 << 64) + c_hi;
        let (carry_hi, _) = temp.overflowing_add(carry_lo_minus_d_hi);
        let carry_hi = carry_hi >> 128;

        self.config
            .carry_lo
            .iter()
            .zip(carry_lo.to_le_bytes().iter())
            .enumerate()
            .map(|(i, (column, byte))| {
                region.assign_advice(
                    || format!("carry_lo({}): offset: {}", i, offset),
                    *column,
                    offset,
                    || Ok(F::from(*byte as u64)),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.config
            .carry_hi
            .iter()
            .zip(carry_hi.to_le_bytes().iter())
            .enumerate()
            .map(|(i, (column, byte))| {
                region.assign_advice(
                    || format!("carry_hi({}): offset: {}", i, offset),
                    *column,
                    offset,
                    || Ok(F::from(*byte as u64)),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::marker::PhantomData;

    use eth_types::{Field, Word};
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        pairing::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, Selector},
        poly::Rotation,
    };
    use rand::Rng;

    use crate::{
        mul_add::{MulAddChip, MulAddConfig},
        util::{split_u256, split_u256_limb64, Expr},
    };

    macro_rules! try_test_circuit {
        ($values:expr) => {{
            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = usize::BITS - $values.len().leading_zeros() + 2;
            let circuit = TestCircuit::<Fp> {
                values: $values,
                _marker: PhantomData,
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_ok());
        }};
    }

    macro_rules! try_test_circuit_error {
        ($values:expr) => {{
            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = usize::BITS - $values.len().leading_zeros() + 2;
            let circuit = TestCircuit::<Fp> {
                values: $values,
                _marker: PhantomData,
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    pub(crate) fn rand_bytes_array<const N: usize>() -> [u8; N] {
        [(); N].map(|_| rand::random())
    }

    pub(crate) fn rand_word() -> Word {
        Word::from_big_endian(&rand_bytes_array::<32>())
    }

    #[test]
    fn mul_over_rows() {
        #[derive(Clone)]
        struct TestCircuitConfig<F> {
            q_enable: Selector,
            a_limbs: [Column<Advice>; 4],
            b_limbs: [Column<Advice>; 4],
            d: [Column<Advice>; 2],
            mul_config: MulAddConfig<F>,
        }

        #[derive(Clone, Default)]
        struct TestCircuit<F> {
            /// (a, b, d) tuples for a * b == d (mod 2^256).
            values: Vec<(Word, Word, Word)>,
            _marker: PhantomData<F>,
        }

        impl<F: Field> Circuit<F> for TestCircuit<F> {
            type Config = TestCircuitConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn configure(meta: &mut halo2_proofs::plonk::ConstraintSystem<F>) -> Self::Config {
                let q_enable = meta.complex_selector();
                let a_limbs = [(); 4].map(|_| meta.advice_column());
                let b_limbs = [(); 4].map(|_| meta.advice_column());
                let d = [(); 2].map(|_| meta.advice_column());
                let mul_config = MulAddChip::configure(
                    meta,
                    |meta| meta.query_selector(q_enable),
                    |meta| a_limbs.map(|a| meta.query_advice(a, Rotation::cur())),
                    |meta| b_limbs.map(|b| meta.query_advice(b, Rotation::cur())),
                    |_meta| 0.expr(), // c == 0 for multiplication
                    |_meta| 0.expr(), // c == 0 for multiplication
                    |meta| meta.query_advice(d[0], Rotation::cur()),
                    |meta| meta.query_advice(d[1], Rotation::cur()),
                );
                Self::Config {
                    q_enable,
                    a_limbs,
                    b_limbs,
                    d,
                    mul_config,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl halo2_proofs::circuit::Layouter<F>,
            ) -> Result<(), halo2_proofs::plonk::Error> {
                let chip = MulAddChip::construct(config.mul_config);
                let values = self
                    .values
                    .iter()
                    .map(|(a, b, d)| (split_u256_limb64(a), split_u256_limb64(b), split_u256(d)))
                    .collect::<Vec<([Word; 4], [Word; 4], (Word, Word))>>();

                layouter.assign_region(
                    || "witness",
                    |mut region| {
                        for (offset, (a_limbs, b_limbs, (d_lo, d_hi))) in values.iter().enumerate()
                        {
                            config.q_enable.enable(&mut region, offset)?;
                            for (column, a_limb) in config.a_limbs.into_iter().zip(a_limbs) {
                                region.assign_advice(
                                    || format!("a_limb: {}", offset),
                                    column,
                                    offset,
                                    || Ok(F::from(a_limb.as_u64())),
                                )?;
                            }
                            for (column, b_limb) in config.b_limbs.into_iter().zip(b_limbs) {
                                region.assign_advice(
                                    || format!("b_limb: {}", offset),
                                    column,
                                    offset,
                                    || Ok(F::from(b_limb.as_u64())),
                                )?;
                            }
                            region.assign_advice(
                                || format!("d_lo: {}", offset),
                                config.d[0],
                                offset,
                                || Ok(F::from_u128(d_lo.low_u128())),
                            )?;
                            region.assign_advice(
                                || format!("d_hi: {}", offset),
                                config.d[1],
                                offset,
                                || Ok(F::from_u128(d_hi.low_u128())),
                            )?;

                            let (a, b, d) = self.values[offset];
                            chip.assign(&mut region, offset, [a, b, Word::zero(), d])?;
                        }
                        Ok(())
                    },
                )
            }

            fn without_witnesses(&self) -> Self {
                Self::default()
            }
        }

        let mut rng = rand::thread_rng();
        let mut values = Vec::with_capacity(100);
        for _ in 0..100 {
            let a = rand_word();
            let b = rand_word();
            let (d, _) = a.overflowing_mul(b);
            values.push((a, b, d));
        }

        try_test_circuit!(values.clone());
        try_test_circuit_error!(values
            .clone()
            .into_iter()
            .map(|(a, b, d)| {
                if rng.gen::<bool>() {
                    (a, b, d + 1)
                } else {
                    (a, b, d - 1)
                }
            })
            .collect::<Vec<(Word, Word, Word)>>());
    }
}
