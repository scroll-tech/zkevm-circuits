//! Exponentiation verification circuit.

use eth_types::{Field, ToScalar, U256};
use gadgets::{
    mul_add::{MulAddChip, MulAddConfig},
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    evm_circuit::{util::constraint_builder::BaseConstraintBuilder, witness::Block},
    table::ExpTable,
};

/// Layout for the Exponentiation circuit.
#[derive(Clone, Debug)]
pub struct ExpCircuit<F> {
    /// Whether the row is a step.
    pub q_step: Selector,
    /// The incremental index in the circuit.
    pub idx: Column<Advice>,
    /// Whether this row is the last row in the circuit.
    pub is_last: Column<Advice>,
    /// Boolean value to check whether intermediate_exponent is odd or even.
    pub remainder: Column<Advice>,
    /// The Exponentiation circuit's table.
    pub exp_table: ExpTable,
    /// Multiplication gadget for verification of each step.
    pub mul_gadget: MulAddConfig<F>,
}

impl<F: Field> ExpCircuit<F> {
    /// Configure the exponentiation circuit.
    pub fn configure(meta: &mut ConstraintSystem<F>, exp_table: ExpTable) -> Self {
        let q_step = meta.complex_selector();
        let idx = meta.advice_column();
        let is_last = meta.advice_column();
        let remainder = meta.advice_column();
        let mul_gadget = MulAddChip::configure(meta, q_step);

        meta.create_gate("base limbs check", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // base limbs MUST be the same across all steps. Since each step consumes 7 rows
            // (check MulAddChip), we check the current step's rotation `i`
            // against `i + 7`.
            for i in 0..4 {
                cb.require_equal(
                    "base_limb[i] is the same across all steps",
                    meta.query_advice(exp_table.base_limb, Rotation(i)),
                    meta.query_advice(exp_table.base_limb, Rotation(i + 7)),
                );
            }

            cb.gate(and::expr([
                meta.query_selector(q_step),
                not::expr(meta.query_advice(is_last, Rotation::cur())),
            ]))
        });

        meta.create_gate("exp circuit", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // We don't use the exp circuit for exponentiation by 0 or 1, so the first
            // multiplication MUST equal `base*base == base^2`. Since we populate the
            // multiplication gadget in a reverse order, the first multiplication is
            // assigned to the last row.
            cb.condition(meta.query_advice(is_last, Rotation::cur()), |cb| {
                for (i, mul_gadget_col) in [
                    mul_gadget.col0,
                    mul_gadget.col1,
                    mul_gadget.col2,
                    mul_gadget.col3,
                ]
                .into_iter()
                .enumerate()
                {
                    cb.require_equal(
                        "if is_last is True: exp_table.base_limb[i] == mul_gadget.a[i]",
                        meta.query_advice(exp_table.base_limb, Rotation(i as i32)),
                        meta.query_advice(mul_gadget_col, Rotation(0)),
                    );
                    cb.require_equal(
                        "if is_last is True: exp_table.base_limb[i] == mul_gadget.b[i]",
                        meta.query_advice(exp_table.base_limb, Rotation(i as i32)),
                        meta.query_advice(mul_gadget_col, Rotation(1)),
                    );
                }
            });

            // For every step, the intermediate exponentiation MUST equal the result of
            // the corresponding multiplication.
            cb.require_equal(
                "intermediate exponentiation lo == mul_gadget.d_lo",
                meta.query_advice(exp_table.intermediate_exp_lo_hi, Rotation::cur()),
                meta.query_advice(mul_gadget.col2, Rotation(2)),
            );
            cb.require_equal(
                "intermediate exponentiation hi == mul_gadget.d_hi",
                meta.query_advice(exp_table.intermediate_exp_lo_hi, Rotation::next()),
                meta.query_advice(mul_gadget.col3, Rotation(2)),
            );

            // For every step, the MulAddChip's `c` MUST be 0, considering the equation `a *
            // b + c == d` applied ONLY for multiplication.
            cb.require_zero(
                "mul_gadget.c == 0",
                and::expr([
                    meta.query_advice(mul_gadget.col0, Rotation(2)),
                    meta.query_advice(mul_gadget.col1, Rotation(2)),
                ]),
            );

            // The intermediate exponent starts at the exponent, i.e.
            // intermediate_exponent[0] == exponent.
            // For every intermediate step, the intermediate exponent is reduced:
            // 1. intermediate_exponent::next == intermediate_exponent::cur - 1, if odd.
            // 2. intermediate_exponent::next == intermediate_exponent::cur/2, if even.
            let remainder_expr = meta.query_advice(remainder, Rotation::cur());
            cb.require_boolean("remainder is 0 or 1", remainder_expr.clone());

            // remainder == 1 => odd
            cb.condition(
                and::expr([
                    not::expr(meta.query_advice(is_last, Rotation::cur())),
                    remainder_expr.clone(),
                ]), |cb| {
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur - 1 (lo::next == lo::cur - 1)",
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation(7)),
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation(0)) - 1.expr(),
                );
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur - 1 (hi::next == hi::cur)",
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation(8)),
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation(1)),
                );
            });
            // remainder == 0 => even
            cb.condition(
                and::expr([
                    not::expr(meta.query_advice(is_last, Rotation::cur())),
                    not::expr(remainder_expr),
                ]), |cb| {
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur / 2",
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation(0)),
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation(7)) * 2.expr(),
                );
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur / 2",
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation(1)),
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation(8)) * 2.expr(),
                );
            });

            // For the last step, the intermediate_exponent MUST be 2, since we do not cover
            // the case where exponent == 0 or exponent == 1 in exponentiation
            // circuit.
            cb.condition(meta.query_advice(is_last, Rotation::cur()), |cb| {
                cb.require_equal(
                    "if is_last is True: intermediate_exponent == 2 (lo == 2)",
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation::cur()),
                    2.expr(),
                );
                cb.require_zero(
                    "if is_last is True: intermediate_exponent == 2 (hi == 0)",
                    meta.query_advice(exp_table.intermediate_exponent_lo_hi, Rotation::next()),
                );
            });

            cb.gate(meta.query_selector(q_step))
        });

        Self {
            q_step,
            idx,
            is_last,
            remainder,
            exp_table,
            mul_gadget,
        }
    }

    /// Assign witness to the exponentiation circuit.
    pub fn assign_block(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        const OFFSET_INCREMENT: usize = 7usize;
        const ROWS_PER_STEP: usize = 4usize;

        let mul_chip = MulAddChip::construct(self.mul_gadget.clone());

        layouter.assign_region(
            || "exponentiation circuit",
            |mut region| {
                // assign everything except the exp table.
                let mut offset = 0;
                for exp_event in block.exp_events.iter() {
                    let mut exponent = exp_event.exponent;
                    for (idx, step) in exp_event.steps.iter().rev().enumerate() {
                        let is_last = if idx == exp_event.steps.len() - 1 {
                            F::one()
                        } else {
                            F::zero()
                        };
                        let (exponent_div2, remainder) = exponent.div_mod(2.into());
                        if remainder.is_zero() {
                            // exponent is even
                            exponent = exponent_div2;
                        } else {
                            // exponent is odd
                            exponent = exponent - 1;
                        }

                        self.q_step.enable(&mut region, offset)?;
                        region.assign_advice(
                            || format!("idx: {}", offset),
                            self.idx,
                            offset,
                            || Ok(F::from(idx as u64)),
                        )?;
                        region.assign_advice(
                            || format!("is_last: {}", offset),
                            self.is_last,
                            offset,
                            || Ok(is_last),
                        )?;
                        region.assign_advice(
                            || format!("remainder: {}", offset),
                            self.remainder,
                            offset,
                            || Ok(remainder.to_scalar().unwrap()),
                        )?;
                        mul_chip.assign(
                            &mut region,
                            offset,
                            [step.a, step.b, U256::zero(), step.d],
                        )?;

                        // mul_chip has 7 rows, exp_table has 4 rows. So we increment the offset by
                        // the maximum number of rows taken up by any gadget within the
                        // exponentiation circuit.
                        offset += OFFSET_INCREMENT;
                    }
                }

                // assign exp table.
                offset = 0usize;
                for exp_event in block.exp_events.iter() {
                    for step_assignments in
                        ExpTable::assignments::<F>(exp_event).chunks_exact(ROWS_PER_STEP)
                    {
                        for (i, assignment) in step_assignments.iter().enumerate() {
                            for (column, value) in self.exp_table.columns().iter().zip(assignment) {
                                region.assign_advice(
                                    || format!("exp circuit: {:?}: {}", *column, offset + i),
                                    *column,
                                    offset + i,
                                    || Ok(*value),
                                )?;
                            }
                            for column in self.exp_table.columns() {
                                for j in ROWS_PER_STEP..OFFSET_INCREMENT {
                                    region.assign_advice(
                                        || format!("unused rows: {}", offset + j),
                                        column,
                                        offset + j,
                                        || Ok(F::zero()),
                                    )?;
                                }
                            }
                        }
                        offset += OFFSET_INCREMENT;
                    }
                }

                // assign a zero step, analogous to padding.
                let mut all_columns = self.exp_table.columns();
                all_columns.extend_from_slice(&[self.is_last, self.idx, self.remainder]);
                for column in all_columns {
                    for i in 0..OFFSET_INCREMENT {
                        region.assign_advice(
                            || format!("padding steps: {}", offset + i),
                            column,
                            offset + i,
                            || Ok(F::zero()),
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}

#[cfg(feature = "dev")]
/// Dev helpers
pub mod dev {
    use super::*;
    use eth_types::Field;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, ConstraintSystem},
    };

    use crate::evm_circuit::witness::Block;

    #[derive(Clone)]
    struct ExpCircuitTesterConfig<F> {
        exp_circuit: ExpCircuit<F>,
    }

    #[derive(Default)]
    struct ExpCircuitTester<F> {
        block: Block<F>,
    }

    impl<F: Field> ExpCircuitTester<F> {
        pub fn new(block: Block<F>) -> Self {
            Self { block }
        }
    }

    impl<F: Field> Circuit<F> for ExpCircuitTester<F> {
        type Config = ExpCircuitTesterConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let exp_table = ExpTable::construct(meta);
            let exp_circuit = ExpCircuit::configure(meta, exp_table);

            ExpCircuitTesterConfig { exp_circuit }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            config.exp_circuit.assign_block(&mut layouter, &self.block)
        }
    }

    /// Test exponentiation circuit with the provided block witness
    pub fn test_exp_circuit<F: Field>(k: u32, block: Block<F>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = ExpCircuitTester::<F>::new(block);
        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        prover.verify()
    }
}

#[cfg(test)]
mod tests {
    use bus_mapping::{circuit_input_builder::CircuitInputBuilder, mock::BlockData};
    use eth_types::{bytecode, geth_types::GethData, Word};
    use mock::TestContext;

    use crate::{evm_circuit::witness::block_convert, exp_circuit::dev::test_exp_circuit};

    fn gen_data(base: Word, exponent: Word) -> CircuitInputBuilder {
        let code = bytecode! {
            PUSH32(exponent)
            PUSH32(base)
            EXP
            STOP
        };
        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    fn test_ok(base: Word, exponent: Word) {
        let builder = gen_data(base, exponent);
        let block = block_convert(&builder.block, &builder.code_db);
        assert_eq!(test_exp_circuit(10, block), Ok(()));
    }

    #[test]
    fn exp_circuit_valid() {
        test_ok(3.into(), 7.into());
        test_ok(5.into(), 11.into());
        test_ok(7.into(), 13.into());
        test_ok(11.into(), 17.into());
        test_ok(13.into(), 23.into());
        test_ok(29.into(), 43.into());
    }
}
