//! Exponentiation verification circuit.

use std::{marker::PhantomData, ops::Add};

use bus_mapping::circuit_input_builder::{ExpEvent, ExpStep};
use eth_types::{Field, ToScalar, U256};
use gadgets::{
    mul_add::{MulAddChip, MulAddConfig},
    util::{and, not, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

use crate::{
    evm_circuit::util::constraint_builder::BaseConstraintBuilder,
    table::{ExpTable, LookupTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness,
};

/// The number of rows assigned for each step in an exponentiation trace.
pub const OFFSET_INCREMENT: usize = 7usize;
/// The number of rows required for the exponentiation table within the circuit
/// for each step.
pub const ROWS_PER_STEP: usize = 4usize;
/// The gate "verify all but the last step" at constraint "`base_limb[i]` is the
/// same across all steps" uses rotation 10 in `exp_table.base_limb` which is
/// enabled with `q_usable`, which in turn is enabled in all steps.  This means
/// this circuit requires these extra rows after the last enabled `q_usable`.
const UNUSABLE_EXP_ROWS: usize = 10usize;

/// Layout for the Exponentiation circuit.
#[derive(Clone, Debug)]
pub struct ExpCircuitConfig<F> {
    /// Whether the row is enabled.
    pub q_usable: Selector,
    /// The Exponentiation circuit's table.
    pub exp_table: ExpTable,
    /// Multiplication gadget for verification of each step.
    pub mul_gadget: MulAddConfig<F>,
    /// Multiplication gadget to perform 2*n + k.
    pub parity_check: MulAddConfig<F>,
}

impl<F: Field> SubCircuitConfig<F> for ExpCircuitConfig<F> {
    type ConfigArgs = ExpTable;

    /// Return a new ExpCircuitConfig
    fn new(meta: &mut ConstraintSystem<F>, exp_table: Self::ConfigArgs) -> Self {
        let q_usable = meta.complex_selector();
        let mul_gadget = MulAddChip::configure(meta, |meta| {
            and::expr([
                meta.query_selector(q_usable),
                meta.query_fixed(exp_table.is_step, Rotation::cur()),
            ])
        });
        let parity_check = MulAddChip::configure(meta, |meta| {
            and::expr([
                meta.query_selector(q_usable),
                meta.query_fixed(exp_table.is_step, Rotation::cur()),
            ])
        });

        // multiplier <- 2^64
        let two = U256::from(2);
        let multiplier: F = two.pow(U256::from(64)).to_scalar().unwrap();

        meta.create_gate("verify all but the last step", |meta| {
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

            // We want to verify that the multiplication result from each step (of
            // exponentiation by squaring) is passed on as the first
            // multiplicand to the next step. Since the steps are assigned in
            // the reverse order, we have: a::cur == d::next.
            let (a_limb0, a_limb1, a_limb2, a_limb3) = mul_gadget.a_limbs_cur(meta);
            let a_lo_cur = a_limb0 + (a_limb1 * multiplier);
            let a_hi_cur = a_limb2 + (a_limb3 * multiplier);
            let (d_lo_next, d_hi_next) = mul_gadget.d_lo_hi_next(meta);
            cb.require_equal(
                "multiplication gadget => a::cur == d::next (lo)",
                a_lo_cur,
                d_lo_next,
            );
            cb.require_equal(
                "multiplication gadget => a::cur == d::next (hi)",
                a_hi_cur,
                d_hi_next,
            );

            // Identifier does not change over the steps of an exponentiation trace.
            cb.require_equal(
                "identifier does not change",
                meta.query_advice(exp_table.identifier, Rotation::cur()),
                meta.query_advice(exp_table.identifier, Rotation(7)),
            );

            cb.gate(and::expr([
                meta.query_selector(q_usable),
                meta.query_fixed(exp_table.is_step, Rotation::cur()),
                not::expr(meta.query_advice(exp_table.is_last, Rotation::cur())),
            ]))
        });

        meta.create_gate("verify all rows", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // is_step is boolean.
            cb.require_boolean(
                "is_step is boolean",
                meta.query_fixed(exp_table.is_step, Rotation::cur()),
            );

            // is_last is boolean.
            cb.require_boolean(
                "is_last is boolean",
                meta.query_advice(exp_table.is_last, Rotation::cur()),
            );

            cb.gate(meta.query_selector(q_usable))
        });

        meta.create_gate("verify all steps", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            // For every step, the intermediate exponentiation MUST equal the result of
            // the corresponding multiplication.
            let (d_lo_cur, d_hi_cur) = mul_gadget.d_lo_hi_cur(meta);
            cb.require_equal(
                "intermediate exponentiation lo == mul_gadget.d_lo",
                meta.query_advice(exp_table.exponentiation_lo_hi, Rotation::cur()),
                d_lo_cur,
            );
            cb.require_equal(
                "intermediate exponentiation hi == mul_gadget.d_hi",
                meta.query_advice(exp_table.exponentiation_lo_hi, Rotation::next()),
                d_hi_cur,
            );

            // For every step, the MulAddChip's `c` MUST be 0, considering the equation `a *
            // b + c == d` applied ONLY for multiplication.
            let (c_lo_cur, c_hi_cur) = mul_gadget.c_lo_hi_cur(meta);
            cb.require_zero(
                "mul_gadget.c == 0 (lo)",
                c_lo_cur,
            );
            cb.require_zero(
                "mul_gadget.c == 0 (hi)",
                c_hi_cur,
            );

            // The odd/even assignment is boolean.
            let (is_odd, remainder_hi) = parity_check.c_lo_hi_cur(meta);
            cb.require_zero("is_odd is boolean (hi == 0)", remainder_hi);
            cb.require_boolean("is_odd is boolean (lo is boolean)", is_odd.clone());

            // There should be no overflow in the parity check mul gadget.
            cb.require_zero("no overflow in parity check mul gadget", parity_check.overflow.clone());

            // remainder == 1 => exponent is odd
            cb.condition(
                and::expr([
                    not::expr(meta.query_advice(exp_table.is_last, Rotation::cur())),
                    is_odd.clone(),
                ]), |cb| {
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur - 1 (lo::next == lo::cur - 1)",
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation(7)),
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation(0)) - 1.expr(),
                );
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur - 1 (hi::next == hi::cur)",
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation(8)),
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation(1)),
                );

                // base MUST equal b.
                let (b_limb0, b_limb1, b_limb2, b_limb3) = mul_gadget.b_limbs_cur(meta);
                let (base_limb0, base_limb1, base_limb2, base_limb3) = (
                    meta.query_advice(exp_table.base_limb, Rotation::cur()),
                    meta.query_advice(exp_table.base_limb, Rotation::next()),
                    meta.query_advice(exp_table.base_limb, Rotation(2)),
                    meta.query_advice(exp_table.base_limb, Rotation(3)),
                );
                cb.require_equal("exp_table.base_limbs[i] == mul_gadget.b[i]", base_limb0, b_limb0);
                cb.require_equal("exp_table.base_limbs[i] == mul_gadget.b[i]", base_limb1, b_limb1);
                cb.require_equal("exp_table.base_limbs[i] == mul_gadget.b[i]", base_limb2, b_limb2);
                cb.require_equal("exp_table.base_limbs[i] == mul_gadget.b[i]", base_limb3, b_limb3);
            });
            // remainder == 0 => exponent is even
            cb.condition(
                and::expr([
                    not::expr(meta.query_advice(exp_table.is_last, Rotation::cur())),
                    not::expr(is_odd),
                ]), |cb| {
                let (exponent_lo, exponent_hi) = parity_check.d_lo_hi_cur(meta);
                cb.require_equal(
                    "exponent::next == exponent::cur / 2 (equate cur lo)",
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation(0)),
                    exponent_lo,
                );
                cb.require_equal(
                    "exponent::next == exponent::cur / 2 (equate cur hi)",
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation(1)),
                    exponent_hi,
                );
                let (limb0, limb1, limb2, limb3) = parity_check.b_limbs_cur(meta);
                let exponent_next_lo = limb0 + (limb1 * multiplier);
                let exponent_next_hi = limb2 + (limb3 * multiplier);
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur / 2 (equate next lo)",
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation(7)),
                    exponent_next_lo,
                );
                cb.require_equal(
                    "intermediate_exponent::next == intermediate_exponent::cur / 2 (equate next hi)",
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation(8)),
                    exponent_next_hi,
                );

                // a == b
                let (a_limb0, a_limb1, a_limb2, a_limb3) = mul_gadget.a_limbs_cur(meta);
                let (b_limb0, b_limb1, b_limb2, b_limb3) = mul_gadget.b_limbs_cur(meta);
                cb.require_equal("mul_gadget.a[i] == mul_gadget.b[i]", a_limb0, b_limb0);
                cb.require_equal("mul_gadget.a[i] == mul_gadget.b[i]", a_limb1, b_limb1);
                cb.require_equal("mul_gadget.a[i] == mul_gadget.b[i]", a_limb2, b_limb2);
                cb.require_equal("mul_gadget.a[i] == mul_gadget.b[i]", a_limb3, b_limb3);
            });

            // For the last step in the exponentiation operation's trace.
            cb.condition(meta.query_advice(exp_table.is_last, Rotation::cur()), |cb| {
                cb.require_equal(
                    "if is_last is True: intermediate_exponent == 2 (lo == 2)",
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation::cur()),
                    2.expr(),
                );
                cb.require_zero(
                    "if is_last is True: intermediate_exponent == 2 (hi == 0)",
                    meta.query_advice(exp_table.exponent_lo_hi, Rotation::next()),
                );
                // a == b == base
                let (a_limb0, a_limb1, a_limb2, a_limb3) = mul_gadget.a_limbs_cur(meta);
                let (b_limb0, b_limb1, b_limb2, b_limb3) = mul_gadget.b_limbs_cur(meta);
                let (base_limb0, base_limb1, base_limb2, base_limb3) = (
                    meta.query_advice(exp_table.base_limb, Rotation::cur()),
                    meta.query_advice(exp_table.base_limb, Rotation::next()),
                    meta.query_advice(exp_table.base_limb, Rotation(2)),
                    meta.query_advice(exp_table.base_limb, Rotation(3)),
                );
                cb.require_equal("if is_last is True: base == a", base_limb0.clone(), a_limb0);
                cb.require_equal("if is_last is True: base == a", base_limb1.clone(), a_limb1);
                cb.require_equal("if is_last is True: base == a", base_limb2.clone(), a_limb2);
                cb.require_equal("if is_last is True: base == a", base_limb3.clone(), a_limb3);
                cb.require_equal("if is_last is True: base == b", base_limb0, b_limb0);
                cb.require_equal("if is_last is True: base == b", base_limb1, b_limb1);
                cb.require_equal("if is_last is True: base == b", base_limb2, b_limb2);
                cb.require_equal("if is_last is True: base == b", base_limb3, b_limb3);
            });

            cb.gate(and::expr([
                meta.query_selector(q_usable),
                meta.query_fixed(exp_table.is_step, Rotation::cur()),
            ]))
        });

        Self {
            q_usable,
            exp_table,
            mul_gadget,
            parity_check,
        }
    }
}

impl<F: Field> ExpCircuitConfig<F> {
    /// Assign witness to the exponentiation circuit.
    pub fn assign_exp_events(
        &self,
        layouter: &mut impl Layouter<F>,
        exp_events: &[ExpEvent],
        max_exp_steps: usize,
    ) -> Result<(), Error> {
        let max_exp_rows = max_exp_steps * OFFSET_INCREMENT;
        debug_assert!(
            Self::min_num_rows(exp_events) <= max_exp_rows,
            "insufficient rows to populate the exponentiation trace"
        );

        let mut mul_chip = MulAddChip::construct(self.mul_gadget.clone());
        let mut parity_check_chip = MulAddChip::construct(self.parity_check.clone());

        layouter.assign_region(
            || "exponentiation circuit",
            |mut region| {
                let mut offset = 0;
                for exp_event in exp_events.iter() {
                    self.assign_exp_event(
                        &mut region,
                        &mut offset,
                        exp_event,
                        &mut mul_chip,
                        &mut parity_check_chip,
                    )?;
                }

                // Fill the rest of the circuit with valid rows to achieve a constant assignment
                // to the q_usable fixed column.
                let pad_exp_event = ExpEvent::default();
                while offset + OFFSET_INCREMENT <= max_exp_rows - UNUSABLE_EXP_ROWS {
                    self.assign_exp_event(
                        &mut region,
                        &mut offset,
                        &pad_exp_event,
                        &mut mul_chip,
                        &mut parity_check_chip,
                    )?;
                }

                // Fill extra unused rows required by the rotations at the last `q_enable`.
                self.assign_unused_rows(&mut region, offset)?;
                Ok(())
            },
        )
    }

    fn assign_exp_event(
        &self,
        region: &mut Region<F>,
        offset: &mut usize,
        exp_event: &ExpEvent,
        mul_chip: &mut MulAddChip<F>,
        parity_check_chip: &mut MulAddChip<F>,
    ) -> Result<(), Error> {
        let mut exponent = exp_event.exponent;
        for (step, step_assignments) in exp_event
            .steps
            .iter()
            .rev()
            .zip(ExpTable::assignments::<F>(exp_event).chunks_exact(OFFSET_INCREMENT))
        {
            // assign everything except the exp table.
            self.assign_step(
                region,
                *offset,
                &mut exponent,
                step,
                mul_chip,
                parity_check_chip,
            )?;
            // assign exp table.
            for (i, assignment) in step_assignments.iter().enumerate() {
                for (column, value) in <ExpTable as LookupTable<F>>::advice_columns(&self.exp_table)
                    .iter()
                    .zip(assignment)
                {
                    region.assign_advice(
                        || format!("exp circuit: {:?}: {}", *column, *offset + i),
                        *column,
                        *offset + i,
                        || Value::known(*value),
                    )?;
                }
            }
            region.assign_fixed(
                || format!("exp_circuit: {:?}: {}", self.exp_table.is_step, offset),
                self.exp_table.is_step,
                *offset,
                || Value::known(F::one()),
            )?;
            for i in 1..OFFSET_INCREMENT {
                region.assign_fixed(
                    || format!("exp_circuit: {:?}: {}", self.exp_table.is_step, *offset + i),
                    self.exp_table.is_step,
                    *offset + i,
                    || Value::known(F::zero()),
                )?;
            }
            // mul_chip has 7 rows, exp_table has 4 rows. So we increment the offset by
            // the maximum number of rows taken up by any gadget within the
            // exponentiation circuit.
            *offset += OFFSET_INCREMENT;
        }
        Ok(())
    }

    fn assign_step(
        &self,
        region: &mut Region<F>,
        offset: usize,
        exponent: &mut U256,
        step: &ExpStep,
        mul_chip: &mut MulAddChip<F>,
        parity_check_chip: &mut MulAddChip<F>,
    ) -> Result<(), Error> {
        let two = U256::from(2);
        let (exponent_div2, remainder) = exponent.div_mod(two);

        for i in 0..OFFSET_INCREMENT {
            self.q_usable.enable(region, offset + i)?;
        }
        mul_chip.assign(region, offset, [step.a, step.b, U256::zero(), step.d])?;
        parity_check_chip.assign(region, offset, [two, exponent_div2, remainder, *exponent])?;

        // update reducing exponent
        if remainder.is_zero() {
            // exponent is even
            *exponent = exponent_div2;
        } else {
            // exponent is odd
            *exponent = *exponent - 1;
        }
        Ok(())
    }

    fn assign_unused_rows(&self, region: &mut Region<'_, F>, offset: usize) -> Result<(), Error> {
        let mut all_columns = <ExpTable as LookupTable<F>>::advice_columns(&self.exp_table);
        all_columns.extend_from_slice(&[
            self.mul_gadget.col0,
            self.mul_gadget.col1,
            self.mul_gadget.col2,
            self.mul_gadget.col3,
            self.mul_gadget.col4,
            self.parity_check.col0,
            self.parity_check.col1,
            self.parity_check.col2,
            self.parity_check.col3,
            self.parity_check.col4,
        ]);
        for i in 0..UNUSABLE_EXP_ROWS {
            for column in &all_columns {
                region.assign_advice(
                    || format!("unused rows: {}", offset + i),
                    *column,
                    offset + i,
                    || Value::known(F::zero()),
                )?;
            }
            region.assign_fixed(
                || format!("unused rows: {}", offset + i),
                self.exp_table.is_step,
                offset + i,
                || Value::known(F::zero()),
            )?;
        }

        Ok(())
    }

    fn min_num_rows(exp_events: &[ExpEvent]) -> usize {
        exp_events
            .iter()
            .map(|e| e.steps.len() * OFFSET_INCREMENT)
            .sum::<usize>()
            .add(UNUSABLE_EXP_ROWS)
    }
}

/// ExpCircuit
#[derive(Default, Clone, Debug)]
pub struct ExpCircuit<F> {
    /// Exp events
    pub exp_events: Vec<ExpEvent>,
    /// Max number of rows in exp circuit
    pub max_exp_rows: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> ExpCircuit<F> {
    /// Return a new ExpCircuit
    pub fn new(exp_events: Vec<ExpEvent>, max_exp_rows: usize) -> Self {
        Self {
            exp_events,
            max_exp_rows,
            _marker: PhantomData::default(),
        }
    }
}

impl<F: Field> SubCircuit<F> for ExpCircuit<F> {
    type Config = ExpCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        // Hardcoded to pass unit tests for now. In the future, insert:
        // "block.circuits_params.max_exp_rows"
        Self::new(
            block.exp_events.clone(),
            block.circuits_params.max_exp_steps,
        )
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (
            Self::Config::min_num_rows(&block.exp_events),
            block.circuits_params.max_exp_steps,
        )
    }

    /// Make the assignments to the ExpCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        _challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign_exp_events(layouter, &self.exp_events, self.max_exp_rows)
    }
}

#[cfg(any(feature = "test", test))]
impl<F: Field> Circuit<F> for ExpCircuit<F> {
    type Config = (ExpCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let exp_table = ExpTable::construct(meta);
        let challenges = Challenges::construct(meta);
        (ExpCircuitConfig::new(meta, exp_table), challenges)
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        let challenges = challenges.values(&mut layouter);
        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

#[cfg(any(feature = "test", test))]
/// Dev helpers
pub mod dev {
    use super::*;
    use eth_types::Field;
    use halo2_proofs::dev::MockProver;

    use crate::evm_circuit::witness::Block;

    /// Test exponentiation circuit with the provided block witness
    pub fn test_exp_circuit<F: Field>(k: u32, block: Block<F>) {
        let circuit = ExpCircuit::<F>::new(
            block.exp_events.clone(),
            block.circuits_params.max_exp_steps,
        );
        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied_par()
    }
}

#[cfg(test)]
mod tests {
    use bus_mapping::{
        circuit_input_builder::{CircuitInputBuilder, CircuitsParams},
        evm::OpcodeId,
        mock::BlockData,
    };
    use eth_types::{bytecode, geth_types::GethData, Bytecode, Word};
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use mock::TestContext;

    use crate::{
        evm_circuit::witness::block_convert,
        exp_circuit::{dev::test_exp_circuit, ExpCircuit},
    };

    fn gen_code_single(base: Word, exponent: Word) -> Bytecode {
        bytecode! {
            PUSH32(exponent)
            PUSH32(base)
            EXP
            STOP
        }
    }

    fn gen_code_multiple(args: Vec<(Word, Word)>) -> Bytecode {
        let mut code = Bytecode::default();
        for (base, exponent) in args.into_iter() {
            code.push(32, exponent);
            code.push(32, base);
            code.write_op(OpcodeId::EXP);
        }
        code.write_op(OpcodeId::STOP);
        code
    }

    fn gen_data(code: Bytecode) -> CircuitInputBuilder {
        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    fn test_ok(base: Word, exponent: Word, k: Option<u32>) {
        let code = gen_code_single(base, exponent);
        let builder = gen_data(code);
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        test_exp_circuit(k.unwrap_or(18), block);
    }

    fn test_ok_multiple(args: Vec<(Word, Word)>) {
        let code = gen_code_multiple(args);
        let builder = gen_data(code);
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        test_exp_circuit(20, block);
    }

    #[test]
    fn exp_circuit_single() {
        test_ok(2.into(), 2.into(), None);
        test_ok(3.into(), 7.into(), None);
        test_ok(5.into(), 11.into(), None);
        test_ok(7.into(), 13.into(), None);
        test_ok(11.into(), 17.into(), None);
        test_ok(13.into(), 23.into(), None);
        test_ok(29.into(), 43.into(), None);
        test_ok(41.into(), 259.into(), None);
    }

    #[test]
    fn exp_circuit_big() {
        test_ok(
            2.into(),
            Word::from_str_radix("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE", 16).unwrap(),
            Some(20),
        );
    }

    #[test]
    fn exp_circuit_multiple() {
        test_ok_multiple(vec![
            (3.into(), 7.into()),
            (5.into(), 11.into()),
            (7.into(), 13.into()),
            (11.into(), 17.into()),
            (13.into(), 23.into()),
            (29.into(), 43.into()),
            (41.into(), 259.into()),
        ]);
    }

    #[test]
    fn variadic_size_check() {
        let k = 20;
        // Empty
        let block: GethData = TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b)
            .unwrap()
            .into();
        let mut builder =
            BlockData::new_from_geth_data_with_params(block.clone(), CircuitsParams::default())
                .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        let circuit = ExpCircuit::<Fr>::new(
            block.exp_events.clone(),
            block.circuits_params.max_exp_steps,
        );
        let prover1 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

        // Non-empty
        let code = bytecode! {
            PUSH32(8)
            PUSH32(10)
            EXP
            PUSH32(3)
            PUSH32(5)
            EXP
            STOP
        };
        let builder = gen_data(code);
        let block = block_convert::<Fr>(&builder.block, &builder.code_db).unwrap();
        let circuit = ExpCircuit::<Fr>::new(
            block.exp_events.clone(),
            block.circuits_params.max_exp_steps,
        );
        let prover2 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover1.fixed(), prover2.fixed());
        assert_eq!(prover1.permutation(), prover2.permutation());
    }
}
