use crate::arith_helpers::*;
use crate::common::*;
use crate::gates::gate_helpers::biguint_to_f;
use crate::keccak_arith::*;
use halo2::circuit::Cell;
use halo2::circuit::Layouter;
use halo2::{
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use pairing::{arithmetic::FieldExt, bn256::Fr as Fp};
use std::{convert::TryInto, marker::PhantomData};

/// The number of next_inputs that are used inside the `absorb` circuit.
pub(crate) const ABSORB_NEXT_INPUTS: usize = 17;

#[derive(Clone, Debug)]
pub struct AbsorbConfig<F> {
    q_mixing: Selector,
    state: [Column<Advice>; 25],
    _marker: PhantomData<F>,
}

impl<F: FieldExt> AbsorbConfig<F> {
    pub const OFFSET: usize = 2;
    // We assume state is recieved in base-9.
    // Rows are assigned as:
    // 1) STATE (25 columns) (offset -1)
    // 2) NEXT_INPUTS (17 columns) + is_mixing flag (1 column) (offset +0)
    // (current rotation)
    // 3) OUT_STATE (25 columns) (offset +1)
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 25],
    ) -> AbsorbConfig<F> {
        // def absorb(state: List[List[int], next_input: List[List[int]):
        //     for x in range(5):
        //         for y in range(5):
        //             # state[x][y] has 2*a + b + 3*c already, now add 2*d to
        // make it 2*a + b + 3*c + 2*d             # coefficient in 0~8
        //             state[x][y] += 2 * next_input[x][y]
        //     return state

        // Declare the q_mixing.
        let q_mixing = meta.selector();
        state
            .iter()
            .for_each(|column| meta.enable_equality((*column).into()));

        meta.create_gate("absorb", |meta| {
            // We do a trick which consists on multiplying an internal selector
            // which is always active by the actual `is_mixing` flag
            // which will then enable or disable the gate.
            let q_enable = {
                // We query the flag value from the `state` `Advice` column at
                // rotation curr and position = `ABSORB_NEXT_INPUTS + 1`
                // and multiply to it the active selector so that we avoid the
                // `PoisonedConstraints` and each gate equation
                // can be satisfied while enforcing the correct gate logic.
                let flag = Expression::Constant(F::one())
                    - meta.query_advice(state[ABSORB_NEXT_INPUTS], Rotation::cur());
                // Note also that we want to enable the gate when `is_mixing` is
                // false. (flag = 0). Therefore, we are doing
                // `1-flag` in order to enforce this. (See the flag computation
                // above).
                meta.query_selector(q_mixing) * flag
            };

            (0..ABSORB_NEXT_INPUTS)
                .map(|idx| {
                    let val = meta.query_advice(state[idx], Rotation::prev())
                        + (Expression::Constant(F::from(2))
                            * meta.query_advice(state[idx], Rotation::cur()));

                    let next_lane = meta.query_advice(state[idx], Rotation::next());

                    q_enable.clone() * (val - next_lane)
                })
                .collect::<Vec<_>>()
        });

        AbsorbConfig {
            q_mixing,
            state,
            _marker: PhantomData,
        }
    }

    /// Doc this
    pub fn copy_state_flag_next_inputs(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: [(Cell, F); 25],
        out_state: [F; 25],
        next_input: [F; ABSORB_NEXT_INPUTS],
        flag: (Cell, F),
    ) -> Result<([(Cell, F); 25], (Cell, F)), Error> {
        layouter.assign_region(
            || "Absorb state assignations",
            |mut region| {
                let mut offset = 0;
                // State at offset + 0
                for (idx, (cell, value)) in in_state.iter().enumerate() {
                    let new_cell = region.assign_advice(
                        || format!("assign state {}", idx),
                        self.state[idx],
                        offset,
                        || Ok(*value),
                    )?;

                    region.constrain_equal(*cell, new_cell)?;
                }

                offset += 1;
                // Enable `q_mixing` at `offset + 1`
                self.q_mixing.enable(&mut region, offset)?;
                // Assign next_mixing at offset + 1
                for (idx, lane) in next_input.iter().enumerate() {
                    region.assign_advice(
                        || format!("assign next_input {}", idx),
                        self.state[idx],
                        offset,
                        || Ok(*lane),
                    )?;
                }
                // Assign flag at last column(17th) of the offset + 1 row.
                let obtained_cell = region.assign_advice(
                    || format!("assign next_input {}", ABSORB_NEXT_INPUTS),
                    self.state[ABSORB_NEXT_INPUTS],
                    offset,
                    || Ok(flag.1),
                )?;
                region.constrain_equal(flag.0, obtained_cell)?;

                offset += 1;
                // Assign out_state at offset + 2
                let mut state: Vec<(Cell, F)> = Vec::with_capacity(25);
                for (idx, lane) in out_state.iter().enumerate() {
                    let cell = region.assign_advice(
                        || format!("assign state {}", idx),
                        self.state[idx],
                        offset,
                        || Ok(*lane),
                    )?;
                    state.push((cell, *lane));
                }
                let out_state: [(Cell, F); 25] = state
                    .try_into()
                    .expect("Unexpected into_slice conversion err");

                Ok((out_state, (obtained_cell, flag.1)))
            },
        )
    }

    /// Given a [`State`] and the `next_inputs` returns the `init_state` and
    /// `out_state` ready to be added as circuit witnesses applying `Absorb`
    /// to the input to get the output.
    ///
    /// It also returns `next_inputs` ready to be used in the circuit.
    pub(crate) fn compute_circ_states(
        state: StateBigInt,
        next_input: State,
    ) -> ([F; 25], [F; 25], [F; ABSORB_NEXT_INPUTS]) {
        let mut in_biguint = StateBigInt::default();
        let mut next_biguint = StateBigInt::default();

        let mut in_state: [Fp; 25] = [Fp::zero(); 25];
        let mut in_next_input_25: [Fp; 25] = [Fp::zero(); 25];

        for (x, y) in (0..5).cartesian_product(0..5) {
            in_biguint[(x, y)] =
                convert_b2_to_b9(state[(x, y)].clone().try_into().expect("Conversion err"));
            next_biguint[(x, y)] = convert_b2_to_b9(next_input[x][y]);
            in_state[5 * x + y] = biguint_to_f(&in_biguint[(x, y)]);
            in_next_input_25[5 * x + y] = biguint_to_f(&next_biguint[(x, y)]);
        }

        let mut in_next_input_17 = [Fp::zero(); ABSORB_NEXT_INPUTS];
        in_next_input_17.copy_from_slice(&in_next_input_25[0..ABSORB_NEXT_INPUTS]);
        let s1_arith = KeccakFArith::absorb(&in_biguint, &next_input);
        let next_input = state_to_biguint(in_next_input_25);
        (
            state_bigint_to_field::<F, 25>(in_biguint),
            state_bigint_to_field::<F, 25>(s1_arith),
            state_bigint_to_field::<F, ABSORB_NEXT_INPUTS>(next_input),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::State;
    use halo2::circuit::Layouter;
    use halo2::plonk::{Advice, Column, ConstraintSystem, Error};
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;
    use std::marker::PhantomData;

    #[test]
    fn test_absorb_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            next_input: [F; ABSORB_NEXT_INPUTS],
            is_mixing: bool,
            _marker: PhantomData<F>,
        }
        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = AbsorbConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| {
                        let column = meta.advice_column();
                        meta.enable_equality(column.into());
                        column
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                AbsorbConfig::configure(meta, state)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let val: F = (self.is_mixing as u64).into();
                let flag: (Cell, F) = layouter.assign_region(
                    || "witness_is_mixing_flag",
                    |mut region| {
                        let offset = 1;
                        let cell = region.assign_advice(
                            || "assign is_mising",
                            config.state[ABSORB_NEXT_INPUTS + 1],
                            offset,
                            || Ok(val),
                        )?;
                        Ok((cell, val))
                    },
                )?;

                // Witness `in_state`.
                let in_state: [(Cell, F); 25] = layouter.assign_region(
                    || "Witness input state",
                    |mut region| {
                        let mut state: Vec<(Cell, F)> = Vec::with_capacity(25);
                        for (idx, val) in self.in_state.iter().enumerate() {
                            let cell = region.assign_advice(
                                || "witness input state",
                                config.state[idx],
                                0,
                                || Ok(*val),
                            )?;
                            state.push((cell, *val))
                        }

                        Ok(state.try_into().unwrap())
                    },
                )?;

                config.copy_state_flag_next_inputs(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.next_input,
                    flag,
                )?;

                Ok(())
            }
        }

        let input1: State = [
            [1, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        let next_input: State = [
            [2, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        let (in_state, out_state, next_input) =
            AbsorbConfig::compute_circ_states(input1.into(), next_input);

        // With flag set to false, the gate should trigger.
        {
            // With the correct input and output witnesses, the proof should
            // pass.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state,
                next_input,
                is_mixing: false,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

            assert_eq!(prover.verify(), Ok(()));

            // With wrong input and/or output witnesses, the proof should fail
            // to be verified.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: in_state,
                next_input,
                is_mixing: false,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

            assert!(prover.verify().is_err());
        }

        // With flag set to `true`, the gate shouldn't trigger.
        // And so we can pass any witness data and the proof should pass.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: in_state,
                next_input,
                is_mixing: true,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
