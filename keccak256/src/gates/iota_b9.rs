use crate::arith_helpers::*;
use crate::common::*;
use crate::gates::gate_helpers::biguint_to_f;
use crate::keccak_arith::*;
use halo2::circuit::Cell;
use halo2::circuit::Layouter;
use halo2::plonk::Instance;
use halo2::{
    circuit::Region,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct IotaB9Config<F> {
    q_not_last: Selector,
    q_last: Selector,
    state: [Column<Advice>; 25],
    pub(crate) round_ctant_b9: Column<Advice>,
    pub(crate) round_constants: Column<Instance>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> IotaB9Config<F> {
    pub const OFFSET: usize = 2;
    // We assume state is recieved in base-9.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 25],
        round_ctant_b9: Column<Advice>,
        round_constants: Column<Instance>,
    ) -> IotaB9Config<F> {
        let q_not_last = meta.selector();
        let q_last = meta.selector();

        // Enable copy constraints over PI and the Advices.
        meta.enable_equality(round_ctant_b9.into());
        meta.enable_equality(round_constants.into());

        // def iota_b9(state: List[List[int], round_constant_base9: int):
        //     d = round_constant_base9
        //     # state[0][0] has 2*a + b + 3*c already, now add 2*d to make it
        // 2*a + b + 3*c + 2*d     # coefficient in 0~8
        //     state[0][0] += 2*d
        //     return state
        meta.create_gate("iota_b9 in steady state", |meta| {
            let q_enable = meta.query_selector(q_not_last);
            let state_00 = meta.query_advice(state[0], Rotation::cur())
                + (Expression::Constant(F::from(2))
                    * meta.query_advice(round_ctant_b9, Rotation::cur()));
            let next_lane = meta.query_advice(state[0], Rotation::next());
            vec![q_enable * (state_00 - next_lane)]
        });

        meta.create_gate("iota_b9 in final round", |meta| {
            // Note also that we want to enable the gate when `is_mixing` is
            // false. (flag = 0). Therefore, we are doing
            // `1-flag` in order to enforce this. (See the flag computation
            // below).
            let q_enable = {
                let flag = Expression::Constant(F::one())
                    - meta.query_advice(round_ctant_b9, Rotation::next());
                meta.query_selector(q_last) * flag
            };

            let state_00 = meta.query_advice(state[0], Rotation::cur())
                + (Expression::Constant(F::from(2))
                    * meta.query_advice(round_ctant_b9, Rotation::cur()));
            let next_lane = meta.query_advice(state[0], Rotation::next());
            vec![q_enable * (state_00 - next_lane)]
        });

        IotaB9Config {
            q_not_last,
            q_last,
            state,
            round_ctant_b9,
            round_constants,
            _marker: PhantomData,
        }
    }

    /// Doc this
    pub fn not_last_round(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: [(Cell, F); 25],
        out_state: [F; 25],
        absolute_row: usize,
    ) -> Result<[(Cell, F); 25], Error> {
        layouter.assign_region(
            || "Assign IotaB9 for steady step",
            |mut region| {
                let mut offset = 0;
                // Enable `q_not_last`.
                self.q_not_last.enable(&mut region, offset)?;

                // Assign state
                self.assign_in_state(&mut region, offset, in_state)?;

                // Assign round_constant at offset + 0
                self.assign_round_ctant_b9(&mut region, offset, absolute_row)?;

                offset += 1;
                // Assign out_state at offset + 1
                self.assign_out_state(&mut region, offset, out_state)
            },
        )
    }

    /// Assignment for iota_b9 in the context of the final round, where
    /// the prover must witness an `is_mixing` flag in the round_ctant_b9
    /// advice column.
    pub fn last_round(
        &self,
        layouter: &mut impl Layouter<F>,
        state: [(Cell, F); 25],
        out_state: [F; 25],
        absolute_row: usize,
        flag: (Cell, F),
    ) -> Result<[(Cell, F); 25], Error> {
        // Copies the `[(Cell,F);25]` to the `state` Advice column.
        let copy_state = |region: &mut Region<'_, F>,
                          offset: usize,
                          in_state: [(Cell, F); 25]|
         -> Result<(), Error> {
            for (idx, (cell, value)) in in_state.iter().enumerate() {
                let new_cell = region.assign_advice(
                    || format!("copy in_state {}", idx),
                    self.state[idx],
                    offset,
                    || Ok(*value),
                )?;

                region.constrain_equal(*cell, new_cell)?;
            }

            Ok(())
        };

        // Copies the `is_mixing` flag to the `round_ctant_b9` Advice column.
        let copy_flag =
            |region: &mut Region<'_, F>, offset: usize, flag: (Cell, F)| -> Result<(), Error> {
                let obtained_cell = region.assign_advice(
                    || format!("assign is_mixing flag {:?}", flag.1),
                    self.round_ctant_b9,
                    offset,
                    || Ok(flag.1),
                )?;
                region.constrain_equal(flag.0, obtained_cell)?;

                Ok(())
            };

        layouter.assign_region(
            || "Assign IotaB9 for final round step",
            |mut region| {
                let mut offset = 0;

                // Enable `q_last`.
                self.q_last.enable(&mut region, offset)?;

                // Copy state at offset + 0
                copy_state(&mut region, offset, state)?;
                // Assign round_ctant at offset + 0.
                self.assign_round_ctant_b9(&mut region, offset, absolute_row)?;

                offset += 1;
                // Copy flag at `round_ctant_b9` at offset + 1
                copy_flag(&mut region, offset, flag)?;
                // Assign out state at offset + 1
                self.assign_out_state(&mut region, offset, out_state)
            },
        )
    }

    // Assign `[(Cell,F);25]` at `state` `Advice` column at the provided offset
    // enforcing equality between Cells.
    fn assign_in_state(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        state: [(Cell, F); 25],
    ) -> Result<[(Cell, F); 25], Error> {
        let mut out_vec: Vec<(Cell, F)> = vec![];
        let out_state: [(Cell, F); 25] = {
            for (idx, lane) in state.iter().enumerate() {
                let out_cell = region.assign_advice(
                    || format!("assign in_state[{}] and enforce equalty", idx),
                    self.state[idx],
                    offset,
                    || Ok(lane.1),
                )?;
                // Enforce Cell equalty
                region.constrain_equal(lane.0, out_cell)?;
                // Push new generated Cell to out state vec with it's
                // corresponding value.
                out_vec.push((out_cell, lane.1));
            }
            out_vec.try_into().unwrap()
        };
        Ok(out_state)
    }

    // Assign `[F;25]` at `state` `Advice` column at the provided offset.
    fn assign_out_state(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        state: [F; 25],
    ) -> Result<[(Cell, F); 25], Error> {
        let mut out_vec: Vec<(Cell, F)> = vec![];
        let out_state: [(Cell, F); 25] = {
            for (idx, lane) in state.iter().enumerate() {
                let out_cell = region.assign_advice(
                    || format!("assign out state {}", idx),
                    self.state[idx],
                    offset,
                    || Ok(*lane),
                )?;
                out_vec.push((out_cell, *lane));
            }
            out_vec.try_into().unwrap()
        };
        Ok(out_state)
    }

    /// Assigns the ROUND_CONSTANTS_BASE_9 to the `absolute_row` passed as an
    /// absolute instance column. Returns the new offset after the
    /// assigment.
    fn assign_round_ctant_b9(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        absolute_row: usize,
    ) -> Result<(), Error> {
        region.assign_advice_from_instance(
            // `absolute_row` is the absolute offset in the overall Region
            // where the Column is laying.
            || format!("assign round_ctant_b9 {}", absolute_row),
            self.round_constants,
            absolute_row,
            self.round_ctant_b9,
            offset,
        )?;

        Ok(())
    }

    /// Given a [`StateBigInt`] returns the `init_state` and `out_state` ready
    /// to be added as circuit witnesses applying `IotaB9` to the input to
    /// get the output.
    pub(crate) fn compute_circ_states(state: StateBigInt) -> ([F; 25], [F; 25]) {
        let mut in_biguint = StateBigInt::default();
        let mut in_state: [F; 25] = [F::zero(); 25];

        for (x, y) in (0..5).cartesian_product(0..5) {
            in_biguint[(x, y)] =
                convert_b2_to_b9(state[(x, y)].clone().try_into().expect("Conversion err"));
            in_state[5 * x + y] = biguint_to_f(&in_biguint[(x, y)]);
        }

        // Compute out state
        let round_ctant = ROUND_CONSTANTS[PERMUTATION - 1];
        let s1_arith = KeccakFArith::iota_b9(&in_biguint, round_ctant);
        (in_state, state_bigint_to_field::<F, 25>(s1_arith))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{PERMUTATION, ROUND_CONSTANTS};
    use crate::gates::gate_helpers::biguint_to_f;
    use halo2::circuit::Layouter;
    use halo2::plonk::{Advice, Column, ConstraintSystem, Error};
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use pairing::bn256::Fr as Fp;
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;
    use std::marker::PhantomData;

    #[test]
    fn test_iota_b9_gate_last_round() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            // This usize is indeed pointing the exact row of the
            // ROUND_CTANTS_B9 we want to use.
            round_ctant: usize,
            // The flag acts like a selector that turns ON/OFF the gate
            flag: bool,
            _marker: PhantomData<F>,
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = IotaB9Config<F>;
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

                let round_ctant_b9 = meta.advice_column();
                // Allocate space for the round constants in base-9 which is an
                // instance column
                let round_ctants = meta.instance_column();

                // Since we're not using a selector and want to test IotaB9 with
                // the Mixing step, we make q_enable query
                // the round_ctant_b9 at `Rotation::next`.
                IotaB9Config::configure(meta, state, round_ctant_b9, round_ctants)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let offset: usize = 0;

                let val: F = (self.flag as u64).into();
                let (in_state, flag) = layouter.assign_region(
                    || "Wittnes & assignation",
                    |mut region| {
                        // Witness `is_mixing` flag
                        let cell = region.assign_advice(
                            || "witness is_mixing",
                            config.round_ctant_b9,
                            offset + 1,
                            || Ok(val),
                        )?;
                        let flag = (cell, val);

                        // Witness `state`
                        let in_state: [(Cell, F); 25] = {
                            let mut state: Vec<(Cell, F)> = Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.state[idx],
                                    offset,
                                    || Ok(*val),
                                )?;
                                state.push((cell, *val))
                            }
                            state.try_into().unwrap()
                        };
                        Ok((in_state, flag))
                    },
                )?;

                // Assign `in_state`, `out_state`, round and flag
                config.last_round(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.round_ctant,
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
        let (in_state, out_state) = IotaB9Config::compute_circ_states(input1.into());

        let constants: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
            .collect();

        // (flag = 0) -> Out state is checked as constraints are applied.
        // Providing the correct `out_state` should pass the verification.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state,
                round_ctant: PERMUTATION - 1,
                flag: false,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![constants.clone()]).unwrap();

            assert_eq!(prover.verify(), Ok(()));
        }

        // (flag = 0) -> Out state is checked as constraints are applied.
        // Providing the wrong `out_state` should make the verification fail.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                // Add wrong out_state that should cause the verification to
                // fail.
                out_state: in_state,
                round_ctant: PERMUTATION - 1,
                flag: false,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![constants.clone()]).unwrap();

            let _ = prover.verify().is_err();
        }

        // (flag = 1)
        let circuit = MyCircuit::<Fp> {
            in_state,
            // Use a nonsensical out_state to verify that the gate is not
            // checked.
            out_state: in_state,
            round_ctant: PERMUTATION - 1,
            flag: true,
            _marker: PhantomData,
        };

        let prover = MockProver::<Fp>::run(9, &circuit, vec![constants]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }

    #[test]
    fn test_iota_b9_gate_not_last_round() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            round_ctant_b9: usize,
            _marker: PhantomData<F>,
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = IotaB9Config<F>;
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
                let round_ctant_b9 = meta.advice_column();
                // Allocate space for the round constants in base-9 which is an
                // instance column
                let round_ctants = meta.instance_column();

                IotaB9Config::configure(meta, state, round_ctant_b9, round_ctants)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let in_state = layouter.assign_region(
                    || "Wittnes & assignation",
                    |mut region| {
                        let offset: usize = 0;

                        // Witness `state`
                        let in_state: [(Cell, F); 25] = {
                            let mut state: Vec<(Cell, F)> = Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.state[idx],
                                    offset,
                                    || Ok(*val),
                                )?;
                                state.push((cell, *val))
                            }
                            state.try_into().unwrap()
                        };
                        Ok(in_state)
                    },
                )?;

                // Start IotaB9 config without copy at offset = 0
                config.not_last_round(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.round_ctant_b9,
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
        let mut in_biguint = StateBigInt::default();
        let mut in_state: [Fp; 25] = [Fp::zero(); 25];

        for (x, y) in (0..5).cartesian_product(0..5) {
            in_biguint[(x, y)] = convert_b2_to_b9(input1[x][y]);
            in_state[5 * x + y] = biguint_to_f(&in_biguint[(x, y)]);
        }

        // Test for the 25 rounds
        for (round_idx, round_val) in ROUND_CONSTANTS.iter().enumerate().take(PERMUTATION) {
            // Compute out state
            let s1_arith = KeccakFArith::iota_b9(&in_biguint, *round_val);
            let out_state = state_bigint_to_field::<Fp, 25>(s1_arith);

            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state,
                round_ctant_b9: round_idx,
                _marker: PhantomData,
            };

            let constants: Vec<Fp> = ROUND_CONSTANTS
                .iter()
                .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
                .collect();

            let prover = MockProver::<Fp>::run(9, &circuit, vec![constants]).unwrap();

            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
