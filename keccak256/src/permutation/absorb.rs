use crate::arith_helpers::*;
use crate::common::*;
use eth_types::Field;
use halo2_proofs::circuit::{AssignedCell, Layouter, Region};
use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use std::{convert::TryInto, marker::PhantomData};

#[derive(Clone, Debug)]
pub struct AbsorbConfig<F> {
    q_mixing: Selector,
    state: [Column<Advice>; 25],
    _marker: PhantomData<F>,
}

impl<F: Field> AbsorbConfig<F> {
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
            .for_each(|column| meta.enable_equality(*column));

        meta.create_gate("absorb", |meta| {
            // We do a trick which consists on multiplying an internal selector
            // which is always active by the actual `is_mixing` flag
            // which will then enable or disable the gate.
            let q_enable = {
                // We query the flag value from the `state` `Advice` column at
                // rotation curr and position = `NEXT_INPUTS_LANES + 1`
                // and multiply to it the active selector so that we avoid the
                // `PoisonedConstraints` and each gate equation
                // can be satisfied while enforcing the correct gate logic.
                //
                // This is boolean-constrained outside of `AbsorbConfig` by `MixingConfig`.
                let flag = meta.query_advice(state[NEXT_INPUTS_LANES], Rotation::cur());
                // Note also that we want to enable the gate when `is_mixing` is
                // true. (flag = 1). See the flag computation above.
                meta.query_selector(q_mixing) * flag
            };

            (0..NEXT_INPUTS_LANES)
                .map(|idx| {
                    let val = meta.query_advice(state[idx], Rotation::prev())
                        + (Expression::Constant(F::from(A4))
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

    fn assign_next_inp_and_flag(
        &self,
        region: &mut Region<F>,
        offset: usize,
        flag: AssignedCell<F, F>,
        next_input: [F; NEXT_INPUTS_LANES],
    ) -> Result<AssignedCell<F, F>, Error> {
        // Generate next_input in base-9.
        let mut next_mixing = state_to_biguint::<F, NEXT_INPUTS_LANES>(next_input);
        for (x, y) in (0..5).cartesian_product(0..5) {
            // Assign only first 17 values.
            if x >= 3 && y >= 1 {
                break;
            }
            next_mixing[(x, y)] = convert_b2_to_b9(next_mixing[(x, y)].clone().try_into().unwrap())
        }
        let next_input = state_bigint_to_field::<F, NEXT_INPUTS_LANES>(next_mixing);

        // Assign next_mixing.
        for (idx, lane) in next_input.iter().enumerate() {
            region.assign_advice(
                || format!("assign next_input {}", idx),
                self.state[idx],
                offset,
                || Ok(*lane),
            )?;
        }

        // Assign flag at last column(17th).
        let flag_assig_cell = flag.copy_advice(
            || format!("assign next_input {}", NEXT_INPUTS_LANES),
            region,
            self.state[NEXT_INPUTS_LANES],
            offset,
        )?;

        Ok(flag_assig_cell)
    }

    /// Doc this $
    pub fn copy_state_flag_next_inputs(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: &[AssignedCell<F, F>; 25],
        out_state: [F; 25],
        // Passed in base-2 and converted internally after witnessing it.
        next_input: [F; NEXT_INPUTS_LANES],
        flag: AssignedCell<F, F>,
    ) -> Result<([AssignedCell<F, F>; 25], AssignedCell<F, F>), Error> {
        layouter.assign_region(
            || "Absorb state assignations",
            |mut region| {
                let mut offset = 0;
                // State at offset + 0
                for (idx, in_state) in in_state.iter().enumerate() {
                    in_state.copy_advice(
                        || format!("assign state {}", idx),
                        &mut region,
                        self.state[idx],
                        offset,
                    )?;
                }

                offset += 1;
                // Enable `q_mixing` at `offset + 1`
                self.q_mixing.enable(&mut region, offset)?;

                // Assign `next_inputs` and flag.
                let flag =
                    self.assign_next_inp_and_flag(&mut region, offset, flag.clone(), next_input)?;

                offset += 1;
                // Assign out_state at offset + 2
                let mut state: Vec<AssignedCell<F, F>> = Vec::with_capacity(25);
                for (idx, lane) in out_state.iter().enumerate() {
                    let assig_cell = region.assign_advice(
                        || format!("assign state {}", idx),
                        self.state[idx],
                        offset,
                        || Ok(*lane),
                    )?;
                    state.push(assig_cell);
                }
                let out_state: [AssignedCell<F, F>; 25] = state
                    .try_into()
                    .expect("Unexpected into_slice conversion err");

                Ok((out_state, flag))
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::State;
    use crate::keccak_arith::KeccakFArith;
    use halo2_proofs::circuit::Layouter;
    use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error};
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use itertools::Itertools;
    use pairing::bn256::Fr as Fp;
    use pairing::group::ff::PrimeField;
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;
    use std::marker::PhantomData;

    #[test]
    fn test_absorb_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            next_input: [F; NEXT_INPUTS_LANES],
            is_mixing: bool,
            _marker: PhantomData<F>,
        }
        impl<F: Field> Circuit<F> for MyCircuit<F>
        where
            F: PrimeField<Repr = [u8; 32]>,
        {
            type Config = AbsorbConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| {
                        let column = meta.advice_column();
                        meta.enable_equality(column);
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
                let flag: AssignedCell<F, F> = layouter.assign_region(
                    || "witness_is_mixing_flag",
                    |mut region| {
                        let offset = 1;
                        region.assign_advice(
                            || "assign is_mixing",
                            config.state[NEXT_INPUTS_LANES + 1],
                            offset,
                            || Ok(val),
                        )
                    },
                )?;

                // Witness `in_state`.
                let in_state: [AssignedCell<F, F>; 25] = layouter.assign_region(
                    || "Witness input state",
                    |mut region| {
                        let mut state: Vec<AssignedCell<F, F>> = Vec::with_capacity(25);
                        for (idx, val) in self.in_state.iter().enumerate() {
                            let cell = region.assign_advice(
                                || "witness input state",
                                config.state[idx],
                                0,
                                || Ok(*val),
                            )?;
                            state.push(cell)
                        }

                        Ok(state.try_into().unwrap())
                    },
                )?;

                config.copy_state_flag_next_inputs(
                    &mut layouter,
                    &in_state,
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

        let input2: State = [
            [2, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];

        // Convert the input to base9 as the gadget already expects it like this
        // since it's always the output of IotaB9.
        let mut in_state = StateBigInt::from(input1);
        for (x, y) in (0..5).cartesian_product(0..5) {
            in_state[(x, y)] = convert_b2_to_b9(input1[x][y])
        }

        let in_state = state_bigint_to_field(in_state);
        let out_state =
            state_bigint_to_field(KeccakFArith::absorb(&StateBigInt::from(input1), &input2));

        let next_input = state_bigint_to_field(StateBigInt::from(input2));

        // With flag set to true, the gate should trigger.
        {
            // With the correct input and output witnesses, the proof should
            // pass.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state,
                next_input,
                is_mixing: true,
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
                is_mixing: true,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

            assert!(prover.verify().is_err());
        }

        // With flag set to `false`, the gate shouldn't trigger.
        // And so we can pass any witness data and the proof should pass.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: in_state,
                next_input,
                is_mixing: false,
                _marker: PhantomData,
            };

            let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

            assert_eq!(prover.verify(), Ok(()));
        }
    }
}
