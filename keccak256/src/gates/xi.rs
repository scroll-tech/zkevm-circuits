use halo2::{
    circuit::{Cell, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use pairing::arithmetic::FieldExt;
use std::{convert::TryInto, marker::PhantomData};

#[derive(Clone, Debug)]
pub struct XiConfig<F> {
    #[allow(dead_code)]
    q_enable: Selector,
    state: [Column<Advice>; 25],
    _marker: PhantomData<F>,
}

impl<F: FieldExt> XiConfig<F> {
    pub const OFFSET: usize = 2;
    // We assume state is recieved in base-9.
    pub fn configure(
        q_enable: Selector,
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 25],
    ) -> XiConfig<F> {
        meta.create_gate("xi", |meta| {
            //  state in base 9, coefficient in 0~1
            //  def xi(state: List[List[int]]):
            //      new_state = [[0 for x in range(5)] for y in range(5)]
            //      # Xi step
            //      for x in range(5):
            //          for y in range(5):
            //              # a, b, c, d are base9, coefficient in 0~1
            //              a = state[x][y]
            //              b = state[(x + 1) % 5][y]
            //              c = state[(x + 2) % 5][y]
            //              # coefficient in 0~6
            //              new_state[x][y] = 2*a + b + 3*c
            //      return new_state
            (0..5)
                .cartesian_product(0..5usize)
                .map(|(x, y)| {
                    let a = meta.query_advice(state[5 * x + y], Rotation::cur());
                    let b = meta.query_advice(state[5 * ((x + 1) % 5) + y], Rotation::cur());
                    let c = meta.query_advice(state[5 * ((x + 2) % 5) + y], Rotation::cur());
                    let next_lane = meta.query_advice(state[5 * x + y], Rotation::next());
                    meta.query_selector(q_enable)
                        * ((Expression::Constant(F::from(2)) * a
                            + b
                            + Expression::Constant(F::from(3)) * c)
                            - next_lane)
                })
                .collect::<Vec<_>>()
        });

        XiConfig {
            q_enable,
            state,
            _marker: PhantomData,
        }
    }

    pub fn assign_state(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        state: [(Cell, F); 25],
        out_state: [F; 25],
    ) -> Result<[(Cell, F); 25], Error> {
        self.q_enable.enable(region, offset)?;
        for (idx, lane) in state.iter().enumerate() {
            let obtained_cell = region.assign_advice(
                || format!("assign state {}", idx),
                self.state[idx],
                offset,
                || Ok(lane.1),
            )?;
            region.constrain_equal(lane.0, obtained_cell)?;
        }

        let mut out_vec: Vec<(Cell, F)> = vec![];
        let out_state: [(Cell, F); 25] = {
            for (idx, lane) in out_state.iter().enumerate() {
                let out_cell = region.assign_advice(
                    || format!("assign out_state {}", idx),
                    self.state[idx],
                    offset + 1,
                    || Ok(*lane),
                )?;
                out_vec.push((out_cell, *lane));
            }
            out_vec.try_into().unwrap()
        };
        Ok(out_state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith_helpers::*;
    use crate::common::*;
    use crate::gates::gate_helpers::biguint_to_f;
    use crate::keccak_arith::*;
    use halo2::circuit::Layouter;
    use halo2::plonk::{Advice, Column, ConstraintSystem, Error};
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use itertools::Itertools;
    use pairing::arithmetic::FieldExt;
    use pairing::bn256::Fr as Fp;
    use std::convert::TryInto;
    use std::marker::PhantomData;

    #[test]
    fn test_xi_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            _marker: PhantomData<F>,
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = XiConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let q_enable = meta.complex_selector();

                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| {
                        let column = meta.advice_column();
                        meta.enable_equality(column.into());
                        column
                    })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                XiConfig::configure(q_enable, meta, state)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                let offset = 0;
                let in_state = layouter.assign_region(
                    || "Wittnes & assignation",
                    |mut region| {
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

                layouter.assign_region(
                    || "assign input state",
                    |mut region| {
                        config.q_enable.enable(&mut region, offset)?;
                        config.assign_state(&mut region, offset, in_state, self.out_state)
                    },
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
        let s1_arith = KeccakFArith::xi(&in_biguint);
        let mut out_state: [Fp; 25] = [Fp::zero(); 25];
        for (x, y) in (0..5).cartesian_product(0..5) {
            out_state[5 * x + y] = biguint_to_f(&s1_arith[(x, y)]);
        }
        let circuit = MyCircuit::<Fp> {
            in_state,
            out_state,
            _marker: PhantomData,
        };

        // Test without public inputs
        let prover = MockProver::<Fp>::run(9, &circuit, vec![]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }
}
