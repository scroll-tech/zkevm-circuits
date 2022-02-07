use crate::arith_helpers::*;
use halo2::{
    circuit::{Cell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct ThetaConfig<F> {
    q_enable: Selector,
    pub(crate) state: [Column<Advice>; 25],
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ThetaConfig<F> {
    pub const OFFSET: usize = 2;
    pub fn configure(
        q_enable: Selector,
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 25],
    ) -> ThetaConfig<F> {
        meta.create_gate("theta", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let column_sum: Vec<Expression<F>> = (0..5)
                .map(|x| {
                    let state_x0 = meta.query_advice(state[5 * x], Rotation::cur());
                    let state_x1 = meta.query_advice(state[5 * x + 1], Rotation::cur());
                    let state_x2 = meta.query_advice(state[5 * x + 2], Rotation::cur());
                    let state_x3 = meta.query_advice(state[5 * x + 3], Rotation::cur());
                    let state_x4 = meta.query_advice(state[5 * x + 4], Rotation::cur());
                    state_x0 + state_x1 + state_x2 + state_x3 + state_x4
                })
                .collect::<Vec<_>>();

            (0..5)
                .cartesian_product(0..5)
                .map(|(x, y)| {
                    let new_state = meta.query_advice(state[5 * x + y], Rotation::next());
                    let old_state = meta.query_advice(state[5 * x + y], Rotation::cur());
                    let right = old_state
                        + column_sum[(x + 4) % 5].clone()
                        + Expression::Constant(F::from(B13.into()))
                            * column_sum[(x + 1) % 5].clone();
                    q_enable.clone() * (new_state - right)
                })
                .collect::<Vec<_>>()
        });

        ThetaConfig {
            q_enable,
            state,
            _marker: PhantomData,
        }
    }

    pub fn assign_state(
        &self,
        layouter: &mut impl Layouter<F>,
        state: [(Cell, F); 25],
        out_state: [F; 25],
    ) -> Result<[(Cell, F); 25], Error> {
        layouter.assign_region(
            || "Theta gate",
            |mut region| {
                let offset = 0;
                self.q_enable.enable(&mut region, offset)?;

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
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::*;
    use crate::gates::gate_helpers::biguint_to_f;
    use crate::keccak_arith::*;
    use halo2::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use itertools::Itertools;
    use pairing::{arithmetic::FieldExt, bn256::Fr as Fp};
    use std::convert::TryInto;
    use std::marker::PhantomData;

    #[test]
    fn test_theta_gates() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            _marker: PhantomData<F>,
        }
        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = ThetaConfig<F>;
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

                ThetaConfig::configure(q_enable, meta, state)
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

                let _ = config.assign_state(&mut layouter, in_state, self.out_state);

                Ok(())
            }
        }

        let input1: State = [
            [1, 0, 0, 0, 0],
            [0, 0, 0, 9223372036854775808, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 0, 0],
        ];
        let mut in_biguint = StateBigInt::default();
        let mut in_state: [Fp; 25] = [Fp::zero(); 25];

        for (x, y) in (0..5).cartesian_product(0..5) {
            in_biguint[(x, y)] = convert_b2_to_b13(input1[x][y]);
            in_state[5 * x + y] = biguint_to_f(&in_biguint[(x, y)]);
        }
        let s1_arith = KeccakFArith::theta(&in_biguint);
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

        let mut out_state2 = out_state;
        out_state2[0] = Fp::from(5566u64);

        let circuit2 = MyCircuit::<Fp> {
            in_state,
            out_state: out_state2,
            _marker: PhantomData,
        };

        let prover = MockProver::<Fp>::run(9, &circuit2, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
