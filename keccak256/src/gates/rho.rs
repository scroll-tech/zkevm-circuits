use crate::gates::{
    rho_checks::{LaneRotateConversionConfig, OverflowCheckConfig},
    tables::{Base13toBase9TableConfig, SpecialChunkTableConfig},
};

use halo2::{
    circuit::{Cell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct RhoConfig<F> {
    state: [Column<Advice>; 25],
    lane_configs: [LaneRotateConversionConfig<F>; 25],
    overflow_check_config: OverflowCheckConfig<F>,
    base13_to_9_table: Base13toBase9TableConfig<F>,
    special_chunk_table: SpecialChunkTableConfig<F>,
}

impl<F: FieldExt> RhoConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 25],
        base13_to_9_table: Base13toBase9TableConfig<F>,
        special_chunk_table: SpecialChunkTableConfig<F>,
    ) -> Self {
        let lane_configs: [LaneRotateConversionConfig<F>; 25] = state
            .iter()
            .enumerate()
            .map(|(idx, &lane)| {
                LaneRotateConversionConfig::configure(
                    meta,
                    idx,
                    lane,
                    &base13_to_9_table,
                    &special_chunk_table,
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let overflow_detector_cols = lane_configs
            .iter()
            .map(|config| config.overflow_detector)
            .collect();
        let overflow_check_config =
            OverflowCheckConfig::configure(meta, overflow_detector_cols);
        Self {
            state,
            lane_configs,
            overflow_check_config,
            base13_to_9_table,
            special_chunk_table,
        }
    }
    pub fn assign_rotation_checks(
        &self,
        layouter: &mut impl Layouter<F>,
        state: [(Cell, F); 25],
    ) -> Result<[(Cell, F); 25], Error> {
        type R<F> = ((Cell, F), Vec<(Cell, F)>, Vec<(Cell, F)>);
        let lane_and_ods: Result<Vec<R<F>>, Error> = state
            .iter()
            .zip(self.lane_configs.iter())
            .map(|(&lane, lane_config)| -> Result<R<F>, Error> {
                let (out_lane, step2_od, step3_od) =
                    lane_config.assign_region(layouter, lane)?;
                Ok((out_lane, step2_od, step3_od))
            })
            .into_iter()
            .collect();
        let lane_and_ods = lane_and_ods?;
        let lane_and_ods: [R<F>; 25] = lane_and_ods.try_into().unwrap();
        let next_state = lane_and_ods.clone().map(|(out_lane, _, _)| out_lane);

        let step2_od_join = lane_and_ods
            .iter()
            .map(|(_, step2_od, _)| step2_od.clone())
            .flatten()
            .collect::<Vec<_>>();
        let step3_od_join = lane_and_ods
            .iter()
            .map(|(_, _, step3_od)| step3_od.clone())
            .flatten()
            .collect::<Vec<_>>();
        self.overflow_check_config.assign_region(
            &mut layouter.namespace(|| "Final overflow check"),
            step2_od_join,
            step3_od_join,
        )?;
        Ok(next_state)
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.base13_to_9_table.load(layouter)?;
        self.special_chunk_table.load(layouter)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith_helpers::*;
    use crate::common::*;
    use crate::gates::gate_helpers::*;
    use crate::gates::tables::{
        Base13toBase9TableConfig, SpecialChunkTableConfig,
    };
    use crate::keccak_arith::*;
    use halo2::circuit::Layouter;
    use halo2::plonk::{Advice, Column, ConstraintSystem, Error};
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use itertools::Itertools;
    use pairing::arithmetic::FieldExt;
    use pairing::bn256::Fr as Fp;
    use std::convert::TryInto;
    #[test]
    fn test_rho_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
        }
        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = RhoConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| meta.advice_column())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();

                let base13_to_9 = Base13toBase9TableConfig::configure(meta);
                let special_chunk_table =
                    SpecialChunkTableConfig::configure(meta);
                RhoConfig::configure(
                    meta,
                    state,
                    base13_to_9,
                    special_chunk_table,
                )
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                config.load(&mut layouter)?;
                let state = layouter.assign_region(
                    || "assign input state",
                    |mut region| {
                        let offset = 0;
                        let state: [(Cell, F); 25] = self
                            .in_state
                            .iter()
                            .enumerate()
                            .map(|(idx, &value)| {
                                let cell = region
                                    .assign_advice(
                                        || format!("lane {}", idx),
                                        config.state[idx],
                                        offset,
                                        || Ok(value),
                                    )
                                    .unwrap();
                                (cell, value)
                            })
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();
                        Ok(state)
                    },
                )?;
                let next_state =
                    config.assign_rotation_checks(&mut layouter, state)?;
                assert_eq!(next_state.map(|lane| lane.1), self.out_state);
                Ok(())
            }
        }

        let input1: State = [
            [102, 111, 111, 98, 97],
            [114, 0, 5, 0, 0],
            [0, 0, 0, 0, 0],
            [0, 0, 0, 5, 0],
            [0, 0, 0, 0, 0],
        ];
        let mut in_biguint = StateBigInt::default();
        let mut in_state: [Fp; 25] = [Fp::zero(); 25];

        for (x, y) in (0..5).cartesian_product(0..5) {
            in_biguint[(x, y)] = convert_b2_to_b13(input1[x][y]);
        }
        let s0_arith = KeccakFArith::theta(&in_biguint);
        for (x, y) in (0..5).cartesian_product(0..5) {
            in_state[5 * x + y] = biguint_to_f(&s0_arith[(x, y)]);
        }
        let s1_arith = KeccakFArith::rho(&s0_arith);
        let mut out_state: [Fp; 25] = [Fp::zero(); 25];
        for (x, y) in (0..5).cartesian_product(0..5) {
            out_state[5 * x + y] = biguint_to_f(&s1_arith[(x, y)]);
        }
        let circuit = MyCircuit::<Fp> {
            in_state,
            out_state,
        };
        let k = 15;
        #[cfg(feature = "dev-graph")]
        {
            use plotters::prelude::*;
            let root =
                BitMapBackend::new("rho-test-circuit.png", (16384, 65536))
                    .into_drawing_area();
            root.fill(&WHITE).unwrap();
            let root = root.titled("Rho", ("sans-serif", 60)).unwrap();
            halo2::dev::CircuitLayout::default()
                .render(k, &circuit, &root)
                .unwrap();
        }
        // Test without public inputs
        let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();

        assert_eq!(prover.verify(), Ok(()));
    }
}
