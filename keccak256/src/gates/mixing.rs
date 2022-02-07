use super::super::arith_helpers::*;
use super::tables::FromBase9TableConfig;
use super::{
    absorb::{AbsorbConfig, ABSORB_NEXT_INPUTS},
    iota_b13::IotaB13Config,
    iota_b9::IotaB9Config,
    state_conversion::StateBaseConversion,
};
use crate::common::*;
use halo2::{
    circuit::{Cell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use num_bigint::BigUint;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct MixingConfig<F> {
    iota_b9_config: IotaB9Config<F>,
    iota_b13_config: IotaB13Config<F>,
    absorb_config: AbsorbConfig<F>,
    base_conv_config: StateBaseConversion<F>,
    state: [Column<Advice>; 25],
    flag: Column<Advice>,
}

impl<F: FieldExt> MixingConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        table: FromBase9TableConfig<F>,
    ) -> MixingConfig<F> {
        // Allocate space for the flag column from which we will copy to all of
        // the sub-configs.
        let flag = meta.advice_column();
        meta.enable_equality(flag.into());

        // Allocate state columns and enable copy constraints for them.
        let state: [Column<Advice>; 25] = (0..25)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column.into());
                column
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // Allocate space for the round constants in base-9 which is an
        // instance column
        let round_ctant_b9 = meta.advice_column();
        let round_constants_b9 = meta.instance_column();

        // Allocate space for the round constants in base-13 which is an
        // instance column
        let round_ctant_b13 = meta.advice_column();
        let round_constants_b13 = meta.instance_column();

        // We mix -> Flag = true
        let iota_b9_config =
            IotaB9Config::configure(meta, state, round_ctant_b9, round_constants_b9);
        // We don't mix -> Flag = false
        let absorb_config = AbsorbConfig::configure(meta, state);
        meta.enable_equality(flag.into());
        let base_info = table.get_base_info(false);
        let base_conv_config = StateBaseConversion::configure(meta, state, base_info, flag);

        let iota_b13_config =
            IotaB13Config::configure(meta, state, round_ctant_b13, round_constants_b13);

        MixingConfig {
            iota_b9_config,
            iota_b13_config,
            absorb_config,
            base_conv_config,
            state,
            flag,
        }
    }

    pub fn assign_state(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: [(Cell, F); 25],
        out_state: [F; 25],
        out_absorb_state: Option<[F; 25]>,
        flag: bool,
        next_mixing: Option<[F; ABSORB_NEXT_INPUTS]>,
        absolute_row: usize,
    ) -> Result<[(Cell, F); 25], Error> {
        // Witness the mixing flag.
        let val: F = (flag as u64).into();
        let flag_cell = layouter.assign_region(
            || "Mixing witnessing",
            |mut region| {
                let offset: usize = 0;
                // Witness `is_mixing` flag.
                let cell =
                    region.assign_advice(|| "witness is_mixing", self.flag, offset, || Ok(val))?;
                Ok((cell, val))
            },
        )?;

        // If we mix:
        let mix_res =
            self.iota_b9_config
                .last_round(layouter, in_state, out_state, absolute_row, flag_cell);

        // If we don't mix:
        // Absorb
        let (out_state_absorb_cells, flag_cell) = self.absorb_config.copy_state_flag_next_inputs(
            layouter,
            in_state,
            out_absorb_state.unwrap_or_default(),
            next_mixing.unwrap_or_default(),
            flag_cell,
        )?;

        // Base conversion assign
        let base_conv_cells =
            self.base_conv_config
                .assign_region(layouter, out_state_absorb_cells, flag_cell)?;

        // IotaB13
        let non_mix_res = self.iota_b13_config.copy_state_flag_and_assing_rc(
            layouter,
            base_conv_cells,
            out_state,
            absolute_row,
            flag_cell,
        );

        if flag {
            mix_res
        } else {
            non_mix_res
        }
    }

    /// Given an `in_state` as [`State`] and `next_inputs` as [`Option<State>`],
    /// compute the result of the mixing step depending on the mixing flag
    /// returning the `in_state`, `out_state` and `next_inputs` (if any) on a
    /// way on which can be directly witnessed in the circuit.
    pub(crate) fn compute_circ_states(
        in_state: State,
        next_inputs: Option<State>,
    ) -> (
        [F; 25],
        [F; 25],
        Option<[F; 25]>,
        Option<[F; ABSORB_NEXT_INPUTS]>,
    ) {
        if let Some(next_inputs) = next_inputs {
            // We mix, therefore we apply Absorb
            let (in_state, out_absorb, next_inputs) =
                AbsorbConfig::compute_circ_states(in_state.into(), next_inputs);

            // Base conversion
            let big_uint_out = state_to_biguint::<F>(out_absorb)
                .xy
                .iter()
                .map(|elem| convert_b9_lane_to_b13(elem.clone()))
                .collect::<Vec<BigUint>>();

            let big_uint_out = StateBigInt { xy: big_uint_out };
            let out_base_conv: [F; 25] = state_bigint_to_field(big_uint_out);

            // IotaB13
            let (_, out_state) = IotaB13Config::compute_circ_states(
                state_to_state_bigint::<F, 25>(out_base_conv).into(),
            );
            (in_state, out_state, Some(out_absorb), Some(next_inputs))
        } else {
            // We don't mix, therefore we run IotaB9
            let (in_state, out_state) = IotaB9Config::compute_circ_states(in_state.into());
            (in_state, out_state, None, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{State, PERMUTATION, ROUND_CONSTANTS};
    use crate::gates::gate_helpers::biguint_to_f;
    use halo2::circuit::Layouter;
    use halo2::plonk::{ConstraintSystem, Error};
    use halo2::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use pairing::bn256::Fr as Fp;
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;

    #[test]
    fn test_mixing_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            out_state_absorb: Option<[F; 25]>,
            next_mixing: Option<[F; ABSORB_NEXT_INPUTS]>,
            // This usize is indeed pointing the exact row of the
            // ROUND_CTANTS we want to use.
            round_ctant: usize,
            // flag
            is_mixing: bool,
        }

        #[derive(Clone)]
        struct MyConfig<F> {
            mixing_conf: MixingConfig<F>,
            table: FromBase9TableConfig<F>,
        }

        impl<F: FieldExt> MyConfig<F> {
            pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
                self.table.load(layouter)?;
                Ok(())
            }
        }

        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let table = FromBase9TableConfig::configure(meta);
                MyConfig {
                    mixing_conf: MixingConfig::configure(meta, table.clone()),
                    table,
                }
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                // Load the table
                config.table.load(&mut layouter)?;
                let offset: usize = 0;

                let in_state = layouter.assign_region(
                    || "Wittnes & assignation",
                    |mut region| {
                        // Witness `state`
                        let in_state: [(Cell, F); 25] = {
                            let mut state: Vec<(Cell, F)> = Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.mixing_conf.state[idx],
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

                config.mixing_conf.assign_state(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.out_state_absorb,
                    self.is_mixing,
                    self.next_mixing,
                    self.round_ctant,
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

        let (in_state, out_mixing_state, out_absorb, next_mixing) =
            MixingConfig::compute_circ_states(input1, Some(next_input));

        let (_, out_non_mixing_state, _, _) = MixingConfig::compute_circ_states(input1, None);

        let constants_b13: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b13(*num)))
            .collect();

        let constants_b9: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
            .collect();

        // With flag set to false, we don't mix. And so we should obtain Absorb
        // + base_conv + IotaB13 result
        {
            // With the correct input and output witnesses, the proof should
            // pass.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: out_mixing_state,
                next_mixing,
                out_state_absorb: out_absorb,
                is_mixing: true,
                round_ctant: PERMUTATION - 1,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9.clone(), constants_b13.clone()],
            )
            .unwrap();

            assert_eq!(prover.verify(), Ok(()));

            // With wrong input and/or output witnesses, the proof should fail
            // to be verified.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: out_non_mixing_state,
                next_mixing,
                out_state_absorb: out_absorb,
                is_mixing: true,
                round_ctant: PERMUTATION - 1,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9.clone(), constants_b13.clone()],
            )
            .unwrap();

            assert!(prover.verify().is_err());
        }

        // With flag set to `false`, we don't mix. And so we should obtain
        // IotaB9 application as result.
        {
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: out_non_mixing_state,
                next_mixing,
                out_state_absorb: out_absorb,
                is_mixing: false,
                round_ctant: PERMUTATION - 1,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9.clone(), constants_b13.clone()],
            )
            .unwrap();

            assert_eq!(prover.verify(), Ok(()));

            // With wrong input and/or output witnesses, the proof should fail
            // to be verified.
            let circuit = MyCircuit::<Fp> {
                in_state,
                out_state: out_non_mixing_state,
                next_mixing,
                out_state_absorb: out_absorb,
                is_mixing: true,
                round_ctant: PERMUTATION - 1,
            };

            let prover =
                MockProver::<Fp>::run(17, &circuit, vec![constants_b9, constants_b13]).unwrap();

            assert!(prover.verify().is_err());
        }
    }
}
