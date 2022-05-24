use super::super::arith_helpers::*;
use super::tables::FromBase9TableConfig;
use super::{
    absorb::AbsorbConfig, base_conversion::BaseConversionConfig, iota_b13::IotaB13Config,
    iota_b9::IotaB9Config,
};
use crate::common::*;
use crate::keccak_arith::KeccakFArith;
use eth_types::Field;
use halo2_proofs::circuit::{AssignedCell, Region};
use halo2_proofs::plonk::{Expression, Instance, Selector};
use halo2_proofs::poly::Rotation;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct MixingConfig<F> {
    iota_b9_config: IotaB9Config<F>,
    iota_b13_config: IotaB13Config<F>,
    absorb_config: AbsorbConfig<F>,
    base_conv_config: BaseConversionConfig<F>,
    state: [Column<Advice>; 25],
    flag: Column<Advice>,
    q_flag: Selector,
    q_out_copy: Selector,
    out_mixing: [Column<Advice>; 25],
}

impl<F: Field> MixingConfig<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        table: &FromBase9TableConfig<F>,
        round_ctant_b9: Column<Advice>,
        round_ctant_b13: Column<Advice>,
        round_constants_b9: Column<Instance>,
        round_constants_b13: Column<Instance>,
    ) -> MixingConfig<F> {
        // Allocate space for the flag column from which we will copy to all of
        // the sub-configs.
        let flag = meta.advice_column();
        meta.enable_equality(flag);

        let q_flag = meta.selector();

        meta.create_gate("Ensure flag consistency", |meta| {
            let q_flag = meta.query_selector(q_flag);

            let negated_flag = meta.query_advice(flag, Rotation::next());
            let flag = meta.query_advice(flag, Rotation::cur());
            // We do a trick which consists on multiplying an internal selector
            // which is always active by the actual `negated_flag`
            // which will then enable or disable the gate.
            //
            // Force that `flag + negated_flag = 1`.
            // This ensures that flag = !negated_flag.
            let flag_consistency =
                (flag.clone() + negated_flag.clone()) - Expression::Constant(F::one());

            // Define bool constraint for flags.
            // Based on: `(1-flag) * flag = 0` only if `flag` is boolean.
            let bool_constraint = |flag: Expression<F>| -> Expression<F> {
                (Expression::Constant(F::one()) - flag.clone()) * flag
            };

            // Add a constraint that sums up the results of the two branches
            // constraining it to be equal to `out_state`.
            [
                q_flag.clone() * flag_consistency,
                q_flag.clone() * bool_constraint(flag),
                q_flag * bool_constraint(negated_flag),
            ]
        });

        // Allocate state columns and enable copy constraints for them.
        let state: [Column<Advice>; 25] = (0..25)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // We don't mix -> Flag = false
        let iota_b9_config =
            IotaB9Config::configure(meta, state, round_ctant_b9, round_constants_b9);
        // We mix -> Flag = true
        let absorb_config = AbsorbConfig::configure(meta, state);

        let base_info = table.get_base_info(false);
        let base_conv_lane = meta.advice_column();
        let base_conv_config =
            BaseConversionConfig::configure(meta, base_info, base_conv_lane, flag);

        let iota_b13_config =
            IotaB13Config::configure(meta, state, round_ctant_b13, round_constants_b13);

        // Allocate out_mixing columns and enable copy constraints for them.
        // Offset = 0 (Non mixing)
        // Offset = 1 (Mixing)
        let out_mixing: [Column<Advice>; 25] = (0..25)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let q_out_copy = meta.selector();

        meta.create_gate("Mixing result copies and constraints", |meta| {
            let q_enable = meta.query_selector(q_out_copy);
            // Add out mixing states together multiplied by the mixing_flag.
            let negated_flag = meta.query_advice(flag, Rotation::next());
            let flag = meta.query_advice(flag, Rotation::cur());

            // Multiply by flag and negated_flag the out mixing results.
            let left_side = meta.query_advice(out_mixing[0], Rotation::cur()) * negated_flag;
            let right_side = meta.query_advice(out_mixing[0], Rotation::next()) * flag;
            let out_state = meta.query_advice(state[0], Rotation::cur());

            // We add the results of the mixing gate if/else branches multiplied
            // by it's corresponding flags so that we always
            // copy from the same place on the copy_constraints while enforcing
            // the equality with the out_state of the permutation.
            [q_enable * ((left_side + right_side) - out_state)]
        });

        MixingConfig {
            iota_b9_config,
            iota_b13_config,
            absorb_config,
            base_conv_config,
            state,
            flag,
            q_flag,
            q_out_copy,
            out_mixing,
        }
    }

    /// Enforce flag constraints
    pub fn enforce_flag_consistency(
        &self,
        layouter: &mut impl Layouter<F>,
        flag_bool: bool,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        layouter.assign_region(
            || "Flag and Negated flag assignation",
            |mut region| {
                self.q_flag.enable(&mut region, 0)?;
                // Witness `is_mixing` flag
                let flag = region.assign_advice(
                    || "witness is_mixing",
                    self.flag,
                    0,
                    || Ok(F::from(flag_bool as u64)),
                )?;

                // Witness negated `is_mixing` flag
                let negated_flag = region.assign_advice(
                    || "witness negated is_mixing",
                    self.flag,
                    1,
                    || Ok(F::from(!flag_bool as u64)),
                )?;

                Ok((flag, negated_flag))
            },
        )
    }

    /// Enforce flag constraints
    pub fn assign_out_mixing_states(
        &self,
        layouter: &mut impl Layouter<F>,
        flag_bool: bool,
        negated_flag: AssignedCell<F, F>,
        out_mixing_circ: &[AssignedCell<F, F>; 25],
        out_non_mixing_circ: &[AssignedCell<F, F>; 25],
        out_state: [F; 25],
    ) -> Result<[AssignedCell<F, F>; 25], Error> {
        layouter.assign_region(
            || "Out Mixing states assignation",
            |mut region| {
                // Enable selector
                self.q_out_copy.enable(&mut region, 0)?;

                // Copy constrain flags.
                let _flag_cell = region.assign_advice(
                    || "witness is_mixing",
                    self.flag,
                    0,
                    || Ok(F::from(flag_bool as u64)),
                )?;

                negated_flag.copy_advice(|| "witness is_mixing", &mut region, self.flag, 1)?;

                // Copy-constrain both out states.
                self.copy_state(&mut region, 0, self.out_mixing, out_non_mixing_circ)?;

                self.copy_state(&mut region, 1, self.out_mixing, out_mixing_circ)?;

                let out_state: [AssignedCell<F, F>; 25] = {
                    let mut out_vec: Vec<AssignedCell<F, F>> = vec![];
                    for (idx, lane) in out_state.iter().enumerate() {
                        let out_cell = region.assign_advice(
                            || format!("assign out_state [{}]", idx),
                            self.state[idx],
                            0,
                            || Ok(*lane),
                        )?;
                        out_vec.push(out_cell);
                    }
                    out_vec.try_into().unwrap()
                };

                Ok(out_state)
            },
        )
    }

    pub fn assign_state(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: &[AssignedCell<F, F>; 25],
        out_state: [F; 25],
        flag_bool: bool,
        next_mixing: Option<[F; NEXT_INPUTS_LANES]>,
        absolute_row: usize,
    ) -> Result<[AssignedCell<F, F>; 25], Error> {
        // Enforce flag constraints and witness them.
        let (flag, negated_flag) = self.enforce_flag_consistency(layouter, flag_bool)?;

        // If we don't mix:
        // IotaB9
        let non_mix_res = {
            let out_state_iota_b9: [F; 25] = state_bigint_to_field(KeccakFArith::iota_b9(
                &state_to_biguint(split_state_cells(in_state.clone())),
                *ROUND_CONSTANTS.last().unwrap(),
            ));

            self.iota_b9_config.last_round(
                layouter,
                in_state,
                out_state_iota_b9,
                absolute_row,
                &flag,
            )
        }?;

        // If we mix:
        // Absorb
        let (out_state_absorb_cells, _) = self.absorb_config.copy_state_flag_next_inputs(
            layouter,
            in_state,
            // Compute out_absorb state.
            state_bigint_to_field(KeccakFArith::absorb(
                &state_to_biguint(split_state_cells(in_state.clone())),
                &state_to_state_bigint::<F, NEXT_INPUTS_LANES>(next_mixing.unwrap_or_default()),
            )),
            next_mixing.unwrap_or_default(),
            flag.clone(),
        )?;

        // Base conversion assign
        let base_conv_cells =
            self.base_conv_config
                .assign_state(layouter, &out_state_absorb_cells, flag.clone())?;

        // IotaB13
        let mix_res = {
            let out_iota_b13_state: [F; 25] = state_bigint_to_field(KeccakFArith::iota_b13(
                &state_to_biguint(split_state_cells(base_conv_cells.clone())),
                *ROUND_CONSTANTS.last().unwrap(),
            ));

            self.iota_b13_config.copy_state_flag_and_assing_rc(
                layouter,
                &base_conv_cells,
                out_iota_b13_state,
                absolute_row,
                &flag,
            )
        }?;

        let mixing_res = self.assign_out_mixing_states(
            layouter,
            flag_bool,
            negated_flag,
            &mix_res,
            &non_mix_res,
            out_state,
        );

        if !flag_bool {
            Ok(non_mix_res)
        } else {
            mixing_res
        }
    }

    /// Copies the `[(Cell,F);25]` to the passed [Column<Advice>; 25].
    fn copy_state(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        columns: [Column<Advice>; 25],
        state: &[AssignedCell<F, F>; 25],
    ) -> Result<(), Error> {
        for (idx, state_cell) in state.iter().enumerate() {
            state_cell.copy_advice(
                || format!("Copy state {}", idx),
                region,
                columns[idx],
                offset,
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{State, PERMUTATION, ROUND_CONSTANTS};
    use crate::gate_helpers::biguint_to_f;
    use halo2_proofs::circuit::Layouter;
    use halo2_proofs::pairing::bn256::Fr as Fp;
    use halo2_proofs::plonk::{ConstraintSystem, Error};
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use itertools::Itertools;
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;

    #[test]
    fn test_mixing_gate() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            next_mixing: Option<[F; NEXT_INPUTS_LANES]>,
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

        impl<F: Field> Circuit<F> for MyCircuit<F> {
            type Config = MyConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                let table = FromBase9TableConfig::configure(meta);
                // Allocate space for the round constants in base-9 which is an
                // instance column
                let round_ctant_b9 = meta.advice_column();
                meta.enable_equality(round_ctant_b9);
                let round_constants_b9 = meta.instance_column();

                // Allocate space for the round constants in base-13 which is an
                // instance column
                let round_ctant_b13 = meta.advice_column();
                meta.enable_equality(round_ctant_b13);
                let round_constants_b13 = meta.instance_column();

                MyConfig {
                    mixing_conf: MixingConfig::configure(
                        meta,
                        &table,
                        round_ctant_b9,
                        round_ctant_b13,
                        round_constants_b9,
                        round_constants_b13,
                    ),
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
                    || "Mixing Wittnes assignment",
                    |mut region| {
                        // Witness `in_state`
                        let in_state: [AssignedCell<F, F>; 25] = {
                            let mut state: Vec<AssignedCell<F, F>> = Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.mixing_conf.state[idx],
                                    offset,
                                    || Ok(*val),
                                )?;
                                state.push(cell)
                            }
                            state.try_into().unwrap()
                        };

                        Ok(in_state)
                    },
                )?;

                config.mixing_conf.assign_state(
                    &mut layouter,
                    &in_state,
                    self.out_state,
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

        // Convert the next_input_b9 to base9 as it needs to be added to the
        // state in base9 too.
        let next_input = StateBigInt::from(input2);

        // Compute out mixing state (when flag = 1)
        let out_mixing_state = state_bigint_to_field(KeccakFArith::mixing(
            &in_state,
            Some(&input2),
            *ROUND_CONSTANTS.last().unwrap(),
        ));

        // Compute out non-mixing state (when flag = 0)
        let out_non_mixing_state = state_bigint_to_field(KeccakFArith::mixing(
            &in_state,
            None,
            *ROUND_CONSTANTS.last().unwrap(),
        ));

        // Add inputs in the correct format.
        let in_state = state_bigint_to_field(StateBigInt::from(input1));
        let next_mixing = Some(state_bigint_to_field(next_input));

        // Compute round constants in the correct base.
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
                next_mixing: None,
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
                out_state: in_state,
                next_mixing,
                is_mixing: false,
                round_ctant: PERMUTATION - 1,
            };

            let prover =
                MockProver::<Fp>::run(17, &circuit, vec![constants_b9, constants_b13]).unwrap();

            assert!(prover.verify().is_err());
        }
    }
}
