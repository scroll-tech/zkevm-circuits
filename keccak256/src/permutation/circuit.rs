use crate::{
    arith_helpers::*,
    common::{NEXT_INPUTS_LANES, PERMUTATION, ROUND_CONSTANTS},
    keccak_arith::*,
    permutation::{
        base_conversion::BaseConversionConfig, iota_b9::IotaB9Config, mixing::MixingConfig,
        pi::pi_gate_permutation, rho::RhoConfig, tables::FromBase9TableConfig, theta::ThetaConfig,
        xi::XiConfig,
    },
};
use eth_types::Field;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub struct KeccakFConfig<F: Field> {
    theta_config: ThetaConfig<F>,
    rho_config: RhoConfig<F>,
    xi_config: XiConfig<F>,
    iota_b9_config: IotaB9Config<F>,
    from_b9_table: FromBase9TableConfig<F>,
    base_conversion_config: BaseConversionConfig<F>,
    mixing_config: MixingConfig<F>,
    pub state: [Column<Advice>; 25],
    q_out: Selector,
    base_conv_activator: Column<Advice>,
}

impl<F: Field> KeccakFConfig<F> {
    // We assume state is received in base-9.
    pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let state = (0..25)
            .map(|_| {
                let column = meta.advice_column();
                meta.enable_equality(column);
                column
            })
            .collect_vec()
            .try_into()
            .unwrap();

        // theta
        let theta_config = ThetaConfig::configure(meta.selector(), meta, state);
        // rho
        let rho_config = RhoConfig::configure(meta, state);
        // xi
        let xi_config = XiConfig::configure(meta.selector(), meta, state);

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

        // Iotab9
        let iota_b9_config =
            IotaB9Config::configure(meta, state, round_ctant_b9, round_constants_b9);

        // Allocate space for the activation flag of the base_conversion.
        let base_conv_activator = meta.advice_column();
        meta.enable_equality(base_conv_activator);
        // Base conversion config.
        let from_b9_table = FromBase9TableConfig::configure(meta);
        let base_info = from_b9_table.get_base_info(false);
        let base_conv_lane = meta.advice_column();
        let base_conversion_config =
            BaseConversionConfig::configure(meta, base_info, base_conv_lane, base_conv_activator);

        // Mixing will make sure that the flag is binary constrained and that
        // the out state matches the expected result.
        let mixing_config = MixingConfig::configure(
            meta,
            &from_b9_table,
            round_ctant_b9,
            round_ctant_b13,
            round_constants_b9,
            round_constants_b13,
        );

        // Allocate the `out state correctness` gate selector
        let q_out = meta.selector();
        // Constraint the out of the mixing gate to be equal to the out state
        // announced.
        meta.create_gate("Constraint out_state correctness", |meta| {
            (0..25usize)
                .into_iter()
                .map(|idx| {
                    let q_out = meta.query_selector(q_out);
                    let out_mixing = meta.query_advice(state[idx], Rotation::cur());
                    let out_expected_state = meta.query_advice(state[idx], Rotation::next());
                    q_out * (out_mixing - out_expected_state)
                })
                .collect_vec()
        });

        KeccakFConfig {
            theta_config,
            rho_config,
            xi_config,
            iota_b9_config,
            from_b9_table,
            base_conversion_config,
            mixing_config,
            state,
            q_out,
            base_conv_activator,
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.rho_config.load(layouter)?;
        self.from_b9_table.load(layouter)
    }

    pub fn assign_all(
        &self,
        layouter: &mut impl Layouter<F>,
        in_state: [AssignedCell<F, F>; 25],
        out_state: [F; 25],
        flag: bool,
        next_mixing: Option<[F; NEXT_INPUTS_LANES]>,
    ) -> Result<[AssignedCell<F, F>; 25], Error> {
        let mut state = in_state;

        // First 23 rounds
        for (round_idx, round_val) in ROUND_CONSTANTS.iter().enumerate().take(PERMUTATION) {
            // State in base-13
            // theta
            state = {
                // Apply theta outside circuit
                let out_state =
                    KeccakFArith::theta(&state_to_biguint(split_state_cells(state.clone())));
                let out_state = state_bigint_to_field(out_state);
                // assignment
                self.theta_config
                    .assign_state(layouter, &state, out_state)?
            };

            // rho
            state = {
                // assignment
                self.rho_config.assign_rotation_checks(layouter, &state)?
            };
            // Outputs in base-9 which is what Pi requires

            // Apply Pi permutation
            state = pi_gate_permutation(state.clone());

            // xi
            state = {
                // Apply xi outside circuit
                let out_state =
                    KeccakFArith::xi(&state_to_biguint(split_state_cells(state.clone())));
                let out_state = state_bigint_to_field(out_state);
                // assignment
                self.xi_config.assign_state(layouter, &state, out_state)?
            };

            // Last round before Mixing does not run IotaB9 nor BaseConversion
            if round_idx == PERMUTATION - 1 {
                break;
            }

            // iota_b9
            state = {
                let out_state = KeccakFArith::iota_b9(
                    &state_to_biguint(split_state_cells(state.clone())),
                    *round_val,
                );
                let out_state = state_bigint_to_field(out_state);
                self.iota_b9_config
                    .not_last_round(layouter, &state, out_state, round_idx)?
            };

            // The resulting state is in Base-9 now. We now convert it to
            // base_13 which is what Theta requires again at the
            // start of the loop.
            state = {
                let activation_flag = layouter.assign_region(
                    || "Base conversion enable",
                    |mut region| {
                        region.assign_advice(
                            || "Enable base conversion",
                            self.base_conv_activator,
                            0,
                            || Ok(F::one()),
                        )
                    },
                )?;

                self.base_conversion_config
                    .assign_state(layouter, &state, activation_flag)?
            }
        }

        // Mixing step
        let mix_res = KeccakFArith::mixing(
            &state_to_biguint(split_state_cells(state.clone())),
            next_mixing
                .map(|state| state_to_state_bigint::<F, NEXT_INPUTS_LANES>(state))
                .as_ref(),
            *ROUND_CONSTANTS.last().unwrap(),
        );

        let mix_res = self.mixing_config.assign_state(
            layouter,
            &state,
            state_bigint_to_field(mix_res),
            flag,
            next_mixing,
            // Last round = PERMUTATION - 1
            PERMUTATION - 1,
        )?;

        self.constrain_out_state(layouter, &mix_res, out_state)
    }

    pub fn constrain_out_state(
        &self,
        layouter: &mut impl Layouter<F>,
        out_mixing: &[AssignedCell<F, F>; 25],
        out_state: [F; 25],
    ) -> Result<[AssignedCell<F, F>; 25], Error> {
        layouter.assign_region(
            || "Constraint out_state and out_mixing",
            |mut region| {
                // Enable selector at offset = 0
                self.q_out.enable(&mut region, 0)?;

                // Allocate out_mixing at offset = 0 in `state` column.
                self.copy_state(&mut region, 0, self.state, out_mixing)?;

                // Witness out_state at offset = 1 in `state` column.
                let out_state: [AssignedCell<F, F>; 25] = {
                    let mut out_vec: Vec<AssignedCell<F, F>> = vec![];
                    for (idx, lane) in out_state.iter().enumerate() {
                        let out_cell = region.assign_advice(
                            || format!("assign out_state [{}]", idx),
                            self.state[idx],
                            1,
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

    /// Copies the `state` cells to the passed [Column<Advice>; 25].
    fn copy_state(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        columns: [Column<Advice>; 25],
        state: &[AssignedCell<F, F>; 25],
    ) -> Result<(), Error> {
        for (idx, cell) in state.iter().enumerate() {
            cell.copy_advice(
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
    use crate::common::{State, NEXT_INPUTS_LANES, ROUND_CONSTANTS};
    use crate::gate_helpers::biguint_to_f;
    use halo2_proofs::circuit::Layouter;
    use halo2_proofs::pairing::bn256::Fr as Fp;
    use halo2_proofs::plonk::{ConstraintSystem, Error};
    use halo2_proofs::{circuit::SimpleFloorPlanner, dev::MockProver, plonk::Circuit};
    use pretty_assertions::assert_eq;
    use std::convert::TryInto;

    // TODO: Remove ignore once this can run in the CI without hanging.
    #[ignore]
    #[test]
    fn test_keccak_round() {
        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
            next_mixing: Option<[F; NEXT_INPUTS_LANES]>,
            // flag
            is_mixing: bool,
        }

        impl<F: Field> Circuit<F> for MyCircuit<F> {
            type Config = KeccakFConfig<F>;
            type FloorPlanner = SimpleFloorPlanner;

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
                Self::Config::configure(meta)
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<F>,
            ) -> Result<(), Error> {
                // Load the table
                config.load(&mut layouter)?;
                let offset: usize = 0;

                let in_state = layouter.assign_region(
                    || "Keccak round Wittnes & flag assignation",
                    |mut region| {
                        // Witness `state`
                        let in_state: [AssignedCell<F, F>; 25] = {
                            let mut state: Vec<AssignedCell<F, F>> = Vec::with_capacity(25);
                            for (idx, val) in self.in_state.iter().enumerate() {
                                let cell = region.assign_advice(
                                    || "witness input state",
                                    config.state[idx],
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

                config.assign_all(
                    &mut layouter,
                    in_state,
                    self.out_state,
                    self.is_mixing,
                    self.next_mixing,
                )?;
                Ok(())
            }
        }

        let in_state: State = [
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

        let mut in_state_biguint = StateBigInt::default();

        // Generate in_state as `[Fp;25]`
        let mut in_state_fp: [Fp; 25] = [Fp::zero(); 25];
        for (x, y) in (0..5).cartesian_product(0..5) {
            in_state_fp[5 * x + y] = biguint_to_f(&convert_b2_to_b13(in_state[x][y]));
            in_state_biguint[(x, y)] = convert_b2_to_b13(in_state[x][y]);
        }

        // Compute out_state_mix
        let mut out_state_mix = in_state_biguint.clone();
        KeccakFArith::permute_and_absorb(&mut out_state_mix, Some(&next_input));

        // Compute out_state_non_mix
        let mut out_state_non_mix = in_state_biguint.clone();
        KeccakFArith::permute_and_absorb(&mut out_state_non_mix, None);

        // Generate out_state as `[Fp;25]`
        let out_state_mix: [Fp; 25] = state_bigint_to_field(out_state_mix);
        let out_state_non_mix: [Fp; 25] = state_bigint_to_field(out_state_non_mix);

        // Generate next_input (tho one that is not None) in the form `[F;17]`
        // Generate next_input as `[Fp;NEXT_INPUTS_LANES]`
        let next_input_fp: [Fp; NEXT_INPUTS_LANES] =
            state_bigint_to_field(StateBigInt::from(next_input));

        let constants_b13: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b13(*num)))
            .collect();

        let constants_b9: Vec<Fp> = ROUND_CONSTANTS
            .iter()
            .map(|num| biguint_to_f(&convert_b2_to_b9(*num)))
            .collect();

        // When we pass no `mixing_inputs`, we perform the full keccak round
        // ending with Mixing executing IotaB9
        {
            // With the correct input and output witnesses, the proof should
            // pass.
            let circuit = MyCircuit::<Fp> {
                in_state: in_state_fp,
                out_state: out_state_non_mix,
                next_mixing: None,
                is_mixing: false,
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
                in_state: out_state_non_mix,
                out_state: out_state_non_mix,
                next_mixing: None,
                is_mixing: true,
            };

            let prover = MockProver::<Fp>::run(
                17,
                &circuit,
                vec![constants_b9.clone(), constants_b13.clone()],
            )
            .unwrap();

            assert!(prover.verify().is_err());
        }

        // When we pass `mixing_inputs`, we perform the full keccak round ending
        // with Mixing executing Absorb + base_conversion + IotaB13
        {
            let circuit = MyCircuit::<Fp> {
                in_state: in_state_fp,
                out_state: out_state_mix,
                next_mixing: Some(next_input_fp),
                is_mixing: true,
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
                in_state: out_state_non_mix,
                out_state: out_state_non_mix,
                next_mixing: Some(next_input_fp),
                is_mixing: true,
            };

            let prover =
                MockProver::<Fp>::run(17, &circuit, vec![constants_b9, constants_b13]).unwrap();

            assert!(prover.verify().is_err());
        }
    }
}
