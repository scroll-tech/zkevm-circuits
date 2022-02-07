use halo2::{
    circuit::{Cell, Layouter},
    plonk::{Advice, Column, ConstraintSystem, Error},
};

use crate::gates::base_conversion::BaseConversionConfig;
use crate::gates::tables::BaseInfo;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub(crate) struct StateBaseConversion<F> {
    bi: BaseInfo<F>,
    bccs: [BaseConversionConfig<F>; 25],
    state: [Column<Advice>; 25],
}

impl<F: FieldExt> StateBaseConversion<F> {
    /// Side effect: parent flag is enabled
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; 25],
        bi: BaseInfo<F>,
        flag: Column<Advice>,
    ) -> Self {
        meta.enable_equality(flag.into());
        let bccs: [BaseConversionConfig<F>; 25] = state
            .iter()
            .map(|&lane| BaseConversionConfig::configure(meta, bi.clone(), lane, flag))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self { bi, bccs, state }
    }

    pub(crate) fn assign_region(
        &self,
        layouter: &mut impl Layouter<F>,
        state: [(Cell, F); 25],
        flag: (Cell, F),
    ) -> Result<[(Cell, F); 25], Error> {
        let state: Result<Vec<(Cell, F)>, Error> = state
            .iter()
            .zip(self.bccs.iter())
            .map(|(&lane, config)| {
                let output = config.assign_region(layouter, lane, flag)?;
                Ok(output)
            })
            .into_iter()
            .collect();
        let state = state?;
        let state: [(Cell, F); 25] = state.try_into().unwrap();
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith_helpers::convert_b2_to_b13;
    use crate::gates::{gate_helpers::biguint_to_f, tables::FromBinaryTableConfig};
    use halo2::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::MockProver,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    };
    use pairing::arithmetic::FieldExt;
    use pairing::bn256::Fr as Fp;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_state_base_conversion() {
        // We have to use a MyConfig because:
        // We need to load the table
        #[derive(Debug, Clone)]
        struct MyConfig<F> {
            flag: Column<Advice>,
            state: [Column<Advice>; 25],
            table: FromBinaryTableConfig<F>,
            conversion: StateBaseConversion<F>,
        }
        impl<F: FieldExt> MyConfig<F> {
            pub fn configure(meta: &mut ConstraintSystem<F>) -> Self {
                let table = FromBinaryTableConfig::configure(meta);
                let state: [Column<Advice>; 25] = (0..25)
                    .map(|_| meta.advice_column())
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                let flag = meta.advice_column();
                let bi = table.get_base_info(false);
                let conversion = StateBaseConversion::configure(meta, state, bi, flag);
                Self {
                    flag,
                    state,
                    table,
                    conversion,
                }
            }

            pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
                self.table.load(layouter)
            }

            pub fn assign_region(
                &self,
                layouter: &mut impl Layouter<F>,
                input: [F; 25],
            ) -> Result<[F; 25], Error> {
                let flag_value = F::one();
                let (state, flag) = layouter.assign_region(
                    || "Input state",
                    |mut region| {
                        let state: [(Cell, F); 25] = input
                            .iter()
                            .enumerate()
                            .map(|(idx, &value)| {
                                let cell = region
                                    .assign_advice(
                                        || format!("State {}", idx),
                                        self.state[idx],
                                        0,
                                        || Ok(value),
                                    )
                                    .unwrap();
                                (cell, value)
                            })
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();
                        let flag =
                            region.assign_advice(|| "Flag", self.flag, 0, || Ok(flag_value))?;
                        Ok((state, flag))
                    },
                )?;
                let output_state =
                    self.conversion
                        .assign_region(layouter, state, (flag, flag_value))?;
                let output_state: [F; 25] = output_state
                    .iter()
                    .map(|&(_, value)| value)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap();
                Ok(output_state)
            }
        }

        #[derive(Default)]
        struct MyCircuit<F> {
            in_state: [F; 25],
            out_state: [F; 25],
        }
        impl<F: FieldExt> Circuit<F> for MyCircuit<F> {
            type Config = MyConfig<F>;
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
                config.load(&mut layouter)?;
                let out_state = config.assign_region(&mut layouter, self.in_state)?;
                assert_eq!(out_state, self.out_state);
                Ok(())
            }
        }
        let in_state: [[u64; 5]; 5] = [
            [4398046511105, 8, 2, 268436480, 2305844108725321728],
            [
                17592186044416,
                52776560230400,
                544,
                68719493120,
                2199023255552,
            ],
            [
                4398046543872,
                1152921504606846984,
                262144,
                1024,
                1099511627780,
            ],
            [0, 52776558133248, 514, 268451840, 2305845208236949504],
            [17592186077184, 1152921504608944128, 262176, 68719476736, 4],
        ];

        let in_state_flat = in_state.iter().flatten().collect::<Vec<_>>();
        let in_state: [Fp; 25] = in_state_flat
            .iter()
            .map(|&x| Fp::from(*x))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let out_state: [Fp; 25] = in_state_flat
            .iter()
            .map(|&x| biguint_to_f::<Fp>(&convert_b2_to_b13(*x)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let circuit = MyCircuit::<Fp> {
            in_state,
            out_state,
        };
        let prover = MockProver::<Fp>::run(17, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()));
    }
}
