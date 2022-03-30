use crate::evm_circuit::util::RandomLinearCombination as RLC;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Chip as ChipTrait, Layouter},
    plonk::{ConstraintSystem, Error, Expression},
};
// use halo2_proofs::plonk::Expression;

use crate::state_circuit::state_new::cell::AdviceCell;

#[derive(Clone, Debug)]
pub struct Config<F: Field, const N: usize> {
    encoded: AdviceCell<F>,
    bytes: [AdviceCell<F>; N],
}

pub struct Chip<F: Field, const N: usize> {
    config: Config<F, N>,
}

impl<F: Field, const N: usize> Chip<F, N> {
    pub fn construct(config: Config<F, N>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        selector: Expression<F>,
        u8_range: Expression<F>,
        power_of_randomness: &[Expression<F>],
    ) -> Config<F, N> {
        let bytes = [0; N].map(|_| AdviceCell::new(meta));
        let encoded = AdviceCell::new(meta);

        meta.lookup_any("rlc bytes fit into u8", |_| {
            bytes
                .iter()
                .map(|byte| (byte.cur.clone(), u8_range.clone()))
                .collect()
        });

        meta.create_gate("rlc encoded value matches claimed bytes", |_| {
            vec![
                selector
                    * (encoded.clone().cur
                        - RLC::random_linear_combine_expr(
                            bytes.clone().map(|byte| byte.cur.clone()),
                            power_of_randomness,
                        )),
            ]
        });

        Config { encoded, bytes }
    }

    pub fn load(&self, _layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

impl<F: Field, const N: usize> ChipTrait<F> for Chip<F, N> {
    type Config = Config<F, N>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}
