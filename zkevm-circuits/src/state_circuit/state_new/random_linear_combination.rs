use crate::evm_circuit::util::RandomLinearCombination as RLC;
use eth_types::{Field, ToLittleEndian, U256};
use halo2_proofs::{
    circuit::{AssignedCell, Chip as ChipTrait, Layouter, Region},
    plonk::{ConstraintSystem, Error, Expression},
};

use crate::state_circuit::state_new::cell::AdviceCell;

#[derive(Clone, Debug)]
pub struct Config<F: Field, const N: usize> {
    pub encoded: AdviceCell<F>,
    pub bytes: [AdviceCell<F>; N],
}

impl<F: Field, const N: usize> Config<F, N> {
    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        randomness: F,
        value: U256,
    ) -> Result<AssignedCell<F, F>, Error> {
        let bytes = value.to_le_bytes();
        for (i, byte) in bytes.iter().enumerate() {
            self.bytes[i].assign(region, offset, F::from(*byte as u64))?;
        }
        self.encoded.assign(
            region,
            offset,
            RLC::random_linear_combine(bytes, randomness),
        )
    }
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

        for byte in &bytes {
            meta.lookup_any("rlc bytes fit into u8", |_| {
                vec![(byte.cur.clone(), u8_range.clone())]
            });
        }

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
