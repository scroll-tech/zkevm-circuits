use eth_types::{Address, Field, ToScalar};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{ConstraintSystem, Error, Expression},
};

use super::cell::FixedCell;

#[derive(Clone)]
pub struct Config<F: Field> {
    u8: FixedCell<F>,
    u10: FixedCell<F>,
    u16: FixedCell<F>,
}

impl<F: Field> Config<F> {
    pub fn u8_range(&self) -> Expression<F> {
        self.u8.cur.clone()
    }
}

// This doesn't seem like it needs to exist?
pub struct Chip<F: Field> {
    config: Config<F>,
}

impl<F: Field> Chip<F> {
    pub fn construct(config: Config<F>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Config<F> {
        Config {
            u8: FixedCell::new(meta),
            u10: FixedCell::new(meta),
            u16: FixedCell::new(meta),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (column, exponent) in [
            (self.config.u8.column, 8),
            (self.config.u10.column, 10),
            (self.config.u16.column, 16),
        ] {
            layouter.assign_region(
                || format!("assign u{} fixed column", exponent),
                |mut region| {
                    for i in 0..(1 << exponent) {
                        region.assign_fixed(
                            || format!("assign {} in u{} fixed column", i, exponent),
                            column,
                            i,
                            || Ok(F::from(i as u64)),
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
        Ok(())
    }
}
