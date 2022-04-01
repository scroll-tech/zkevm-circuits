use eth_types::Field;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use std::marker::PhantomData;

#[derive(Clone, Copy)]
pub struct Config {
    // Can these be TableColumn's?
    // https://github.com/zcash/halo2/blob/642efc1536d3ea2566b04814bd60a00c4745ae22/halo2_proofs/src/plonk/circuit.rs#L266
    pub u8: Column<Fixed>,
    pub u10: Column<Fixed>,
    pub u16: Column<Fixed>,
}

#[derive(Clone)]
pub struct Queries<F> {
    pub u8: Expression<F>,
    pub u10: Expression<F>,
    pub u16: Expression<F>,
}

impl<F: Field> Queries<F> {
    pub fn new(meta: &mut VirtualCells<'_, F>, c: Config) -> Self {
        Self {
            u8: meta.query_fixed(c.u8, Rotation::cur()),
            u10: meta.query_fixed(c.u10, Rotation::cur()),
            u16: meta.query_fixed(c.u16, Rotation::cur()),
        }
    }
}

// impl Config {
//     pub fn u8_range(&self) -> Expression<F> {
//         self.u8.cur.clone()
//     }
// }

// This doesn't seem like it needs to exist?
pub struct Chip<F: Field> {
    config: Config,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> {
    pub fn construct(config: Config) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> Config {
        Config {
            u8: meta.fixed_column(),
            u10: meta.fixed_column(),
            u16: meta.fixed_column(),
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        for (column, exponent) in [
            (self.config.u8, 8),
            (self.config.u10, 10),
            (self.config.u16, 16),
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
