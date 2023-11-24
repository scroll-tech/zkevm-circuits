use super::{bus_builder::BusAssigner, bus_codec::BusMessageF, Field};
use crate::util::{assign_global, Expr};
use halo2_proofs::{
    circuit::{Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, ThirdPhase},
    poly::Rotation,
};

/// A term of the bus sum check.
#[derive(Clone, Debug)]
pub struct BusTerm<F>(Expression<F>);

impl<F> BusTerm<F> {
    /// Wrap an expression to indicate that it was properly constructed as a bus term.
    pub fn verified(term: Expression<F>) -> Self {
        Self(term)
    }
}

impl<F: Field> Expr<F> for BusTerm<F> {
    fn expr(&self) -> Expression<F> {
        self.0.clone()
    }
}

/// BusConfig
#[derive(Clone, Debug)]
pub struct BusConfig {
    enabled: Column<Fixed>,
    is_first: Column<Fixed>,
    acc: Column<Advice>,
}

impl BusConfig {
    /// Create a new bus.
    pub fn new<F: Field>(cs: &mut ConstraintSystem<F>, terms: &[BusTerm<F>]) -> Self {
        let enabled = cs.fixed_column();
        let is_first = cs.fixed_column();
        let acc = cs.advice_column_in(ThirdPhase);

        cs.create_gate("bus sum check", |cs| {
            let not_last = cs.query_fixed(enabled, Rotation::next());
            let enabled = cs.query_fixed(enabled, Rotation::cur());
            let is_first = cs.query_fixed(is_first, Rotation::cur());

            let acc_next = cs.query_advice(acc, Rotation::next());
            let acc = cs.query_advice(acc, Rotation::cur());

            // The sum of terms on the current row.
            let sum = terms
                .iter()
                .fold(0.expr(), |acc, term| acc + term.0.clone());
            let next_or_zero = not_last * acc_next;
            let diff_or_zero = enabled * (next_or_zero - acc.clone());

            [
                // If is_first, then initialize: `acc = 0`.
                is_first * acc,
                // If not last, the terms go into accumulator: `∑terms + acc = acc_next`
                // If last, the final accumulator is zero:     `∑terms + acc = 0`
                // If not enabled, the terms add up to zero:   `∑terms = 0`
                sum - diff_or_zero,
            ]
        });

        cs.annotate_lookup_any_column(enabled, || "Bus_enabled");
        cs.annotate_lookup_any_column(is_first, || "Bus_is_first");
        cs.annotate_lookup_any_column(acc, || "Bus_acc");

        Self {
            enabled,
            is_first,
            acc,
        }
    }

    /// Assign the accumulator values from a BusAssigner.
    pub fn finish_assigner<F: Field, M: BusMessageF<F>>(
        &self,
        layouter: &mut impl Layouter<F>,
        bus_assigner: BusAssigner<F, M>,
    ) -> Result<(), Error> {
        assign_global(
            layouter,
            || "Bus_accumulator",
            |mut region| self.assign(&mut region, bus_assigner.n_rows(), bus_assigner.terms()),
        )
    }

    /// Assign the accumulator values, from the sum of terms per row.
    pub fn assign<F: Field>(
        &self,
        region: &mut Region<'_, F>,
        n_rows: usize,
        terms: Value<&[F]>,
    ) -> Result<(), Error> {
        /*assert_eq!(
            region.global_offset(0),
            0,
            "The bus requires a global region"
        );*/

        region.assign_fixed(
            || "Bus_is_first",
            self.is_first,
            0,
            || Value::known(F::one()),
        )?;

        for offset in 0..n_rows {
            region.assign_fixed(
                || "Bus_enable",
                self.enabled,
                offset,
                || Value::known(F::one()),
            )?;
        }

        terms.map(|terms| {
            assert!(terms.len() <= n_rows, "Bus terms out-of-bound");
            let mut acc = F::zero();

            for offset in 0..n_rows {
                region
                    .assign_advice(|| "Bus_acc", self.acc, offset, || Value::known(acc))
                    .unwrap();

                if let Some(term) = terms.get(offset) {
                    acc += term;
                }
            }
        });
        Ok(())
    }
}
