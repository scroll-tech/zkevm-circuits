//! The BusLookup chip exposes entries from a table as messages on the bus.

use crate::util::query_expression;

use super::{
    bus_builder::{BusAssigner, BusBuilder},
    bus_codec::{BusMessageExpr, BusMessageF},
    bus_port::{BusOp, BusOpF, PortChip},
    util::from_isize,
    Field,
};
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression},
    poly::Rotation,
};

/// BusLookup exposes a table as a lookup through the bus.
#[derive(Clone, Debug)]
pub struct BusLookupChip<F> {
    port: PortChip<F>,
    count: Column<Advice>,
}

impl<F: Field> BusLookupChip<F> {
    /// Create and connect a new BusLookup circuit from the expressions of message and count.
    pub fn connect<M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        enabled: Expression<F>,
        message: M,
    ) -> Self {
        let count = meta.advice_column();
        let count_expr = query_expression(meta, |meta| meta.query_advice(count, Rotation::cur()));

        let port = PortChip::connect(
            meta,
            bus_builder,
            enabled,
            BusOp::send_to_lookups(message, count_expr),
        );

        meta.annotate_lookup_any_column(count, || "BusLookup_count");

        Self { port, count }
    }

    /// Assign a lookup operation from message. The count is discovered from the BusAssigner.
    pub fn assign<M: BusMessageF<F>>(
        &self,
        region: &mut Region<'_, F>,
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        message: M,
    ) -> Result<(), Error> {
        let count = bus_assigner.op_counter().count_receives(&message);
        self.assign_op(
            region,
            bus_assigner,
            offset,
            BusOp::send_to_lookups(message, count),
        )
    }

    /// Assign a lookup operation from message and count.
    pub fn assign_op<M: BusMessageF<F>>(
        &self,
        region: &mut Region<'_, F>,
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        op: BusOpF<M>,
    ) -> Result<(), Error> {
        region.assign_advice(
            || "BusLookup",
            self.count,
            offset,
            || Value::known(from_isize::<F>(op.count())),
        )?;
        self.port.assign(bus_assigner, offset, op);
        Ok(())
    }
}
