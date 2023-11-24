use super::{
    batch_assigner::Assigner,
    bus_builder::{BusAssigner, BusBuilder},
    bus_chip::BusTerm,
    bus_codec::{BusCodecExpr, BusCodecVal, BusMessageExpr, BusMessageF},
    util::from_isize,
    Field,
};
use crate::util::query_expression;
use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Expression, ThirdPhase},
    poly::Rotation,
};
use std::{marker::PhantomData, ops::Mul};

/// A bus operation, as expressions for circuit config.
pub type BusOpExpr<F, M> = BusOp<M, Expression<F>>;

/// A bus operation, as values for circuit assignment.
pub type BusOpF<M> = BusOp<M, isize>;

/// A bus operation.
#[derive(Clone, Debug)]
pub struct BusOp<M, C> {
    message: M,
    count: C,
}

impl<M, C> BusOp<M, C>
where
    M: Clone,
    C: Count,
{
    /// Receive a message, with the expectation that it carries a true fact. This can be a
    /// cross-circuit call answered by a `send`, or a lookup query answered by a `send_to_lookups`.
    pub fn receive(message: M) -> Self {
        Self {
            message,
            count: C::neg_one(),
        }
    }

    /// Send a message, with the responsibility to verify that it states a true fact, and the
    /// expectation that it is received exactly once somewhere else.
    pub fn send(message: M) -> Self {
        Self {
            message,
            count: C::one(),
        }
    }

    /// Expose an entry of a lookup table as a bus message, with the responsibility that it is a
    /// true fact. It can be received any number of times. This number is the `count` advice.
    pub fn send_to_lookups(message: M, count: C) -> Self {
        Self { message, count }
    }

    /// Apply a boolean condition to this operation.
    pub fn conditional(self, condition: C) -> Self {
        Self {
            message: self.message,
            count: self.count * condition,
        }
    }

    /// The message to send or receive.
    pub fn message(&self) -> M {
        self.message.clone()
    }

    /// The number of copies of the message to send (if positive) or receive (if negative).
    pub fn count(&self) -> C {
        self.count.clone()
    }
}

/// Trait usable as BusOp count (Expression or isize).
pub trait Count: Clone + Mul<Output = Self> {
    /// 1
    fn one() -> Self;
    /// -1
    fn neg_one() -> Self;
}

impl<F: Field> Count for Expression<F> {
    fn one() -> Self {
        Self::Constant(F::one())
    }
    fn neg_one() -> Self {
        Self::Constant(-F::one())
    }
}

impl Count for isize {
    fn one() -> Self {
        1
    }
    fn neg_one() -> Self {
        -1
    }
}

/// A chip to access the bus. It manages its own helper column and gives one access per row.
#[derive(Clone, Debug)]
pub struct PortChip<F> {
    helper: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: Field> PortChip<F> {
    /// Create a new bus port with a single access.
    pub fn connect<M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        enabled: Expression<F>,
        op: BusOpExpr<F, M>,
    ) -> Self {
        let helper = meta.advice_column_in(ThirdPhase);
        let helper_expr = query_expression(meta, |meta| meta.query_advice(helper, Rotation::cur()));

        Port::connect(meta, bus_builder, enabled, op, helper_expr);

        meta.annotate_lookup_any_column(helper, || "Port_helper");

        Self {
            helper,
            _marker: PhantomData,
        }
    }

    /// Assign an operation.
    pub fn assign<M: BusMessageF<F>>(
        &self,
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        op: BusOpF<M>,
    ) {
        Port::assign(bus_assigner, offset, op, self.helper, 0);
    }
}

/// Functions to add an operation to the bus.
#[derive(Clone, Debug)]
pub struct Port;

impl Port {
    /// Create a new bus port with a single operation.
    /// The helper cell can be used for something else when not enabled.
    pub fn connect<F: Field, M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        enabled: Expression<F>,
        op: BusOpExpr<F, M>,
        helper: Expression<F>,
    ) {
        let term = Self::create_term(meta, bus_builder.codec(), enabled, op, helper);
        bus_builder.add_term(term);
    }

    /// Assign an operation.
    pub fn assign<F: Field, M: BusMessageF<F>>(
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        op: BusOpF<M>,
        helper: Column<Advice>,
        rotation: isize,
    ) {
        if op.count() == 0 {
            return; // Leave the helper cell at 0.
        }

        let cmd = Box::new(PortAssigner {
            offset,
            helper,
            rotation,
            count: op.count(),
        });
        let denom = bus_assigner.codec().compress(op.message());

        bus_assigner.op_counter().track_op(&op);
        bus_assigner.batch_assigner().assign_later(cmd, denom);
    }

    /// Return the degree of the constraints given these inputs.
    pub fn degree<F: Field, M: BusMessageExpr<F>>(
        codec: &BusCodecExpr<F, M>,
        enabled: Expression<F>,
        op: BusOpExpr<F, M>,
        helper: Expression<F>,
    ) -> usize {
        let term = helper * enabled.clone();
        let [constraint] = Self::constraint(codec, enabled, op, term);
        constraint.degree()
    }

    /// Return the maximum (message_degree, count_degree), given the degrees of the constraint
    /// system and `enabled`.
    pub fn max_degrees(max_degree: usize, enabled_degree: usize) -> (usize, usize) {
        let helper_degree = 1;
        (
            max_degree - enabled_degree - helper_degree,
            max_degree - enabled_degree,
        )
    }

    fn create_term<F: Field, M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        codec: &BusCodecExpr<F, M>,
        enabled: Expression<F>,
        op: BusOpExpr<F, M>,
        helper: Expression<F>,
    ) -> BusTerm<F> {
        let term = helper * enabled.clone();

        meta.create_gate("bus access", |_| {
            Self::constraint(codec, enabled, op, term.clone())
        });

        BusTerm::verified(term)
    }

    fn constraint<F: Field, M: BusMessageExpr<F>>(
        codec: &BusCodecExpr<F, M>,
        enabled: Expression<F>,
        op: BusOpExpr<F, M>,
        term: Expression<F>,
    ) -> [Expression<F>; 1] {
        // Verify that `term = enabled * count / compress(message)`.
        //
        // With witness: helper = count / compress(message)
        //
        // If `enabled = 0`, then `term = 0` by definition. In that case, the helper cell is not
        // constrained, so it can be used for something else.
        [term * codec.compress(op.message()) - op.count() * enabled]
    }

    /// Return the witness that must be assigned to the helper cell.
    /// Very slow. Prefer `BatchAssigner::assign_later` instead.
    pub fn helper_witness<F: Field, M: BusMessageF<F>>(
        codec: &BusCodecVal<F, M>,
        op: BusOpF<M>,
    ) -> Value<F> {
        codec
            .compress(op.message())
            .map(|denom| from_isize::<F>(op.count()) * denom.invert().unwrap_or(F::zero()))
    }
}

struct PortAssigner {
    offset: usize,
    helper: Column<Advice>,
    rotation: isize,
    count: isize,
}

impl<F: Field> Assigner<F> for PortAssigner {
    fn assign(&self, region: &mut Region<'_, F>, inversed_denom: F) -> (usize, F) {
        let term = from_isize::<F>(self.count) * inversed_denom;

        region
            .assign_advice(
                || "BusPort_helper",
                self.helper,
                (self.offset as isize + self.rotation) as usize,
                || Value::known(term),
            )
            .unwrap();

        (self.offset, term)
    }
}

/// A chip to access the bus. It manages its own helper columns and gives multiple accesses per row.
#[derive(Clone, Debug)]
pub struct BusPortMulti<F> {
    // TODO: implement with as few helper columns as possible.
    ports: Vec<PortChip<F>>,
}

impl<F: Field> BusPortMulti<F> {
    /// Create and connect a new bus port with multiple accesses.
    pub fn connect<M: BusMessageExpr<F>>(
        meta: &mut ConstraintSystem<F>,
        bus_builder: &mut BusBuilder<F, M>,
        enabled: Expression<F>,
        ops: Vec<BusOpExpr<F, M>>,
    ) -> Self {
        let ports = ops
            .into_iter()
            .map(|op| PortChip::connect(meta, bus_builder, enabled.clone(), op))
            .collect();
        Self { ports }
    }

    /// Assign operations.
    pub fn assign<M: BusMessageF<F>>(
        &self,
        bus_assigner: &mut BusAssigner<F, M>,
        offset: usize,
        ops: Vec<BusOpF<M>>,
    ) {
        assert_eq!(self.ports.len(), ops.len());
        for (port, op) in self.ports.iter().zip(ops) {
            port.assign(bus_assigner, offset, op);
        }
    }
}
