use super::super::super::{
    BusMappingLookup, BytecodeLookup, Constraint, FixedLookup, Lookup,
};
use crate::util::Expr;
use halo2::{arithmetic::FieldExt, plonk::Expression};

// Default max degree allowed in all expressions passing through the ConstraintBuilder.
const DEFAULT_MAX_DEGREE: usize = 2usize.pow(3) + 1;
// Degree added for expressions used in lookups.
const LOOKUP_DEGREE: usize = 3;

#[derive(Clone, Debug)]
pub struct ConstraintBuilder<F> {
    pub expressions: Vec<Expression<F>>,
    pub(crate) lookups: Vec<Lookup<F>>,
    pub stack_offset: i32,
    pub call_id: Option<Expression<F>>,
    pub max_degree: usize,
}

impl<F: FieldExt> ConstraintBuilder<F> {
    pub(crate) fn with_call_id(call_id: Expression<F>) -> Self {
        Self::init(DEFAULT_MAX_DEGREE, Some(call_id))
    }

    pub(crate) fn with_max_degree(mag_degree: usize) -> Self {
        Self::init(mag_degree, None)
    }

    pub(crate) fn default() -> Self {
        Self::init(DEFAULT_MAX_DEGREE, None)
    }

    fn init(max_degree: usize, call_id: Option<Expression<F>>) -> Self {
        ConstraintBuilder {
            expressions: vec![],
            lookups: vec![],
            stack_offset: 0,
            call_id,
            max_degree,
        }
    }

    // Common

    pub(crate) fn require_boolean(&mut self, value: Expression<F>) {
        self.add_expression(value.clone() * (1.expr() - value));
    }

    pub(crate) fn require_zero(&mut self, expression: Expression<F>) {
        self.add_expression(expression);
    }

    pub(crate) fn require_equal(
        &mut self,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) {
        self.add_expression((lhs) - (rhs));
    }

    pub(crate) fn require_in_range(
        &mut self,
        value: Expression<F>,
        range: u64,
    ) {
        let table = match range {
            16 => FixedLookup::Range16,
            17 => FixedLookup::Range17,
            32 => FixedLookup::Range32,
            256 => FixedLookup::Range256,
            _ => unimplemented!(),
        };
        self.add_fixed_lookup(table, [value, 0.expr(), 0.expr()]);
    }

    pub(crate) fn require_in_set(
        &mut self,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        let mut expression = 1.expr();
        for set_value in set.iter() {
            expression = expression * (value.clone() - set_value.clone());
        }
        self.add_expression(expression);
    }

    // Stack

    pub(crate) fn stack_pop(&mut self, value: Expression<F>) {
        self.stack_lookup(self.stack_offset.expr(), value, false);
        self.stack_offset += 1;
    }

    pub(crate) fn stack_push(&mut self, value: Expression<F>) {
        self.stack_offset -= 1;
        self.stack_lookup(self.stack_offset.expr(), value, true);
    }

    pub(crate) fn stack_lookup(
        &mut self,
        index_offset: Expression<F>,
        value: Expression<F>,
        is_write: bool,
    ) {
        self.validate_lookup_expression(&value);
        self.add_lookup(Lookup::BusMappingLookup(BusMappingLookup::Stack {
            index_offset,
            value,
            is_write,
        }));
    }

    // Memory

    pub(crate) fn memory_write(
        &mut self,
        address: Expression<F>,
        bytes: Vec<Expression<F>>,
    ) {
        self.memory_lookup(address, bytes, true)
    }

    pub(crate) fn memory_read(
        &mut self,
        address: Expression<F>,
        bytes: Vec<Expression<F>>,
    ) {
        self.memory_lookup(address, bytes, false);
    }

    fn memory_lookup(
        &mut self,
        address: Expression<F>,
        bytes: Vec<Expression<F>>,
        is_write: bool,
    ) {
        self.validate_lookup_expression(&self.call_id.clone().unwrap());
        self.validate_lookup_expression(&address);
        for idx in 0..bytes.len() {
            self.validate_lookup_expression(&bytes[idx]);
            self.add_lookup(Lookup::BusMappingLookup(
                BusMappingLookup::Memory {
                    call_id: self.call_id.clone().unwrap(),
                    index: address.clone()
                        + Expression::Constant(F::from_u64(idx as u64)),
                    value: bytes[bytes.len() - 1 - idx].clone(),
                    is_write,
                },
            ));
        }
    }

    // Validation

    pub(crate) fn validate_expression(&self, expression: &Expression<F>) {
        self.validate_degree(expression.degree());
    }

    pub(crate) fn validate_lookup_expression(
        &self,
        expression: &Expression<F>,
    ) {
        self.validate_degree(expression.degree() + LOOKUP_DEGREE);
    }

    pub(crate) fn validate_degree(&self, degree: usize) {
        assert!(
            degree <= self.max_degree,
            "Expression degree too high: {} > {}",
            degree,
            self.max_degree,
        );
    }

    // General

    pub(crate) fn add_expression(&mut self, expression: Expression<F>) {
        self.validate_expression(&expression);
        self.expressions.push(expression);
    }

    pub(crate) fn add_expressions(&mut self, expressions: Vec<Expression<F>>) {
        for expression in expressions {
            self.add_expression(expression);
        }
    }

    pub(crate) fn add_fixed_lookup(
        &mut self,
        table: FixedLookup,
        expressions: [Expression<F>; 3],
    ) {
        for expression in expressions.iter() {
            self.validate_lookup_expression(expression);
        }
        self.add_lookup(Lookup::FixedLookup(table, expressions));
    }

    pub(crate) fn add_bytecode_lookup(
        &mut self,
        table: BytecodeLookup,
        expressions: [Expression<F>; 5],
    ) {
        for expression in expressions.iter() {
            self.validate_lookup_expression(expression);
        }
        self.add_lookup(Lookup::BytecodeLookup(table, expressions));
    }

    fn add_lookup(&mut self, lookup: Lookup<F>) {
        self.lookups.push(lookup);
    }

    // Constraint

    pub(crate) fn constraint(
        &self,
        selector: Expression<F>,
        name: &'static str,
    ) -> Constraint<F> {
        Constraint {
            name,
            selector,
            polys: self.expressions.clone(),
            lookups: self.lookups.clone(),
        }
    }
}
