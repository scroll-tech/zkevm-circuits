use crate::{
    evm_circuit::{
        step::{Preset, Step},
        table::{FixedTableTag, Lookup, RwTableTag, TxTableTag},
        util::{Cell, Word},
    },
    util::Expr,
};
use halo2::{arithmetic::FieldExt, plonk::Expression};
use std::convert::TryInto;

use super::math_gadget::RangeCheckGadget;

// Max degree allowed in all expressions passing through the ConstraintBuilder.
const MAX_DEGREE: usize = 2usize.pow(3) + 1 + 32;
// Degree added for expressions used in lookups.
const LOOKUP_DEGREE: usize = 3;

#[derive(Clone, Debug, Default)]
struct StepRowUsage {
    next_idx: usize,
    is_byte_lookup_enabled: bool,
}

pub(crate) enum Transition<F: FieldExt> {
    Persistent,
    Delta(Expression<F>),
    To(Expression<F>),
}

impl<F: FieldExt> Default for Transition<F> {
    fn default() -> Self {
        Self::Persistent
    }
}

#[derive(Default)]
pub(crate) struct StateTransition<F: FieldExt> {
    pub(crate) rw_counter: Transition<F>,
    pub(crate) call_id: Transition<F>,
    pub(crate) is_root: Transition<F>,
    pub(crate) is_create: Transition<F>,
    pub(crate) opcode_source: Transition<F>,
    pub(crate) program_counter: Transition<F>,
    pub(crate) stack_pointer: Transition<F>,
    pub(crate) gas_left: Transition<F>,
    pub(crate) memory_size: Transition<F>,
    pub(crate) state_write_counter: Transition<F>,
}

pub(crate) struct ConstraintBuilder<'a, F> {
    pub(crate) curr: &'a Step<F>,
    pub(crate) next: &'a Step<F>,
    randomness: &'a Expression<F>,
    constraints: Vec<Expression<F>>,
    lookups: Vec<Lookup<F>>,
    row_usages: Vec<StepRowUsage>,
    rw_counter_offset: usize,
    program_counter_offset: usize,
    stack_pointer_offset: i32,
    condition: Option<Expression<F>>,
}

impl<'a, F: FieldExt> ConstraintBuilder<'a, F> {
    pub(crate) fn new(
        curr: &'a Step<F>,
        next: &'a Step<F>,
        randomness: &'a Expression<F>,
    ) -> Self {
        Self {
            curr,
            next,
            randomness,
            constraints: Vec::new(),
            lookups: Vec::new(),
            row_usages: vec![StepRowUsage::default(); curr.rows.len()],
            rw_counter_offset: 0,
            program_counter_offset: 0,
            stack_pointer_offset: 0,
            condition: None,
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build(
        self,
    ) -> (Vec<Expression<F>>, Vec<Lookup<F>>, Vec<Preset<F>>) {
        let mut constraints = self.constraints;
        let mut presets = Vec::new();

        for (row, usage) in self.curr.rows.iter().zip(self.row_usages.iter()) {
            if usage.is_byte_lookup_enabled {
                constraints.push(row.qs_byte_lookup.expr() - 1.expr());
            }

            presets.extend(
                row.cells[usage.next_idx..]
                    .iter()
                    .map(|cell| (cell.clone(), F::zero())),
            );
            presets.push((
                row.qs_byte_lookup.clone(),
                if usage.is_byte_lookup_enabled {
                    F::one()
                } else {
                    F::zero()
                },
            ));
        }

        (constraints, self.lookups, presets)
    }

    pub(crate) fn randomness(&self) -> Expression<F> {
        self.randomness.clone()
    }

    pub(crate) fn rw_counter_offset(&self) -> usize {
        self.rw_counter_offset
    }

    pub(crate) fn program_counter_offset(&self) -> usize {
        self.program_counter_offset
    }

    pub(crate) fn stack_pointer_offset(&self) -> i32 {
        self.stack_pointer_offset
    }

    // Query

    pub(crate) fn query_bool(&mut self) -> Cell<F> {
        let [cell] = self.query_cells::<1>(false);
        self.require_boolean(cell.expr());
        cell
    }

    pub(crate) fn query_byte(&mut self) -> Cell<F> {
        let [cell] = self.query_cells::<1>(true);
        cell
    }

    pub(crate) fn query_cell(&mut self) -> Cell<F> {
        let [cell] = self.query_cells::<1>(false);
        cell
    }

    pub(crate) fn query_word(&mut self) -> Word<F> {
        Word::new(self.query_bytes(), self.randomness.clone())
    }

    pub(crate) fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.query_cells::<N>(true)
    }

    fn query_cells<const N: usize>(&mut self, is_byte: bool) -> [Cell<F>; N] {
        let mut cells = Vec::with_capacity(N);

        for (row, usage) in
            self.curr.rows.iter().zip(self.row_usages.iter_mut())
        {
            if usage.is_byte_lookup_enabled != is_byte {
                if usage.next_idx > 0 || usage.next_idx == row.cells.len() {
                    continue;
                }
                if is_byte {
                    usage.is_byte_lookup_enabled = true;
                }
            }

            let n = row.cells.len().min(usage.next_idx + N - cells.len());
            cells.extend(row.cells[usage.next_idx..n].iter().cloned());
            usage.next_idx = n;

            if cells.len() == N {
                return cells.try_into().unwrap();
            }
        }

        unreachable!("not enough cells for query")
    }

    // Common

    pub(crate) fn require_boolean(&mut self, value: Expression<F>) {
        self.add_constraint(value.clone() * (1.expr() - value));
    }

    pub(crate) fn require_zero(&mut self, constraint: Expression<F>) {
        self.add_constraint(constraint);
    }

    pub(crate) fn require_equal(
        &mut self,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) {
        self.add_constraint(lhs - rhs);
    }

    pub(crate) fn require_in_range(
        &mut self,
        value: Expression<F>,
        range: u64,
    ) {
        let tag = match range {
            16 => FixedTableTag::Range16,
            17 => FixedTableTag::Range17,
            32 => FixedTableTag::Range32,
            256 => FixedTableTag::Range256,
            512 => FixedTableTag::Range512,
            _ => unimplemented!(),
        };
        self.add_lookup(Lookup::Fixed {
            tag: tag.expr(),
            values: [value, 0.expr(), 0.expr()],
        });
    }

    pub(crate) fn require_sufficient_gas_left(
        &mut self,
        gas_cost: Expression<F>,
    ) -> RangeCheckGadget<F, 8> {
        RangeCheckGadget::construct(
            self,
            self.curr.state.gas_left.expr() - gas_cost,
        )
    }
    pub(crate) fn require_state_transition(
        &mut self,
        state_transition: StateTransition<F>,
    ) {
        for (curr, next, transition) in vec![
            (
                &self.curr.state.rw_counter,
                &self.next.state.rw_counter,
                state_transition.rw_counter,
            ),
            (
                &self.curr.state.call_id,
                &self.next.state.call_id,
                state_transition.call_id,
            ),
            (
                &self.curr.state.is_root,
                &self.next.state.is_root,
                state_transition.is_root,
            ),
            (
                &self.curr.state.is_create,
                &self.next.state.is_create,
                state_transition.is_create,
            ),
            (
                &self.curr.state.opcode_source,
                &self.next.state.opcode_source,
                state_transition.opcode_source,
            ),
            (
                &self.curr.state.program_counter,
                &self.next.state.program_counter,
                state_transition.program_counter,
            ),
            (
                &self.curr.state.stack_pointer,
                &self.next.state.stack_pointer,
                state_transition.stack_pointer,
            ),
            (
                &self.curr.state.gas_left,
                &self.next.state.gas_left,
                state_transition.gas_left,
            ),
            (
                &self.curr.state.memory_size,
                &self.next.state.memory_size,
                state_transition.memory_size,
            ),
            (
                &self.curr.state.state_write_counter,
                &self.next.state.state_write_counter,
                state_transition.state_write_counter,
            ),
        ] {
            match transition {
                Transition::Persistent => {
                    self.require_equal(next.expr(), curr.expr())
                }
                Transition::Delta(delta) => {
                    self.require_equal(next.expr(), curr.expr() + delta)
                }
                Transition::To(to) => self.require_equal(next.expr(), to),
            }
        }
    }

    // Opcode

    pub(crate) fn opcode_lookup(&mut self, opcode: Expression<F>) {
        self.opcode_lookup_at(
            self.curr.state.program_counter.expr()
                + self.program_counter_offset.expr(),
            opcode,
        );
        self.program_counter_offset += 1;
    }

    pub(crate) fn opcode_lookup_at(
        &mut self,
        index: Expression<F>,
        opcode: Expression<F>,
    ) {
        let is_root_create =
            self.curr.state.is_root.expr() * self.curr.state.is_create.expr();
        self.add_lookup(
            Lookup::Tx {
                id: self.curr.state.opcode_source.expr(),
                tag: TxTableTag::Calldata.expr(),
                index: index.clone(),
                value: opcode.clone(),
            }
            .conditional(is_root_create.clone()),
        );
        self.add_lookup(
            Lookup::Bytecode {
                hash: self.curr.state.opcode_source.expr(),
                index,
                value: opcode,
            }
            .conditional(1.expr() - is_root_create),
        );
    }

    // Stack

    pub(crate) fn stack_pop(&mut self, value: Expression<F>) {
        self.stack_lookup(
            false.expr(),
            self.stack_pointer_offset.expr(),
            value,
        );
        self.stack_pointer_offset += 1;
    }

    pub(crate) fn stack_push(&mut self, value: Expression<F>) {
        self.stack_pointer_offset -= 1;
        self.stack_lookup(true.expr(), self.stack_pointer_offset.expr(), value);
    }

    pub(crate) fn stack_lookup(
        &mut self,
        is_write: Expression<F>,
        stack_pointer_offset: Expression<F>,
        value: Expression<F>,
    ) {
        self.stack_lookup_at(
            is_write,
            stack_pointer_offset,
            value,
            self.rw_counter_offset.expr(),
        );
        self.rw_counter_offset += 1;
    }

    pub(crate) fn stack_lookup_at(
        &mut self,
        is_write: Expression<F>,
        stack_pointer_offset: Expression<F>,
        value: Expression<F>,
        rw_counter_offset: Expression<F>,
    ) {
        self.add_lookup(Lookup::Rw {
            counter: self.curr.state.rw_counter.expr() + rw_counter_offset,
            is_write,
            tag: RwTableTag::Stack.expr(),
            values: [
                self.curr.state.call_id.expr(),
                self.curr.state.stack_pointer.expr() + stack_pointer_offset,
                value,
                0.expr(),
                0.expr(),
            ],
        });
    }

    // Memory

    pub(crate) fn memory_lookup(
        &mut self,
        is_write: Expression<F>,
        memory_address: Expression<F>,
        byte: Expression<F>,
    ) {
        self.memory_lookup_at(
            is_write,
            memory_address,
            byte,
            self.rw_counter_offset.expr(),
        );
        self.rw_counter_offset += 1;
    }

    pub(crate) fn memory_lookup_at(
        &mut self,
        is_write: Expression<F>,
        memory_address: Expression<F>,
        byte: Expression<F>,
        rw_counter_offset: Expression<F>,
    ) {
        self.add_lookup(Lookup::Rw {
            counter: self.curr.state.rw_counter.expr() + rw_counter_offset,
            is_write,
            tag: RwTableTag::Memory.expr(),
            values: [
                self.curr.state.call_id.expr(),
                memory_address,
                byte,
                0.expr(),
                0.expr(),
            ],
        });
    }

    // Validation

    pub(crate) fn validate_degree(&self, degree: usize) {
        assert!(
            degree <= MAX_DEGREE,
            "Expression degree too high: {} > {}",
            degree,
            MAX_DEGREE,
        );
    }

    // General

    pub(crate) fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        self.condition = Some(condition);
        let ret = constraint(self);
        self.condition = None;
        ret
    }

    pub(crate) fn add_constraints(&mut self, constraint: Vec<Expression<F>>) {
        for constraint in constraint {
            self.add_constraint(constraint);
        }
    }

    pub(crate) fn add_constraint(&mut self, constraint: Expression<F>) {
        let constraint = match &self.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        self.validate_degree(constraint.degree());
        self.constraints.push(constraint);
    }

    pub(crate) fn add_lookup(&mut self, lookup: Lookup<F>) {
        let lookup = match &self.condition {
            Some(condition) => lookup.conditional(condition.clone()),
            None => lookup,
        };
        self.validate_degree(lookup.degree() + LOOKUP_DEGREE);
        self.lookups.push(lookup);
    }
}
