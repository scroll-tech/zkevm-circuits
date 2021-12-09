use crate::{
    evm_circuit::{
        step::{ExecutionState, Preset, Step},
        table::{
            AccountFieldTag, CallContextFieldTag, FixedTableTag, Lookup,
            RwTableTag, TxContextFieldTag,
        },
        util::{Cell, RandomLinearCombination, Word},
    },
    util::Expr,
};
use halo2::{arithmetic::FieldExt, plonk::Expression};
use std::convert::TryInto;

// Max degree allowed in all expressions passing through the ConstraintBuilder.
const MAX_DEGREE: usize = 2usize.pow(3) + 1;
// Degree added for expressions used in lookups.
const LOOKUP_DEGREE: usize = 3;

#[derive(Clone, Debug, Default)]
struct StepRowUsage {
    next_idx: usize,
    is_byte_lookup_enabled: bool,
}

pub(crate) enum Transition<T> {
    Same,
    Delta(T),
    To(T),
}

impl<F> Default for Transition<F> {
    fn default() -> Self {
        Self::Same
    }
}

#[derive(Default)]
pub(crate) struct StepStateTransition<F: FieldExt> {
    pub(crate) rw_counter: Transition<Expression<F>>,
    pub(crate) call_id: Transition<Expression<F>>,
    pub(crate) is_root: Transition<Expression<F>>,
    pub(crate) is_create: Transition<Expression<F>>,
    pub(crate) opcode_source: Transition<Expression<F>>,
    pub(crate) program_counter: Transition<Expression<F>>,
    pub(crate) stack_pointer: Transition<Expression<F>>,
    pub(crate) gas_left: Transition<Expression<F>>,
    pub(crate) memory_word_size: Transition<Expression<F>>,
    pub(crate) state_write_counter: Transition<Expression<F>>,
}

pub(crate) struct ConstraintBuilder<'a, F> {
    pub(crate) curr: &'a Step<F>,
    pub(crate) next: &'a Step<F>,
    power_of_randomness: &'a [Expression<F>; 31],
    execution_state: ExecutionState,
    constraints: Vec<(&'static str, Expression<F>)>,
    constraints_first_step: Vec<(&'static str, Expression<F>)>,
    lookups: Vec<Lookup<F>>,
    row_usages: Vec<StepRowUsage>,
    rw_counter_offset: usize,
    program_counter_offset: usize,
    stack_pointer_offset: i32,
    state_write_counter_offset: usize,
    condition: Option<Expression<F>>,
}

impl<'a, F: FieldExt> ConstraintBuilder<'a, F> {
    pub(crate) fn new(
        curr: &'a Step<F>,
        next: &'a Step<F>,
        power_of_randomness: &'a [Expression<F>; 31],
        execution_state: ExecutionState,
    ) -> Self {
        Self {
            curr,
            next,
            power_of_randomness,
            execution_state,
            constraints: Vec::new(),
            constraints_first_step: Vec::new(),
            lookups: Vec::new(),
            row_usages: vec![StepRowUsage::default(); curr.rows.len()],
            rw_counter_offset: 0,
            program_counter_offset: 0,
            stack_pointer_offset: 0,
            state_write_counter_offset: 0,
            condition: None,
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build(
        self,
    ) -> (
        Vec<(&'static str, Expression<F>)>,
        Vec<(&'static str, Expression<F>)>,
        Vec<Lookup<F>>,
        Vec<Preset<F>>,
    ) {
        let mut constraints = self.constraints;
        let mut presets = Vec::new();

        for (row, usage) in self.curr.rows.iter().zip(self.row_usages.iter()) {
            if usage.is_byte_lookup_enabled {
                constraints.push((
                    "Enable byte lookup",
                    row.qs_byte_lookup.expr() - 1.expr(),
                ));
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

        let execution_state_selector =
            self.curr.execution_state_selector(self.execution_state);

        (
            constraints
                .into_iter()
                .map(|(name, constraint)| {
                    (name, execution_state_selector.clone() * constraint)
                })
                .collect(),
            self.constraints_first_step
                .into_iter()
                .map(|(name, constraint)| {
                    (name, execution_state_selector.clone() * constraint)
                })
                .collect(),
            self.lookups
                .into_iter()
                .map(|lookup| {
                    lookup.conditional(execution_state_selector.clone())
                })
                .collect(),
            presets,
        )
    }

    pub(crate) fn power_of_randomness(&self) -> &[Expression<F>] {
        self.power_of_randomness
    }

    pub(crate) fn execution_state(&self) -> ExecutionState {
        self.execution_state
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
        self.require_boolean("Constrain cell to be a bool", cell.expr());
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
        self.query_rlc()
    }

    pub(crate) fn query_rlc<const N: usize>(
        &mut self,
    ) -> RandomLinearCombination<F, N> {
        RandomLinearCombination::<F, N>::new(
            self.query_bytes(),
            self.power_of_randomness,
        )
    }

    pub(crate) fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.query_cells::<N>(true)
    }

    pub(crate) fn query_cells<const N: usize>(&mut self, is_byte: bool) -> [Cell<F>; N] {
        let mut cells = Vec::with_capacity(N);

        // Iterate rows to find cell that matches the is_byte requirement.
        for (row, usage) in
            self.curr.rows.iter().zip(self.row_usages.iter_mut())
        {
            // If this row doesn't match the is_byte requirement and is already
            // used, skip this row.
            if usage.is_byte_lookup_enabled != is_byte && usage.next_idx > 0 {
                continue;
            }

            // Enable the byte range lookup for this row if queried cells are
            // required to be bytes.
            if usage.next_idx == 0 && is_byte {
                usage.is_byte_lookup_enabled = true;
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

    pub(crate) fn require_zero(
        &mut self,
        name: &'static str,
        constraint: Expression<F>,
    ) {
        self.add_constraint(name, constraint);
    }

    pub(crate) fn require_equal(
        &mut self,
        name: &'static str,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) {
        self.add_constraint(name, lhs - rhs);
    }

    pub(crate) fn require_boolean(
        &mut self,
        name: &'static str,
        value: Expression<F>,
    ) {
        self.add_constraint(name, value.clone() * (1.expr() - value));
    }

    pub(crate) fn require_in_set(
        &mut self,
        name: &'static str,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        self.add_constraint(
            name,
            set.iter().fold(1.expr(), |acc, item| {
                acc * (value.clone() - item.clone())
            }),
        );
    }

    pub(crate) fn require_step_state_transition(
        &mut self,
        step_state_transition: StepStateTransition<F>,
    ) {
        for (name, curr, next, transition) in vec![
            (
                "State transition constrain of rw_counter",
                &self.curr.state.rw_counter,
                &self.next.state.rw_counter,
                step_state_transition.rw_counter,
            ),
            (
                "State transition constrain of call_id",
                &self.curr.state.call_id,
                &self.next.state.call_id,
                step_state_transition.call_id,
            ),
            (
                "State transition constrain of is_root",
                &self.curr.state.is_root,
                &self.next.state.is_root,
                step_state_transition.is_root,
            ),
            (
                "State transition constrain of is_create",
                &self.curr.state.is_create,
                &self.next.state.is_create,
                step_state_transition.is_create,
            ),
            (
                "State transition constrain of opcode_source",
                &self.curr.state.opcode_source,
                &self.next.state.opcode_source,
                step_state_transition.opcode_source,
            ),
            (
                "State transition constrain of program_counter",
                &self.curr.state.program_counter,
                &self.next.state.program_counter,
                step_state_transition.program_counter,
            ),
            (
                "State transition constrain of stack_pointer",
                &self.curr.state.stack_pointer,
                &self.next.state.stack_pointer,
                step_state_transition.stack_pointer,
            ),
            (
                "State transition constrain of gas_left",
                &self.curr.state.gas_left,
                &self.next.state.gas_left,
                step_state_transition.gas_left,
            ),
            (
                "State transition constrain of memory_word_size",
                &self.curr.state.memory_word_size,
                &self.next.state.memory_word_size,
                step_state_transition.memory_word_size,
            ),
            (
                "State transition constrain of state_write_counter",
                &self.curr.state.state_write_counter,
                &self.next.state.state_write_counter,
                step_state_transition.state_write_counter,
            ),
        ] {
            match transition {
                Transition::Same => {
                    self.require_equal(name, next.expr(), curr.expr())
                }
                Transition::Delta(delta) => {
                    self.require_equal(name, next.expr(), curr.expr() + delta)
                }
                Transition::To(to) => self.require_equal(name, next.expr(), to),
            }
        }
    }

    // Fixed

    pub(crate) fn range_lookup(&mut self, value: Expression<F>, range: u64) {
        let tag = match range {
            16 => FixedTableTag::Range16,
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

    // Opcode

    pub(crate) fn opcode_lookup(
        &mut self,
        opcode: Expression<F>,
        is_code: Expression<F>,
    ) {
        self.opcode_lookup_at(
            self.curr.state.program_counter.expr()
                + self.program_counter_offset.expr(),
            opcode,
            is_code,
        );
        self.program_counter_offset += 1;
    }

    pub(crate) fn opcode_lookup_at(
        &mut self,
        index: Expression<F>,
        opcode: Expression<F>,
        is_code: Expression<F>,
    ) {
        let is_root_create =
            self.curr.state.is_root.expr() * self.curr.state.is_create.expr();
        self.add_constraint(
            "The opcode source when is_root and is_create (Root creation transaction) is not determined yet",
            is_root_create.clone(),
        );
        self.add_lookup(
            Lookup::Bytecode {
                hash: self.curr.state.opcode_source.expr(),
                index,
                value: opcode,
                is_code,
            }
            .conditional(1.expr() - is_root_create),
        );
    }

    // Tx context

    pub(crate) fn tx_context(
        &mut self,
        id: Expression<F>,
        field_tag: TxContextFieldTag,
    ) -> Cell<F> {
        let cell = self.query_cell();
        self.tx_context_lookup(id, field_tag.expr(), cell.expr());
        cell
    }

    pub(crate) fn tx_context_as_word(
        &mut self,
        id: Expression<F>,
        field_tag: TxContextFieldTag,
    ) -> Word<F> {
        let word = self.query_word();
        self.tx_context_lookup(id, field_tag.expr(), word.expr());
        word
    }

    fn tx_context_lookup(
        &mut self,
        id: Expression<F>,
        field_tag: Expression<F>,
        value: Expression<F>,
    ) {
        self.add_lookup(Lookup::Tx {
            id,
            field_tag,
            index: 0.expr(),
            value,
        });
    }

    // block
    pub(crate) fn block_lookup(
        &mut self,
        tag: Expression<F>,
        number: Option<Expression<F>>,
        val: Expression<F>,
    ) {
        self.add_lookup(Lookup::Block {
            field_tag: tag,
            number: number.unwrap_or_else(|| 0.expr()),
            value: val,
        });
    }

    // Rw

    /// Add a Lookup::Rw without increasing the rw_counter_offset, which is
    /// useful for state reversion or dummuy lookup.
    fn rw_lookup_with_counter(
        &mut self,
        counter: Expression<F>,
        is_write: Expression<F>,
        tag: RwTableTag,
        values: [Expression<F>; 5],
    ) {
        self.add_lookup(Lookup::Rw {
            counter,
            is_write,
            tag: tag.expr(),
            values,
        });
    }

    /// Add a Lookup::Rw and increase the rw_counter_offset, useful in normal
    /// cases.
    fn rw_lookup(
        &mut self,
        is_write: Expression<F>,
        tag: RwTableTag,
        values: [Expression<F>; 5],
    ) {
        self.rw_lookup_with_counter(
            self.curr.state.rw_counter.expr() + self.rw_counter_offset.expr(),
            is_write,
            tag,
            values,
        );
        self.rw_counter_offset += 1;
    }

    fn state_write_with_reversion(
        &mut self,
        tag: RwTableTag,
        mut values: [Expression<F>; 5],
        is_persistent: Expression<F>,
        rw_counter_end_of_reversion: Expression<F>,
    ) {
        self.rw_lookup(true.expr(), tag, values.clone());

        // Revert if is_persistent is 0
        self.condition(1.expr() - is_persistent, |cb| {
            // Calculate state_write_counter so far
            let state_write_counter = cb.curr.state.state_write_counter.expr()
                + cb.state_write_counter_offset.expr();
            // Swap value and value_prev respect to tag
            match tag {
                RwTableTag::TxAccessListAccount => values.swap(2, 3),
                RwTableTag::TxAccessListStorageSlot => values.swap(3, 4),
                RwTableTag::Account => values.swap(2, 3),
                RwTableTag::AccountStorage => values.swap(3, 4),
                RwTableTag::AccountDestructed => values.swap(2, 3),
                _ => {}
            }

            cb.rw_lookup_with_counter(
                rw_counter_end_of_reversion - state_write_counter,
                true.expr(),
                tag,
                values,
            )
        });

        self.state_write_counter_offset += 1;
    }

    // Access list

    pub(crate) fn account_access_list_write(
        &mut self,
        tx_id: Expression<F>,
        account_address: Expression<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
    ) {
        self.rw_lookup(
            true.expr(),
            RwTableTag::TxAccessListAccount,
            [tx_id, account_address, value, value_prev, 0.expr()],
        );
    }

    // Account

    pub(crate) fn account_read(
        &mut self,
        account_address: Expression<F>,
        field_tag: AccountFieldTag,
        value: Expression<F>,
    ) {
        self.rw_lookup(
            false.expr(),
            RwTableTag::Account,
            [
                account_address,
                field_tag.expr(),
                value.clone(),
                value,
                0.expr(),
            ],
        );
    }

    pub(crate) fn account_write(
        &mut self,
        account_address: Expression<F>,
        field_tag: AccountFieldTag,
        value: Expression<F>,
        value_prev: Expression<F>,
    ) {
        self.rw_lookup(
            true.expr(),
            RwTableTag::Account,
            [
                account_address,
                field_tag.expr(),
                value,
                value_prev,
                0.expr(),
            ],
        );
    }

    pub(crate) fn account_write_with_reversion(
        &mut self,
        account_address: Expression<F>,
        field_tag: AccountFieldTag,
        value: Expression<F>,
        value_prev: Expression<F>,
        is_persistent: Expression<F>,
        rw_counter_end_of_reversion: Expression<F>,
    ) {
        self.state_write_with_reversion(
            RwTableTag::Account,
            [
                account_address,
                field_tag.expr(),
                value,
                value_prev,
                0.expr(),
            ],
            is_persistent,
            rw_counter_end_of_reversion,
        );
    }

    // Call context

    pub(crate) fn call_context(
        &mut self,
        call_id: Option<Expression<F>>,
        field_tag: CallContextFieldTag,
    ) -> Cell<F> {
        let cell = self.query_cell();
        self.call_context_lookup(call_id, field_tag, cell.expr());
        cell
    }

    pub(crate) fn call_context_lookup(
        &mut self,
        call_id: Option<Expression<F>>,
        field_tag: CallContextFieldTag,
        value: Expression<F>,
    ) {
        self.rw_lookup(
            false.expr(),
            RwTableTag::CallContext,
            [
                call_id.unwrap_or_else(|| self.curr.state.call_id.expr()),
                field_tag.expr(),
                value,
                0.expr(),
                0.expr(),
            ],
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
        self.rw_lookup(
            is_write,
            RwTableTag::Stack,
            [
                self.curr.state.call_id.expr(),
                self.curr.state.stack_pointer.expr() + stack_pointer_offset,
                value,
                0.expr(),
                0.expr(),
            ],
        );
    }

    // Memory

    pub(crate) fn memory_lookup(
        &mut self,
        is_write: Expression<F>,
        memory_address: Expression<F>,
        byte: Expression<F>,
    ) {
        self.rw_lookup(
            is_write,
            RwTableTag::Memory,
            [
                self.curr.state.call_id.expr(),
                memory_address,
                byte,
                0.expr(),
                0.expr(),
            ],
        );
    }

    pub(crate) fn memory_lookup_with_counter(
        &mut self,
        rw_counter: Expression<F>,
        is_write: Expression<F>,
        memory_address: Expression<F>,
        byte: Expression<F>,
    ) {
        self.rw_lookup_with_counter(
            rw_counter,
            is_write,
            RwTableTag::Memory,
            [
                self.curr.state.call_id.expr(),
                memory_address,
                byte,
                0.expr(),
                0.expr(),
            ],
        );
    }

    // Tx

    pub(crate) fn tx_lookup(
        &mut self,
        tx_id: Expression<F>,
        tag: TxContextFieldTag,
        index: Option<Expression<F>>,
        value: Expression<F>,
    ) {
        let index = index.unwrap_or(0.expr());
        self.add_lookup(Lookup::Tx {
            id: tx_id,
            field_tag: tag.expr(),
            index: index,
            value: value,
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
        assert!(
            self.condition.is_none(),
            "Nested condition is not supported"
        );
        self.condition = Some(condition);
        let ret = constraint(self);
        self.condition = None;
        ret
    }

    pub(crate) fn add_constraints(
        &mut self,
        constraints: Vec<(&'static str, Expression<F>)>,
    ) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    pub(crate) fn add_constraint(
        &mut self,
        name: &'static str,
        constraint: Expression<F>,
    ) {
        let constraint = match &self.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        self.validate_degree(constraint.degree());
        self.constraints.push((name, constraint));
    }

    pub(crate) fn add_constraint_first_step(
        &mut self,
        name: &'static str,
        constraint: Expression<F>,
    ) {
        let constraint = match &self.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        self.validate_degree(constraint.degree());
        self.constraints_first_step.push((name, constraint));
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
