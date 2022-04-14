use crate::{
    evm_circuit::{
        param::STACK_CAPACITY,
        step::{ExecutionState, Preset, Step},
        table::{
            AccountFieldTag, BytecodeFieldTag, CallContextFieldTag, FixedTableTag, Lookup,
            RwTableTag, TxContextFieldTag,
        },
        util::{Cell, RandomLinearCombination, Word},
    },
    util::Expr,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{
        Error,
        Expression::{self, Constant},
    },
};
use std::convert::TryInto;

// Max degree allowed in all expressions passing through the ConstraintBuilder.
// It aims to cap `extended_k` to 4, which allows constraint degree to 2^4+1,
// but each ExecutionGadget has implicit selector degree 2, so here it only
// allows 2^4+1-2 = 15.
const MAX_DEGREE: usize = 15;
// Implicit degree added to input expressions of lookups. It assumes blind
// factors have been disabled, and table expressions with degree 1.
const LOOKUP_DEGREE: usize = 2;

#[derive(Clone, Debug, Default)]
struct StepRowUsage {
    next_idx: usize,
    is_byte_lookup_enabled: bool,
}

pub(crate) enum Transition<T> {
    Same,
    Delta(T),
    To(T),
    Any,
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
    pub(crate) code_source: Transition<Expression<F>>,
    pub(crate) program_counter: Transition<Expression<F>>,
    pub(crate) stack_pointer: Transition<Expression<F>>,
    pub(crate) gas_left: Transition<Expression<F>>,
    pub(crate) memory_word_size: Transition<Expression<F>>,
    pub(crate) reversible_write_counter: Transition<Expression<F>>,
}

impl<F: FieldExt> StepStateTransition<F> {
    pub(crate) fn new_context() -> Self {
        Self {
            program_counter: Transition::To(0.expr()),
            stack_pointer: Transition::To(STACK_CAPACITY.expr()),
            memory_word_size: Transition::To(0.expr()),
            ..Default::default()
        }
    }

    pub(crate) fn any() -> Self {
        Self {
            rw_counter: Transition::Any,
            call_id: Transition::Any,
            is_root: Transition::Any,
            is_create: Transition::Any,
            code_source: Transition::Any,
            program_counter: Transition::Any,
            stack_pointer: Transition::Any,
            gas_left: Transition::Any,
            memory_word_size: Transition::Any,
            reversible_write_counter: Transition::Any,
        }
    }
}

/// ReversionInfo counts `rw_counter` of reversion for gadgets, by tracking how
/// many reversions that have been used. Gadgets should call
/// [`ConstraintBuilder::reversion_info`] to get [`ReversionInfo`] with
/// `reversible_write_counter` initialized at current tracking one if no
/// `call_id` is specified, then pass it as mutable reference when doing state
/// write.
#[derive(Clone, Debug)]
pub(crate) struct ReversionInfo<F> {
    /// Field [`CallContextFieldTag::RwCounterEndOfReversion`] read from call
    /// context.
    rw_counter_end_of_reversion: Cell<F>,
    /// Field [`CallContextFieldTag::IsPersistent`] read from call context.
    is_persistent: Cell<F>,
    /// Current cumulative reversible_write_counter.
    reversible_write_counter: Expression<F>,
}

impl<F: FieldExt> ReversionInfo<F> {
    pub(crate) fn rw_counter_end_of_reversion(&self) -> Expression<F> {
        self.rw_counter_end_of_reversion.expr()
    }

    pub(crate) fn is_persistent(&self) -> Expression<F> {
        self.is_persistent.expr()
    }

    /// Returns `rw_counter_end_of_reversion - reversible_write_counter` and
    /// increases `reversible_write_counter` by `1`.
    pub(crate) fn rw_counter_of_reversion(&mut self) -> Expression<F> {
        let rw_counter_of_reversion =
            self.rw_counter_end_of_reversion.expr() - self.reversible_write_counter.expr();
        self.reversible_write_counter = self.reversible_write_counter.clone() + 1.expr();
        rw_counter_of_reversion
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        rw_counter_end_of_reversion: usize,
        is_persistent: bool,
    ) -> Result<(), Error> {
        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Some(F::from(rw_counter_end_of_reversion as u64)),
        )?;
        self.is_persistent
            .assign(region, offset, Some(F::from(is_persistent as u64)))?;
        Ok(())
    }
}

#[derive(Default)]
pub struct BaseConstraintBuilder<F> {
    pub constraints: Vec<(&'static str, Expression<F>)>,
    pub max_degree: usize,
    pub condition: Option<Expression<F>>,
}

impl<F: FieldExt> BaseConstraintBuilder<F> {
    pub(crate) fn new(max_degree: usize) -> Self {
        BaseConstraintBuilder {
            constraints: Vec::new(),
            max_degree,
            condition: None,
        }
    }

    pub(crate) fn require_zero(&mut self, name: &'static str, constraint: Expression<F>) {
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

    pub(crate) fn require_boolean(&mut self, name: &'static str, value: Expression<F>) {
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
            set.iter()
                .fold(1.expr(), |acc, item| acc * (value.clone() - item.clone())),
        );
    }

    pub(crate) fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        debug_assert!(
            self.condition.is_none(),
            "Nested condition is not supported"
        );
        self.condition = Some(condition);
        let ret = constraint(self);
        self.condition = None;
        ret
    }

    pub(crate) fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    pub(crate) fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        let constraint = match &self.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        self.validate_degree(constraint.degree(), name);
        self.constraints.push((name, constraint));
    }

    pub(crate) fn validate_degree(&self, degree: usize, name: &'static str) {
        if self.max_degree > 0 {
            debug_assert!(
                degree <= self.max_degree,
                "Expression {} degree too high: {} > {}",
                name,
                degree,
                self.max_degree,
            );
        }
    }

    pub(crate) fn gate(&self, selector: Expression<F>) -> Vec<(&'static str, Expression<F>)> {
        self.constraints
            .clone()
            .into_iter()
            .map(|(name, constraint)| (name, selector.clone() * constraint))
            .collect()
    }
}

pub(crate) struct ConstraintBuilder<'a, F> {
    pub(crate) curr: &'a Step<F>,
    pub(crate) next: &'a Step<F>,
    power_of_randomness: &'a [Expression<F>; 31],
    execution_state: ExecutionState,
    cb: BaseConstraintBuilder<F>,
    constraints_first_step: Vec<(&'static str, Expression<F>)>,
    lookups: Vec<(&'static str, Lookup<F>)>,
    curr_row_usages: Vec<StepRowUsage>,
    next_row_usages: Vec<StepRowUsage>,
    rw_counter_offset: Expression<F>,
    program_counter_offset: usize,
    stack_pointer_offset: i32,
    in_next_step: bool,
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
            cb: BaseConstraintBuilder::new(MAX_DEGREE),
            constraints_first_step: Vec::new(),
            lookups: Vec::new(),
            curr_row_usages: vec![StepRowUsage::default(); curr.rows.len()],
            next_row_usages: vec![StepRowUsage::default(); next.rows.len()],
            rw_counter_offset: 0.expr(),
            program_counter_offset: 0,
            stack_pointer_offset: 0,
            in_next_step: false,
            condition: None,
        }
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn build(
        self,
    ) -> (
        Vec<(&'static str, Expression<F>)>,
        Vec<(&'static str, Expression<F>)>,
        Vec<(&'static str, Lookup<F>)>,
        Vec<Preset<F>>,
    ) {
        let mut constraints = self.cb.constraints;
        let mut presets = Vec::new();

        for (row, usage) in self.curr.rows.iter().zip(self.curr_row_usages.iter()) {
            if usage.is_byte_lookup_enabled {
                constraints.push(("Enable byte lookup", row.qs_byte_lookup.expr() - 1.expr()));
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

        let execution_state_selector = self.curr.execution_state_selector([self.execution_state]);

        (
            constraints
                .into_iter()
                .map(|(name, constraint)| (name, execution_state_selector.clone() * constraint))
                .collect(),
            self.constraints_first_step
                .into_iter()
                .map(|(name, constraint)| (name, execution_state_selector.clone() * constraint))
                .collect(),
            self.lookups
                .into_iter()
                .map(|(name, lookup)| (name, lookup.conditional(execution_state_selector.clone())))
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

    pub(crate) fn rw_counter_offset(&self) -> Expression<F> {
        self.rw_counter_offset.clone()
    }

    pub(crate) fn program_counter_offset(&self) -> usize {
        self.program_counter_offset
    }

    pub(crate) fn stack_pointer_offset(&self) -> i32 {
        self.stack_pointer_offset
    }

    // Query

    pub(crate) fn copy<E: Expr<F>>(&mut self, value: E) -> Cell<F> {
        let cell = self.query_cell();
        self.require_equal("Copy value to new cell", cell.expr(), value.expr());
        cell
    }

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

    pub(crate) fn query_rlc<const N: usize>(&mut self) -> RandomLinearCombination<F, N> {
        RandomLinearCombination::<F, N>::new(self.query_bytes(), self.power_of_randomness)
    }

    pub(crate) fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.query_cells::<N>(true)
    }

    fn query_cells<const N: usize>(&mut self, is_byte: bool) -> [Cell<F>; N] {
        let mut cells = Vec::with_capacity(N);
        let rows = if self.in_next_step {
            &self.next.rows
        } else {
            &self.curr.rows
        };
        let row_usages = if self.in_next_step {
            &mut self.next_row_usages
        } else {
            &mut self.curr_row_usages
        };

        // Iterate rows to find cell that matches the is_byte requirement.
        for (row, usage) in rows.iter().zip(row_usages.iter_mut()) {
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

    pub(crate) fn require_zero(&mut self, name: &'static str, constraint: Expression<F>) {
        self.cb.require_zero(name, constraint);
    }

    pub(crate) fn require_equal(
        &mut self,
        name: &'static str,
        lhs: Expression<F>,
        rhs: Expression<F>,
    ) {
        self.cb.require_equal(name, lhs, rhs);
    }

    pub(crate) fn require_boolean(&mut self, name: &'static str, value: Expression<F>) {
        self.cb.require_boolean(name, value);
    }

    pub(crate) fn require_in_set(
        &mut self,
        name: &'static str,
        value: Expression<F>,
        set: Vec<Expression<F>>,
    ) {
        self.cb.require_in_set(name, value, set);
    }

    pub(crate) fn require_next_state(&mut self, execution_state: ExecutionState) {
        let next_state = self.next.execution_state_selector([execution_state]);
        self.add_constraint(
            "Constrain next execution state",
            1.expr() - next_state.expr(),
        );
    }

    pub(crate) fn require_step_state_transition(
        &mut self,
        step_state_transition: StepStateTransition<F>,
    ) {
        macro_rules! constrain {
            ($name:tt) => {
                match step_state_transition.$name {
                    Transition::Same => self.require_equal(
                        concat!("State transition constraint of ", stringify!($name)),
                        self.next.state.$name.expr(),
                        self.curr.state.$name.expr(),
                    ),
                    Transition::Delta(delta) => self.require_equal(
                        concat!("State transition constraint of ", stringify!($name)),
                        self.next.state.$name.expr(),
                        self.curr.state.$name.expr() + delta,
                    ),
                    Transition::To(to) => self.require_equal(
                        concat!("State transition constraint of ", stringify!($name)),
                        self.next.state.$name.expr(),
                        to,
                    ),
                    _ => {}
                }
            };
        }

        constrain!(rw_counter);
        constrain!(call_id);
        constrain!(is_root);
        constrain!(is_create);
        constrain!(code_source);
        constrain!(program_counter);
        constrain!(stack_pointer);
        constrain!(gas_left);
        constrain!(memory_word_size);
        constrain!(reversible_write_counter);
    }

    // Fixed

    pub(crate) fn range_lookup(&mut self, value: Expression<F>, range: u64) {
        let (name, tag) = match range {
            5 => ("Range5", FixedTableTag::Range5),
            16 => ("Range16", FixedTableTag::Range16),
            32 => ("Range32", FixedTableTag::Range32),
            64 => ("Range64", FixedTableTag::Range64),
            256 => ("Range256", FixedTableTag::Range256),
            512 => ("Range512", FixedTableTag::Range512),
            1024 => ("Range1024", FixedTableTag::Range1024),
            _ => unimplemented!(),
        };
        self.add_lookup(
            name,
            Lookup::Fixed {
                tag: tag.expr(),
                values: [value, 0.expr(), 0.expr()],
            },
        );
    }

    // Opcode

    pub(crate) fn opcode_lookup(&mut self, opcode: Expression<F>, is_code: Expression<F>) {
        self.opcode_lookup_at(
            self.curr.state.program_counter.expr() + self.program_counter_offset.expr(),
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
        let is_root_create = self.curr.state.is_root.expr() * self.curr.state.is_create.expr();
        self.add_constraint(
            "The opcode source when is_root and is_create (Root creation transaction) is not determined yet",
            is_root_create.clone(),
        );
        self.add_lookup(
            "Opcode lookup",
            Lookup::Bytecode {
                hash: self.curr.state.code_source.expr(),
                tag: BytecodeFieldTag::Byte.expr(),
                index,
                is_code,
                value: opcode,
            }
            .conditional(1.expr() - is_root_create),
        );
    }

    // Bytecode table

    pub(crate) fn bytecode_lookup(
        &mut self,
        code_hash: Expression<F>,
        index: Expression<F>,
        is_code: Expression<F>,
        value: Expression<F>,
    ) {
        self.add_lookup(
            "Bytecode (byte) lookup",
            Lookup::Bytecode {
                hash: code_hash,
                tag: BytecodeFieldTag::Byte.expr(),
                index,
                is_code,
                value,
            },
        )
    }

    pub(crate) fn bytecode_length(&mut self, code_hash: Expression<F>) -> Cell<F> {
        let cell = self.query_cell();
        self.add_lookup(
            "Bytecode (length)",
            Lookup::Bytecode {
                hash: code_hash,
                tag: BytecodeFieldTag::Length.expr(),
                index: 0.expr(),
                is_code: 0.expr(),
                value: cell.expr(),
            },
        );
        cell
    }

    // Tx context

    pub(crate) fn tx_context(
        &mut self,
        id: Expression<F>,
        field_tag: TxContextFieldTag,
        index: Option<Expression<F>>,
    ) -> Cell<F> {
        let cell = self.query_cell();
        self.tx_context_lookup(id, field_tag, index, cell.expr());
        cell
    }

    pub(crate) fn tx_context_as_word(
        &mut self,
        id: Expression<F>,
        field_tag: TxContextFieldTag,
        index: Option<Expression<F>>,
    ) -> Word<F> {
        let word = self.query_word();
        self.tx_context_lookup(id, field_tag, index, word.expr());
        word
    }

    pub(crate) fn tx_context_lookup(
        &mut self,
        id: Expression<F>,
        field_tag: TxContextFieldTag,
        index: Option<Expression<F>>,
        value: Expression<F>,
    ) {
        self.add_lookup(
            "Tx lookup",
            Lookup::Tx {
                id,
                field_tag: field_tag.expr(),
                index: index.unwrap_or_else(|| 0.expr()),
                value,
            },
        );
    }

    // block
    pub(crate) fn block_lookup(
        &mut self,
        tag: Expression<F>,
        number: Option<Expression<F>>,
        val: Expression<F>,
    ) {
        self.add_lookup(
            "Block lookup",
            Lookup::Block {
                field_tag: tag,
                number: number.unwrap_or_else(|| 0.expr()),
                value: val,
            },
        );
    }

    // Rw

    /// Add a Lookup::Rw without increasing the rw_counter_offset, which is
    /// useful for state reversion or dummy lookup.
    fn rw_lookup_with_counter(
        &mut self,
        name: &'static str,
        counter: Expression<F>,
        is_write: Expression<F>,
        tag: RwTableTag,
        values: [Expression<F>; 8],
    ) {
        self.add_lookup(
            name,
            Lookup::Rw {
                counter,
                is_write,
                tag: tag.expr(),
                values,
            },
        );
    }

    /// Add a Lookup::Rw and increase the rw_counter_offset, useful in normal
    /// cases.
    fn rw_lookup(
        &mut self,
        name: &'static str,
        is_write: Expression<F>,
        tag: RwTableTag,
        values: [Expression<F>; 8],
    ) {
        self.rw_lookup_with_counter(
            name,
            self.curr.state.rw_counter.expr() + self.rw_counter_offset.clone(),
            is_write,
            tag,
            values,
        );
        // Manually constant folding is used here, since halo2 cannot do this
        // automatically. Better error message will be printed during circuit
        // debugging.
        self.rw_counter_offset = match &self.cb.condition {
            None => {
                if let Constant(v) = self.rw_counter_offset {
                    Constant(v + F::from(1u64))
                } else {
                    self.rw_counter_offset.clone() + 1i32.expr()
                }
            }
            Some(c) => self.rw_counter_offset.clone() + c.clone(),
        };
    }

    fn reversible_write(
        &mut self,
        name: &'static str,
        tag: RwTableTag,
        mut values: [Expression<F>; 8],
        reversion_info: Option<&mut ReversionInfo<F>>,
    ) {
        debug_assert!(
            tag.is_reversible(),
            "Reversible write requires reversible tag"
        );

        self.rw_lookup(name, true.expr(), tag, values.clone());

        if let Some(reversion_info) = reversion_info {
            // Revert if is_persistent is 0
            self.condition(1.expr() - reversion_info.is_persistent(), |cb| {
                // Swap value and value_prev
                values.swap(4, 5);

                cb.rw_lookup_with_counter(
                    name,
                    reversion_info.rw_counter_of_reversion(),
                    true.expr(),
                    tag,
                    values,
                )
            });
        }
    }

    // Access list

    pub(crate) fn account_access_list_write(
        &mut self,
        tx_id: Expression<F>,
        account_address: Expression<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
        reversion_info: Option<&mut ReversionInfo<F>>,
    ) {
        self.reversible_write(
            "TxAccessListAccount write",
            RwTableTag::TxAccessListAccount,
            [
                tx_id,
                account_address,
                0.expr(),
                0.expr(),
                value,
                value_prev,
                0.expr(),
                0.expr(),
            ],
            reversion_info,
        );
    }

    pub(crate) fn account_storage_access_list_write(
        &mut self,
        tx_id: Expression<F>,
        account_address: Expression<F>,
        storage_key: Expression<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
        reversion_info: Option<&mut ReversionInfo<F>>,
    ) {
        self.reversible_write(
            "TxAccessListAccountStorage write",
            RwTableTag::TxAccessListAccountStorage,
            [
                tx_id,
                account_address,
                0.expr(),
                storage_key,
                value,
                value_prev,
                0.expr(),
                0.expr(),
            ],
            reversion_info,
        );
    }

    // Tx Refund

    pub(crate) fn tx_refund_read(&mut self, tx_id: Expression<F>, value: Expression<F>) {
        self.rw_lookup(
            "TxRefund read",
            false.expr(),
            RwTableTag::TxRefund,
            [
                tx_id,
                0.expr(),
                0.expr(),
                0.expr(),
                value.clone(),
                value,
                0.expr(),
                0.expr(),
            ],
        );
    }

    pub(crate) fn tx_refund_write(
        &mut self,
        tx_id: Expression<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
        reversion_info: Option<&mut ReversionInfo<F>>,
    ) {
        self.reversible_write(
            "TxRefund write",
            RwTableTag::TxRefund,
            [
                tx_id,
                0.expr(),
                0.expr(),
                0.expr(),
                value,
                value_prev,
                0.expr(),
                0.expr(),
            ],
            reversion_info,
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
            "Account read",
            false.expr(),
            RwTableTag::Account,
            [
                0.expr(),
                account_address,
                field_tag.expr(),
                0.expr(),
                value.clone(),
                value,
                0.expr(),
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
        reversion_info: Option<&mut ReversionInfo<F>>,
    ) {
        self.reversible_write(
            "Account write with reversion",
            RwTableTag::Account,
            [
                0.expr(),
                account_address,
                field_tag.expr(),
                0.expr(),
                value,
                value_prev,
                0.expr(),
                0.expr(),
            ],
            reversion_info,
        );
    }

    // Account Storage

    pub(crate) fn account_storage_read(
        &mut self,
        account_address: Expression<F>,
        key: Expression<F>,
        value: Expression<F>,
        tx_id: Expression<F>,
        committed_value: Expression<F>,
    ) {
        self.rw_lookup(
            "account_storage_read",
            false.expr(),
            RwTableTag::AccountStorage,
            [
                tx_id,
                account_address,
                0.expr(),
                key,
                value.clone(),
                value,
                0.expr(),
                committed_value,
            ],
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn account_storage_write(
        &mut self,
        account_address: Expression<F>,
        key: Expression<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
        tx_id: Expression<F>,
        committed_value: Expression<F>,
        reversion_info: Option<&mut ReversionInfo<F>>,
    ) {
        self.reversible_write(
            "AccountStorage write",
            RwTableTag::AccountStorage,
            [
                tx_id,
                account_address,
                0.expr(),
                key,
                value,
                value_prev,
                0.expr(),
                committed_value,
            ],
            reversion_info,
        );
    }

    // Call context

    pub(crate) fn call_context(
        &mut self,
        call_id: Option<Expression<F>>,
        field_tag: CallContextFieldTag,
    ) -> Cell<F> {
        let cell = self.query_cell();
        self.call_context_lookup(false.expr(), call_id, field_tag, cell.expr());
        cell
    }

    pub(crate) fn call_context_lookup(
        &mut self,
        is_write: Expression<F>,
        call_id: Option<Expression<F>>,
        field_tag: CallContextFieldTag,
        value: Expression<F>,
    ) {
        self.rw_lookup(
            "CallContext lookup",
            is_write,
            RwTableTag::CallContext,
            [
                call_id.unwrap_or_else(|| self.curr.state.call_id.expr()),
                0.expr(),
                field_tag.expr(),
                0.expr(),
                value,
                0.expr(),
                0.expr(),
                0.expr(),
            ],
        );
    }

    pub(crate) fn reversion_info(&mut self, call_id: Option<Expression<F>>) -> ReversionInfo<F> {
        let [rw_counter_end_of_reversion, is_persistent] = [
            CallContextFieldTag::RwCounterEndOfReversion,
            CallContextFieldTag::IsPersistent,
        ]
        .map(|field_tag| self.call_context(call_id.clone(), field_tag));
        ReversionInfo {
            rw_counter_end_of_reversion,
            is_persistent,
            reversible_write_counter: if call_id.is_some() {
                0.expr()
            } else {
                self.curr.state.reversible_write_counter.expr()
            },
        }
    }

    // Stack

    pub(crate) fn stack_pop(&mut self, value: Expression<F>) {
        self.stack_lookup(false.expr(), self.stack_pointer_offset.expr(), value);
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
            "Stack lookup",
            is_write,
            RwTableTag::Stack,
            [
                self.curr.state.call_id.expr(),
                self.curr.state.stack_pointer.expr() + stack_pointer_offset,
                0.expr(),
                0.expr(),
                value,
                0.expr(),
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
        call_id: Option<Expression<F>>,
    ) {
        self.rw_lookup(
            "Memory lookup",
            is_write,
            RwTableTag::Memory,
            [
                call_id.unwrap_or_else(|| self.curr.state.call_id.expr()),
                memory_address,
                0.expr(),
                0.expr(),
                byte,
                0.expr(),
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
            "Memory lookup",
            rw_counter,
            is_write,
            RwTableTag::Memory,
            [
                self.curr.state.call_id.expr(),
                memory_address,
                0.expr(),
                0.expr(),
                byte,
                0.expr(),
                0.expr(),
                0.expr(),
            ],
        );
    }

    // Validation

    pub(crate) fn validate_degree(&self, degree: usize, name: &'static str) {
        // We need to subtract 2 from MAX_DEGREE because all expressions will be
        // multiplied by state selector and q_step/q_step_first selector.
        debug_assert!(
            degree <= MAX_DEGREE - 2,
            "Expression {} degree too high: {} > {}",
            name,
            degree,
            MAX_DEGREE - 2,
        );
    }

    // General

    pub(crate) fn condition<R>(
        &mut self,
        condition: Expression<F>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        debug_assert!(
            self.cb.condition.is_none(),
            "Nested condition is not supported"
        );
        self.cb.condition = Some(condition);
        let ret = constraint(self);
        self.cb.condition = None;
        ret
    }

    /// This function needs to be used with extra precaution. You need to make
    /// sure the layout is the same as the gadget for `next_step_state`.
    /// `query_cell` will return cells in the next step in the `constraint`
    /// function.
    pub(crate) fn constrain_next_step<R>(
        &mut self,
        next_step_state: ExecutionState,
        condition: Option<Expression<F>>,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        assert!(!self.in_next_step, "Already in the next step");
        self.in_next_step = true;
        let ret = match condition {
            None => {
                self.require_next_state(next_step_state);
                constraint(self)
            }
            Some(cond) => self.condition(cond, |cb| {
                cb.require_next_state(next_step_state);
                constraint(cb)
            }),
        };
        self.in_next_step = false;
        ret
    }

    pub(crate) fn add_constraints(&mut self, constraints: Vec<(&'static str, Expression<F>)>) {
        self.cb.add_constraints(constraints);
    }

    pub(crate) fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        self.cb.add_constraint(name, constraint);
    }

    pub(crate) fn add_constraint_first_step(
        &mut self,
        name: &'static str,
        constraint: Expression<F>,
    ) {
        let constraint = match &self.cb.condition {
            Some(condition) => condition.clone() * constraint,
            None => constraint,
        };
        // Add 1 more degree due to the selector
        self.validate_degree(constraint.degree() + 1, name);
        self.constraints_first_step.push((name, constraint));
    }

    pub(crate) fn add_lookup(&mut self, name: &'static str, lookup: Lookup<F>) {
        let lookup = match &self.cb.condition {
            Some(condition) => lookup.conditional(condition.clone()),
            None => lookup,
        };
        self.validate_degree(lookup.degree() + LOOKUP_DEGREE, name);
        self.lookups.push((name, lookup));
    }
}
