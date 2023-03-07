use crate::{
    evm_circuit::{
        param::STACK_CAPACITY,
        step::{ExecutionState, Step},
        table::{FixedTableTag, Lookup, RwValues},
        util::{Cell, RandomLinearCombination, Word},
    },
    table::{
        AccountFieldTag, BytecodeFieldTag, CallContextFieldTag, RwTableTag, TxContextFieldTag,
        TxLogFieldTag, TxReceiptFieldTag,
    },
    util::{build_tx_log_expression, Challenges, Expr},
};
use eth_types::Field;
use gadgets::util::{and, not};
use halo2_proofs::{
    circuit::Value,
    plonk::{
        Error,
        Expression::{self, Constant},
    },
};
use keccak256::EMPTY_HASH_LE;

use super::{rlc, CachedRegion, CellType, StoredExpression};

// Max degree allowed in all expressions passing through the ConstraintBuilder.
// It aims to cap `extended_k` to 2, which allows constraint degree to 2^2+1,
// but each ExecutionGadget has implicit selector degree 3, so here it only
// allows 2^2+1-3 = 2.
const MAX_DEGREE: usize = 9;
const IMPLICIT_DEGREE: usize = 4;

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
pub(crate) struct StepStateTransition<F: Field> {
    pub(crate) rw_counter: Transition<Expression<F>>,
    pub(crate) call_id: Transition<Expression<F>>,
    pub(crate) is_root: Transition<Expression<F>>,
    pub(crate) is_create: Transition<Expression<F>>,
    pub(crate) code_hash: Transition<Expression<F>>,
    pub(crate) program_counter: Transition<Expression<F>>,
    pub(crate) stack_pointer: Transition<Expression<F>>,
    pub(crate) gas_left: Transition<Expression<F>>,
    pub(crate) memory_word_size: Transition<Expression<F>>,
    pub(crate) reversible_write_counter: Transition<Expression<F>>,
    pub(crate) log_id: Transition<Expression<F>>,
}

impl<F: Field> StepStateTransition<F> {
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
            code_hash: Transition::Any,
            program_counter: Transition::Any,
            stack_pointer: Transition::Any,
            gas_left: Transition::Any,
            memory_word_size: Transition::Any,
            reversible_write_counter: Transition::Any,
            log_id: Transition::Any,
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

impl<F: Field> ReversionInfo<F> {
    pub(crate) fn from_caller(
        cb: &mut ConstraintBuilder<F>,
        caller: &mut ReversionInfo<F>,
        callee_is_success: Expression<F>,
    ) -> Self {
        // not sure if this is correct??
        // let call_id = cb.curr.state.rw_counter.expr();
        let callee = cb.reversion_info_write(None);
        cb.require_equal(
            "callee_is_persistent == is_persistent ⋅ is_success",
            callee.is_persistent(),
            and::expr([caller.is_persistent(), callee_is_success.clone()]),
        );
        cb.condition(callee_is_success * not::expr(caller.is_persistent()), |cb| {
            cb.require_equal(
                "callee_rw_counter_end_of_reversion == rw_counter_end_of_reversion - (reversible_write_counter + 1)",
                callee.rw_counter_end_of_reversion(),
                caller.rw_counter_of_reversion(),
            );
        });
        callee
    }

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
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        rw_counter_end_of_reversion: usize,
        is_persistent: bool,
    ) -> Result<(), Error> {
        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Value::known(F::from(rw_counter_end_of_reversion as u64)),
        )?;
        self.is_persistent
            .assign(region, offset, Value::known(F::from(is_persistent as u64)))?;
        Ok(())
    }
}

#[derive(Default)]
pub struct BaseConstraintBuilder<F> {
    pub constraints: Vec<(&'static str, Expression<F>)>,
    pub max_degree: usize,
    pub condition: Option<Expression<F>>,
}

impl<F: Field> BaseConstraintBuilder<F> {
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
            .filter(|(name, constraint)| {
                self.validate_degree(constraint.degree(), name);
                true
            })
            .collect()
    }
}

/// Internal type to select the location where the constraints are enabled
#[derive(Debug, PartialEq)]
enum ConstraintLocation {
    Step,
    StepFirst,
    StepLast,
    NotStepLast,
}

/// Collection of constraints grouped by which selectors will enable them
pub(crate) struct Constraints<F> {
    /// Enabled with q_step
    pub(crate) step: Vec<(&'static str, Expression<F>)>,
    /// Enabled with q_step_first
    pub(crate) step_first: Vec<(&'static str, Expression<F>)>,
    /// Enabled with q_step * q_step_last
    pub(crate) step_last: Vec<(&'static str, Expression<F>)>,
    /// Enabled with q_step * not(q_step_last)
    pub(crate) not_step_last: Vec<(&'static str, Expression<F>)>,
}

pub(crate) struct ConstraintBuilder<'a, F> {
    pub max_degree: usize,
    pub(crate) curr: Step<F>,
    pub(crate) next: Step<F>,
    challenges: &'a Challenges<Expression<F>>,
    execution_state: ExecutionState,
    constraints: Constraints<F>,
    rw_counter_offset: Expression<F>,
    program_counter_offset: usize,
    stack_pointer_offset: Expression<F>,
    log_id_offset: usize,
    in_next_step: bool,
    condition: Option<Expression<F>>,
    constraints_location: ConstraintLocation,
    stored_expressions: Vec<StoredExpression<F>>,
    pub(crate) max_inner_degree: (&'static str, usize),
}

impl<'a, F: Field> ConstraintBuilder<'a, F> {
    pub(crate) fn new(
        curr: Step<F>,
        next: Step<F>,
        challenges: &'a Challenges<Expression<F>>,
        execution_state: ExecutionState,
    ) -> Self {
        Self {
            max_degree: MAX_DEGREE,
            curr,
            next,
            challenges,
            execution_state,
            constraints: Constraints {
                step: Vec::new(),
                step_first: Vec::new(),
                step_last: Vec::new(),
                not_step_last: Vec::new(),
            },
            rw_counter_offset: 0.expr(),
            program_counter_offset: 0,
            stack_pointer_offset: 0.expr(),
            log_id_offset: 0,
            in_next_step: false,
            condition: None,
            constraints_location: ConstraintLocation::Step,
            stored_expressions: Vec::new(),
            max_inner_degree: ("", 0),
        }
    }

    /// Returns (list of constraints, list of first step constraints, stored
    /// expressions, height used).
    #[allow(clippy::type_complexity)]
    pub(crate) fn build(self) -> (Constraints<F>, Vec<StoredExpression<F>>, usize) {
        let exec_state_sel = self.curr.execution_state_selector([self.execution_state]);
        let mul_exec_state_sel = |c: Vec<(&'static str, Expression<F>)>| {
            c.into_iter()
                .map(|(name, constraint)| (name, exec_state_sel.clone() * constraint))
                .collect()
        };
        (
            Constraints {
                step: mul_exec_state_sel(self.constraints.step),
                step_first: mul_exec_state_sel(self.constraints.step_first),
                step_last: mul_exec_state_sel(self.constraints.step_last),
                not_step_last: mul_exec_state_sel(self.constraints.not_step_last),
            },
            self.stored_expressions,
            self.curr.cell_manager.get_height(),
        )
    }

    pub(crate) fn challenges(&self) -> &Challenges<Expression<F>> {
        self.challenges
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

    pub(crate) fn stack_pointer_offset(&self) -> Expression<F> {
        self.stack_pointer_offset.clone()
    }

    pub(crate) fn log_id_offset(&self) -> usize {
        self.log_id_offset
    }

    // Query

    pub(crate) fn copy<E: Expr<F>>(&mut self, value: E) -> Cell<F> {
        let cell = self.query_cell();
        self.require_equal("Copy value to new cell", cell.expr(), value.expr());
        cell
    }

    pub(crate) fn query_bool(&mut self) -> Cell<F> {
        let cell = self.query_cell();
        self.require_boolean("Constrain cell to be a bool", cell.expr());
        cell
    }

    pub(crate) fn query_byte(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::LookupByte)
    }

    pub(crate) fn query_word_rlc<const N: usize>(&mut self) -> RandomLinearCombination<F, N> {
        RandomLinearCombination::<F, N>::new(self.query_bytes(), self.challenges.evm_word())
    }

    pub(crate) fn query_keccak_rlc<const N: usize>(&mut self) -> RandomLinearCombination<F, N> {
        RandomLinearCombination::<F, N>::new(self.query_bytes(), self.challenges.keccak_input())
    }

    pub(crate) fn query_bytes<const N: usize>(&mut self) -> [Cell<F>; N] {
        self.query_bytes_dyn(N).try_into().unwrap()
    }

    pub(crate) fn query_bytes_dyn(&mut self, count: usize) -> Vec<Cell<F>> {
        self.query_cells(CellType::LookupByte, count)
    }

    pub(crate) fn query_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase1)
    }

    pub(crate) fn query_cell_phase2(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePhase2)
    }

    pub(crate) fn query_copy_cell(&mut self) -> Cell<F> {
        self.query_cell_with_type(CellType::StoragePermutation)
    }

    pub(crate) fn query_cell_with_type(&mut self, cell_type: CellType) -> Cell<F> {
        self.query_cells(cell_type, 1).first().unwrap().clone()
    }

    pub(crate) fn query_bool_with_type(&mut self, cell_type: CellType) -> Cell<F> {
        let cell = self.query_cell_with_type(cell_type);
        self.require_boolean("Constrain cell to be a bool", cell.expr());
        cell
    }

    fn query_cells(&mut self, cell_type: CellType, count: usize) -> Vec<Cell<F>> {
        if self.in_next_step {
            &mut self.next
        } else {
            &mut self.curr
        }
        .cell_manager
        .query_cells(cell_type, count)
    }

    pub(crate) fn word_rlc<const N: usize>(&self, bytes: [Expression<F>; N]) -> Expression<F> {
        rlc::expr(&bytes, self.challenges.evm_word())
    }

    pub(crate) fn keccak_rlc<const N: usize>(&self, bytes: [Expression<F>; N]) -> Expression<F> {
        rlc::expr(&bytes, self.challenges.keccak_input())
    }

    pub(crate) fn empty_hash_rlc(&self) -> Expression<F> {
        self.word_rlc((*EMPTY_HASH_LE).map(|byte| byte.expr()))
    }

    // Common

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

    pub(crate) fn require_next_state(&mut self, execution_state: ExecutionState) {
        let next_state = self.next.execution_state_selector([execution_state]);
        self.add_constraint(
            "Constrain next execution state",
            1.expr() - next_state.expr(),
        );
    }

    pub(crate) fn require_next_state_not(&mut self, execution_state: ExecutionState) {
        let next_state = self.next.execution_state_selector([execution_state]);
        self.add_constraint("Constrain next execution state not", next_state.expr());
    }

    pub(crate) fn require_step_state_transition(
        &mut self,
        step_state_transition: StepStateTransition<F>,
    ) {
        macro_rules! constrain {
            ($name:tt) => {
                match step_state_transition.$name {
                    Transition::Same => self.require_equal(
                        concat!("State transition (same) constraint of ", stringify!($name)),
                        self.next.state.$name.expr(),
                        self.curr.state.$name.expr(),
                    ),
                    Transition::Delta(delta) => self.require_equal(
                        concat!("State transition (delta) constraint of ", stringify!($name)),
                        self.next.state.$name.expr(),
                        self.curr.state.$name.expr() + delta,
                    ),
                    Transition::To(to) => self.require_equal(
                        concat!("State transition (to) constraint of ", stringify!($name)),
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
        constrain!(code_hash);
        constrain!(program_counter);
        constrain!(stack_pointer);
        constrain!(gas_left);
        constrain!(memory_word_size);
        constrain!(reversible_write_counter);
        constrain!(log_id);
    }

    // Fixed

    pub(crate) fn range_lookup(&mut self, value: Expression<F>, range: u64) {
        let (name, tag) = match range {
            5 => ("Range5", FixedTableTag::Range5),
            16 => ("Range16", FixedTableTag::Range16),
            32 => ("Range32", FixedTableTag::Range32),
            64 => ("Range64", FixedTableTag::Range64),
            128 => ("Range128", FixedTableTag::Range128),
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

    // constant gas
    pub(crate) fn constant_gas_lookup(&mut self, opcode: Expression<F>, gas: Expression<F>) {
        self.add_lookup(
            "constant gas",
            Lookup::Fixed {
                tag: FixedTableTag::ConstantGasCost.expr(),
                values: [opcode, gas, 0.expr()],
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
        self.add_lookup(
            "Opcode lookup",
            Lookup::Bytecode {
                hash: self.curr.state.code_hash.expr(),
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

    pub(crate) fn bytecode_length(&mut self, code_hash: Expression<F>, value: Expression<F>) {
        self.add_lookup(
            "Bytecode (length)",
            Lookup::Bytecode {
                hash: code_hash,
                tag: BytecodeFieldTag::Header.expr(),
                index: 0.expr(),
                is_code: 0.expr(),
                value,
            },
        );
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
        let word = self.query_word_rlc();
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
        number: Expression<F>,
        val: Expression<F>,
    ) {
        self.add_lookup(
            "Block lookup",
            Lookup::Block {
                field_tag: tag,
                number,
                value: val,
            },
        );
    }

    // Rw

    /// Add a Lookup::Rw without increasing the rw_counter_offset, which is
    /// useful for state reversion or dummy lookup.
    fn rw_lookup_with_counter(
        &mut self,
        name: &str,
        counter: Expression<F>,
        is_write: Expression<F>,
        tag: RwTableTag,
        values: RwValues<F>,
    ) {
        let name = format!("rw lookup {}", name);
        self.add_lookup(
            &name,
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
        values: RwValues<F>,
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
        self.rw_counter_offset = match &self.condition {
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
        values: RwValues<F>,
        reversion_info: Option<&mut ReversionInfo<F>>,
    ) {
        debug_assert!(
            tag.is_reversible(),
            "Reversible write requires reversible tag"
        );

        self.rw_lookup(name, true.expr(), tag, values.clone());

        // Revert if is_persistent is 0
        if let Some(reversion_info) = reversion_info {
            // To allow conditional reversible writes, we extract the pre-existing condition
            // here if it exists, and then reset it afterwards.
            let condition = self.condition.clone();
            self.condition = None;
            self.condition(
                and::expr(&[
                    condition.clone().unwrap_or_else(|| 1.expr()),
                    not::expr(reversion_info.is_persistent()),
                ]),
                |cb| {
                    let name = format!("{} with reversion", name);
                    cb.rw_lookup_with_counter(
                        &name,
                        reversion_info.rw_counter_of_reversion(),
                        true.expr(),
                        tag,
                        RwValues {
                            value_prev: values.value,
                            value: values.value_prev,
                            ..values
                        },
                    )
                },
            );
            self.condition = condition;
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
            RwValues::new(
                tx_id,
                account_address,
                0.expr(),
                0.expr(),
                value,
                value_prev,
                0.expr(),
                0.expr(),
            ),
            reversion_info,
        );
    }

    pub(crate) fn account_access_list_read(
        &mut self,
        tx_id: Expression<F>,
        account_address: Expression<F>,
        value: Expression<F>,
    ) {
        self.rw_lookup(
            "account access list read",
            false.expr(),
            RwTableTag::TxAccessListAccount,
            RwValues::new(
                tx_id,
                account_address,
                0.expr(),
                0.expr(),
                value.clone(),
                value,
                0.expr(),
                0.expr(),
            ),
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
            RwValues::new(
                tx_id,
                account_address,
                0.expr(),
                storage_key,
                value,
                value_prev,
                0.expr(),
                0.expr(),
            ),
            reversion_info,
        );
    }

    pub(crate) fn account_storage_access_list_read(
        &mut self,
        tx_id: Expression<F>,
        account_address: Expression<F>,
        storage_key: Expression<F>,
        value: Expression<F>,
    ) {
        self.rw_lookup(
            "TxAccessListAccountStorage read",
            false.expr(),
            RwTableTag::TxAccessListAccountStorage,
            RwValues::new(
                tx_id,
                account_address,
                0.expr(),
                storage_key,
                value.clone(),
                value,
                0.expr(),
                0.expr(),
            ),
        );
    }

    // Tx Refund

    pub(crate) fn tx_refund_read(&mut self, tx_id: Expression<F>, value: Expression<F>) {
        self.rw_lookup(
            "TxRefund read",
            false.expr(),
            RwTableTag::TxRefund,
            RwValues::new(
                tx_id,
                0.expr(),
                0.expr(),
                0.expr(),
                value.clone(),
                value,
                0.expr(),
                0.expr(),
            ),
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
            RwValues::new(
                tx_id,
                0.expr(),
                0.expr(),
                0.expr(),
                value,
                value_prev,
                0.expr(),
                0.expr(),
            ),
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
            RwValues::new(
                0.expr(),
                account_address,
                field_tag.expr(),
                0.expr(),
                value.clone(),
                value,
                0.expr(),
                0.expr(),
            ),
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
            "Account write",
            RwTableTag::Account,
            RwValues::new(
                0.expr(),
                account_address,
                field_tag.expr(),
                0.expr(),
                value,
                value_prev,
                0.expr(),
                0.expr(),
            ),
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
            RwValues::new(
                tx_id,
                account_address,
                0.expr(),
                key,
                value.clone(),
                value,
                0.expr(),
                committed_value,
            ),
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
            RwValues::new(
                tx_id,
                account_address,
                0.expr(),
                key,
                value,
                value_prev,
                0.expr(),
                committed_value,
            ),
            reversion_info,
        );
    }

    // Call context

    pub(crate) fn call_context(
        &mut self,
        call_id: Option<Expression<F>>,
        field_tag: CallContextFieldTag,
    ) -> Cell<F> {
        let phase = match field_tag {
            CallContextFieldTag::CodeHash => CellType::StoragePhase2,
            _ => CellType::StoragePhase1,
        };
        let cell = self.query_cell_with_type(phase);
        self.call_context_lookup(false.expr(), call_id, field_tag, cell.expr());
        cell
    }

    pub(crate) fn call_context_as_word(
        &mut self,
        call_id: Option<Expression<F>>,
        field_tag: CallContextFieldTag,
    ) -> Word<F> {
        let word = self.query_word_rlc();
        self.call_context_lookup(false.expr(), call_id, field_tag, word.expr());
        word
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
            RwValues::new(
                call_id.unwrap_or_else(|| self.curr.state.call_id.expr()),
                0.expr(),
                field_tag.expr(),
                0.expr(),
                value,
                0.expr(),
                0.expr(),
                0.expr(),
            ),
        );
    }

    fn reversion_info(
        &mut self,
        call_id: Option<Expression<F>>,
        is_write: bool,
    ) -> ReversionInfo<F> {
        let [rw_counter_end_of_reversion, is_persistent] = [
            CallContextFieldTag::RwCounterEndOfReversion,
            CallContextFieldTag::IsPersistent,
        ]
        .map(|field_tag| {
            let cell = self.query_cell();
            self.call_context_lookup(is_write.expr(), call_id.clone(), field_tag, cell.expr());
            cell
        });

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

    pub(crate) fn reversion_info_read(
        &mut self,
        call_id: Option<Expression<F>>,
    ) -> ReversionInfo<F> {
        self.reversion_info(call_id, false)
    }

    pub(crate) fn reversion_info_write(
        &mut self,
        call_id: Option<Expression<F>>,
    ) -> ReversionInfo<F> {
        self.reversion_info(call_id, true)
    }

    // Stack

    pub(crate) fn stack_pop(&mut self, value: Expression<F>) {
        self.stack_lookup(false.expr(), self.stack_pointer_offset.clone(), value);
        self.stack_pointer_offset = self.stack_pointer_offset.clone() + self.condition_expr();
    }

    pub(crate) fn stack_push(&mut self, value: Expression<F>) {
        self.stack_pointer_offset = self.stack_pointer_offset.clone() - self.condition_expr();
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
            RwValues::new(
                self.curr.state.call_id.expr(),
                self.curr.state.stack_pointer.expr() + stack_pointer_offset,
                0.expr(),
                0.expr(),
                value,
                0.expr(),
                0.expr(),
                0.expr(),
            ),
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
            RwValues::new(
                call_id.unwrap_or_else(|| self.curr.state.call_id.expr()),
                memory_address,
                0.expr(),
                0.expr(),
                byte,
                0.expr(),
                0.expr(),
                0.expr(),
            ),
        );
    }

    pub(crate) fn tx_log_lookup(
        &mut self,
        tx_id: Expression<F>,
        log_id: Expression<F>,
        field_tag: TxLogFieldTag,
        index: Expression<F>,
        value: Expression<F>,
    ) {
        self.rw_lookup(
            "log data lookup",
            1.expr(),
            RwTableTag::TxLog,
            RwValues::new(
                tx_id,
                build_tx_log_expression(index, field_tag.expr(), log_id),
                0.expr(),
                0.expr(),
                value,
                0.expr(),
                0.expr(),
                0.expr(),
            ),
        );
    }

    // Tx Receipt

    pub(crate) fn tx_receipt_lookup(
        &mut self,
        is_write: Expression<F>,
        tx_id: Expression<F>,
        tag: TxReceiptFieldTag,
        value: Expression<F>,
    ) {
        self.rw_lookup(
            "tx receipt lookup",
            is_write,
            RwTableTag::TxReceipt,
            RwValues::new(
                tx_id,
                0.expr(),
                tag.expr(),
                0.expr(),
                value,
                0.expr(),
                0.expr(),
                0.expr(),
            ),
        );
    }

    // RwTable Padding (Start tag)

    pub(crate) fn rw_table_start_lookup(&mut self, counter: Expression<F>) {
        self.rw_lookup_with_counter(
            "Start lookup",
            counter,
            0.expr(),
            RwTableTag::Start,
            RwValues {
                id: 0.expr(),
                address: 0.expr(),
                field_tag: 0.expr(),
                storage_key: 0.expr(),
                value: 0.expr(),
                value_prev: 0.expr(),
                aux1: 0.expr(),
                aux2: 0.expr(),
            },
        );
    }

    // Copy Table

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn copy_table_lookup(
        &mut self,
        src_id: Expression<F>,
        src_tag: Expression<F>,
        dst_id: Expression<F>,
        dst_tag: Expression<F>,
        src_addr: Expression<F>,
        src_addr_end: Expression<F>,
        dst_addr: Expression<F>,
        length: Expression<F>,
        rlc_acc: Expression<F>,
        rwc_inc: Expression<F>,
    ) {
        self.add_lookup(
            "copy lookup",
            Lookup::CopyTable {
                is_first: 1.expr(), // is_first
                src_id,
                src_tag,
                dst_id,
                dst_tag,
                src_addr,
                src_addr_end,
                dst_addr,
                length,
                rlc_acc,
                rw_counter: self.curr.state.rw_counter.expr() + self.rw_counter_offset(),
                rwc_inc: rwc_inc.clone(),
            },
        );
        self.rw_counter_offset = self.rw_counter_offset.clone() + self.condition_expr() * rwc_inc;
    }

    // Exponentiation Table

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn exp_table_lookup(
        &mut self,
        identifier: Expression<F>,
        is_last: Expression<F>,
        base_limbs: [Expression<F>; 4],
        exponent_lo_hi: [Expression<F>; 2],
        exponentiation_lo_hi: [Expression<F>; 2],
    ) {
        self.add_lookup(
            "exponentiation lookup",
            Lookup::ExpTable {
                identifier,
                is_last,
                base_limbs,
                exponent_lo_hi,
                exponentiation_lo_hi,
            },
        );
    }

    // Keccak Table

    pub(crate) fn keccak_table_lookup(
        &mut self,
        input_rlc: Expression<F>,
        input_len: Expression<F>,
        output_rlc: Expression<F>,
    ) {
        self.add_lookup(
            "keccak lookup",
            Lookup::KeccakTable {
                input_rlc,
                input_len,
                output_rlc,
            },
        );
    }

    // Validation

    pub(crate) fn validate_degree(&self, degree: usize, name: &'static str) {
        // We need to subtract IMPLICIT_DEGREE from MAX_DEGREE because all expressions
        // will be multiplied by state selector and q_step/q_step_first
        // selector.
        debug_assert!(
            degree <= MAX_DEGREE - IMPLICIT_DEGREE,
            "Expression {} degree too high: {} > {}",
            name,
            degree,
            MAX_DEGREE - IMPLICIT_DEGREE,
        );
    }

    // General

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
        for (name, constraint) in constraints {
            self.add_constraint(name, constraint);
        }
    }

    pub(crate) fn add_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        let constraint = self.split_expression(
            name,
            constraint * self.condition_expr(),
            MAX_DEGREE - IMPLICIT_DEGREE,
        );

        self.validate_degree(constraint.degree(), name);
        self.push_constraint(name, constraint);
    }

    /// TODO: Doc
    fn constraint_at_location<R>(
        &mut self,
        location: ConstraintLocation,
        constraint: impl FnOnce(&mut Self) -> R,
    ) -> R {
        debug_assert_eq!(
            self.constraints_location,
            ConstraintLocation::Step,
            "ConstraintLocation can't be combined"
        );
        self.constraints_location = location;
        let ret = constraint(self);
        self.constraints_location = ConstraintLocation::Step;
        ret
    }
    /// TODO: Doc
    pub(crate) fn step_first<R>(&mut self, constraint: impl FnOnce(&mut Self) -> R) -> R {
        self.constraint_at_location(ConstraintLocation::StepFirst, constraint)
    }
    /// TODO: Doc
    pub(crate) fn step_last<R>(&mut self, constraint: impl FnOnce(&mut Self) -> R) -> R {
        self.constraint_at_location(ConstraintLocation::StepLast, constraint)
    }
    /// TODO: Doc
    pub(crate) fn not_step_last<R>(&mut self, constraint: impl FnOnce(&mut Self) -> R) -> R {
        self.constraint_at_location(ConstraintLocation::NotStepLast, constraint)
    }

    /// TODO: Doc
    fn push_constraint(&mut self, name: &'static str, constraint: Expression<F>) {
        match self.constraints_location {
            ConstraintLocation::Step => self.constraints.step.push((name, constraint)),
            ConstraintLocation::StepFirst => self.constraints.step_first.push((name, constraint)),
            ConstraintLocation::StepLast => self.constraints.step_last.push((name, constraint)),
            ConstraintLocation::NotStepLast => {
                self.constraints.not_step_last.push((name, constraint))
            }
        }
    }

    pub(crate) fn add_lookup(&mut self, name: &str, lookup: Lookup<F>) {
        let lookup = match &self.condition {
            Some(condition) => lookup.conditional(condition.clone()),
            None => lookup,
        };
        let compressed_expr = self.split_expression(
            "Lookup compression",
            rlc::expr(&lookup.input_exprs(), self.challenges.lookup_input()),
            MAX_DEGREE - IMPLICIT_DEGREE,
        );
        self.store_expression(name, compressed_expr, CellType::Lookup(lookup.table()));
    }

    pub(crate) fn store_expression(
        &mut self,
        name: &str,
        expr: Expression<F>,
        cell_type: CellType,
    ) -> Expression<F> {
        // Check if we already stored the expression somewhere
        let stored_expression = self.find_stored_expression(&expr, cell_type);

        match stored_expression {
            Some(stored_expression) => {
                debug_assert!(
                    !matches!(cell_type, CellType::Lookup(_)),
                    "The same lookup is done multiple times",
                );
                stored_expression.cell.expr()
            }
            None => {
                // Even if we're building expressions for the next step,
                // these intermediate values need to be stored in the current step.
                let in_next_step = self.in_next_step;
                self.in_next_step = false;
                let cell = self.query_cell_with_type(cell_type);
                self.in_next_step = in_next_step;

                // Require the stored value to equal the value of the expression
                let name = format!("{} (stored expression)", name);
                self.push_constraint(
                    Box::leak(name.clone().into_boxed_str()),
                    cell.expr() - expr.clone(),
                );

                self.stored_expressions.push(StoredExpression {
                    name,
                    cell: cell.clone(),
                    cell_type,
                    expr_id: expr.identifier(),
                    expr,
                });
                cell.expr()
            }
        }
    }

    pub(crate) fn find_stored_expression(
        &self,
        expr: &Expression<F>,
        cell_type: CellType,
    ) -> Option<&StoredExpression<F>> {
        let expr_id = expr.identifier();
        self.stored_expressions
            .iter()
            .find(|&e| e.cell_type == cell_type && e.expr_id == expr_id)
    }

    fn split_expression(
        &mut self,
        name: &'static str,
        expr: Expression<F>,
        max_degree: usize,
    ) -> Expression<F> {
        if expr.degree() > self.max_inner_degree.1 {
            self.max_inner_degree = (name, expr.degree());
        }
        if expr.degree() > max_degree {
            match expr {
                Expression::Negated(poly) => {
                    Expression::Negated(Box::new(self.split_expression(name, *poly, max_degree)))
                }
                Expression::Scaled(poly, v) => {
                    Expression::Scaled(Box::new(self.split_expression(name, *poly, max_degree)), v)
                }
                Expression::Sum(a, b) => {
                    let a = self.split_expression(name, *a, max_degree);
                    let b = self.split_expression(name, *b, max_degree);
                    a + b
                }
                Expression::Product(a, b) => {
                    let (mut a, mut b) = (*a, *b);
                    while a.degree() + b.degree() > max_degree {
                        let mut split = |expr: Expression<F>| {
                            if expr.degree() > max_degree {
                                self.split_expression(name, expr, max_degree)
                            } else {
                                let cell_type = CellType::storage_for_expr(&expr);
                                self.store_expression(name, expr, cell_type)
                            }
                        };
                        if a.degree() >= b.degree() {
                            a = split(a);
                        } else {
                            b = split(b);
                        }
                    }
                    a * b
                }
                _ => expr.clone(),
            }
        } else {
            expr.clone()
        }
    }

    fn condition_expr(&self) -> Expression<F> {
        match &self.condition {
            Some(condition) => condition.clone(),
            None => 1.expr(),
        }
    }
}
