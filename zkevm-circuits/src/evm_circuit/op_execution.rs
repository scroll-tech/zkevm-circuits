use super::{
    param::{
        CIRCUIT_HEIGHT, CIRCUIT_WIDTH, NUM_CELL_OP_EXECUTION_STATE,
        NUM_CELL_OP_GADGET_SELECTOR, NUM_CELL_RESUMPTION,
    },
    Case, Cell, Constraint, CoreStateInstance, ExecutionStep, Lookup, Word,
};
use crate::util::Expr;
use bus_mapping::evm::OpcodeId;
use halo2::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{ConstraintSystem, Error, Expression},
};
use std::{collections::HashMap, ops::Range};

mod arithmetic;
mod comparator;
mod pop;
mod push;
mod dup;

use arithmetic::AddGadget;
use comparator::LtGadget;
use pop::PopGadget;
use push::PushGadget;
use dup::DupGadget;

fn bool_switches_constraints<F: FieldExt>(
    bool_switches: &[Cell<F>],
) -> Vec<Expression<F>> {
    let mut constraints = Vec::with_capacity(bool_switches.len() + 1);
    let mut sum_to_one = 0.expr();

    for switch in bool_switches {
        constraints.push(switch.expr() * (1.expr() - switch.expr()));
        sum_to_one = sum_to_one + switch.expr();
    }

    constraints.push(1.expr() - sum_to_one);

    constraints
}

#[derive(Debug)]
struct CaseConfig {
    case: Case,
    num_word: usize,
    num_cell: usize,
    will_halt: bool,
}

impl CaseConfig {
    fn num_total_cell(&self) -> usize {
        32 * self.num_word
            + self.num_cell
            + if self.will_halt {
                NUM_CELL_RESUMPTION
            } else {
                0
            }
    }

    // allocate indices of cells for words, cells and unused. It assumes input
    // free_cells are in order of rotation and then column index.
    fn allocate_indices<F: FieldExt>(
        &self,
        num_case: usize,
        free_cells: &[Cell<F>],
    ) -> (Vec<Range<usize>>, Vec<usize>, Vec<usize>) {
        let num_free_cell = free_cells.len();
        let num_total_cell = num_case + self.num_total_cell();
        assert!(num_free_cell >= num_total_cell);

        let num_unused = num_free_cell - num_total_cell;
        let word_height = 32 / CIRCUIT_WIDTH;

        let mut word_ranges = Vec::with_capacity(self.num_word);
        let mut cell_idxs = Vec::with_capacity(self.num_cell + num_unused);

        let mut begin_idx = num_case;
        let mut rotation_range = Range::default();
        for (idx, cell) in free_cells.iter().enumerate() {
            // skip case selector
            if idx < num_case {
                continue;
            }

            let next_idx = idx + 1;
            if next_idx == num_free_cell || word_ranges.len() == self.num_word {
                cell_idxs.append(&mut (idx..num_free_cell).collect());
                break;
            }

            // find cells in rectangle region for words
            if rotation_range.contains(&cell.rotation) {
                if next_idx - begin_idx == 32 {
                    let next_cell = &free_cells[next_idx];
                    word_ranges.push(begin_idx..next_idx);
                    begin_idx = next_idx;
                    rotation_range =
                        next_cell.rotation..next_cell.rotation + word_height;
                }
            } else {
                cell_idxs.append(&mut (begin_idx..idx).collect());
                begin_idx = idx;
                rotation_range = cell.rotation..cell.rotation + word_height;
            }
        }

        assert_eq!(
            word_ranges.len(),
            self.num_word,
            "not enough rectangle regions for words"
        );

        let (cell_idxs, unused_idxs) = cell_idxs.split_at(self.num_cell);
        (word_ranges, cell_idxs.to_vec(), unused_idxs.to_vec())
    }
}

#[derive(Debug)]
struct CaseAllocation<F> {
    selector: Cell<F>,
    words: Vec<Word<F>>,
    cells: Vec<Cell<F>>,
    resumption: Option<Resumption<F>>,
}

#[derive(Clone, Debug)]
struct Resumption<F> {
    caller_id: Cell<F>,
    gas_available: Cell<F>,
}

impl<F: FieldExt> Resumption<F> {
    fn new(cells: &[Cell<F>]) -> Self {
        assert_eq!(cells.len(), NUM_CELL_RESUMPTION);

        Self {
            caller_id: cells[0].clone(),
            gas_available: cells[1].clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct OpExecutionState<F> {
    pub is_executing: Cell<F>,
    pub global_counter: Cell<F>,
    pub call_id: Cell<F>,
    pub program_counter: Cell<F>,
    pub stack_pointer: Cell<F>,
    gas_counter: Cell<F>,
    opcode: Cell<F>,
}

impl<F: FieldExt> OpExecutionState<F> {
    pub(crate) fn new(cells: &[Cell<F>]) -> Self {
        assert_eq!(cells.len(), NUM_CELL_OP_EXECUTION_STATE);

        Self {
            is_executing: cells[0].clone(),
            global_counter: cells[1].clone(),
            call_id: cells[2].clone(),
            program_counter: cells[3].clone(),
            stack_pointer: cells[4].clone(),
            gas_counter: cells[5].clone(),
            opcode: cells[6].clone(),
        }
    }
}

trait OpGadget<F: FieldExt> {
    const RESPONSIBLE_OPCODES: &'static [OpcodeId];

    const CASE_CONFIGS: &'static [CaseConfig];

    fn construct(case_allocations: Vec<CaseAllocation<F>>) -> Self;

    fn constraints(
        &self,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
    ) -> Vec<Constraint<F>>;

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        core_state: &mut CoreStateInstance,
        execution_step: &ExecutionStep,
    ) -> Result<(), Error>;
}

// Preset stores default values for each case of op gadget
#[derive(Clone, Default)]
struct Preset<F> {
    qs_byte_lookups: [F; CIRCUIT_HEIGHT],
    free_cells: Vec<(usize, F)>,
}

#[derive(Clone)]
pub(crate) struct OpExecutionGadget<F> {
    r: F,
    qs_byte_lookups: Vec<Cell<F>>,
    state_curr: OpExecutionState<F>,
    state_next: OpExecutionState<F>,
    qs_ops: Vec<Cell<F>>,
    free_cells: Vec<Cell<F>>,
    resumption: Resumption<F>,
    qs_op_idx_map: HashMap<OpcodeId, usize>,
    preset_map: HashMap<(usize, Case), Preset<F>>,
    add_gadget: AddGadget<F>,
    push_gadget: PushGadget<F>,
    lt_gadget: LtGadget<F>,
    pop_gadget: PopGadget<F>,
    dup1_gadget: DupGadget<F, 0x80>,
    dup2_gadget: DupGadget<F, 0x81>,
    dup3_gadget: DupGadget<F, 0x82>,
    dup4_gadget: DupGadget<F, 0x83>,
    dup5_gadget: DupGadget<F, 0x84>,
    dup6_gadget: DupGadget<F, 0x85>,
    dup7_gadget: DupGadget<F, 0x86>,
    dup8_gadget: DupGadget<F, 0x87>,
    dup9_gadget: DupGadget<F, 0x88>,
    dup10_gadget: DupGadget<F, 0x89>,
    dup11_gadget: DupGadget<F, 0x8a>,
    dup12_gadget: DupGadget<F, 0x8b>,
    dup13_gadget: DupGadget<F, 0x8c>,
    dup14_gadget: DupGadget<F, 0x8d>,
    dup15_gadget: DupGadget<F, 0x8e>,
    dup16_gadget: DupGadget<F, 0x8f>,
}

impl<F: FieldExt> OpExecutionGadget<F> {
    // TODO: refactor input type
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        r: F,
        qs_op_execution: Expression<F>,
        qs_byte_lookups: Vec<Cell<F>>,
        state_curr: OpExecutionState<F>,
        state_next: OpExecutionState<F>,
        free_cells: Vec<Cell<F>>,
        independent_lookups: &mut Vec<(Expression<F>, Vec<Lookup<F>>)>,
    ) -> Self {
        let (qs_ops, free_cells) =
            free_cells.split_at(NUM_CELL_OP_GADGET_SELECTOR);
        let resumption = Resumption::new(
            &free_cells[free_cells.len() - NUM_CELL_RESUMPTION..],
        );

        let mut qs_op_idx_map = HashMap::new();
        let mut preset_map = HashMap::new();
        let mut qs_op_idx = 0;

        let mut constraints = vec![Constraint {
            name: "op selectors",
            selector: 1.expr(),
            polys: bool_switches_constraints(qs_ops),
            lookups: vec![],
        }];

        // This helps construct different gadgets that implement trait OpGadget
        // with identical inputs.
        macro_rules! construct_op_gadget {
            ($name:ident) => {
                let $name = Self::construct_op_gadget(
                    r,
                    &state_curr,
                    &state_next,
                    &qs_byte_lookups[..],
                    qs_ops,
                    qs_op_idx,
                    free_cells,
                    &resumption,
                    &mut qs_op_idx_map,
                    &mut preset_map,
                    &mut constraints,
                );
                qs_op_idx += 1;
            };
        }

        construct_op_gadget!(add_gadget);
        construct_op_gadget!(push_gadget);
        construct_op_gadget!(lt_gadget);
        construct_op_gadget!(pop_gadget);
        construct_op_gadget!(dup1_gadget);
        construct_op_gadget!(dup2_gadget);
        construct_op_gadget!(dup3_gadget);
        construct_op_gadget!(dup4_gadget);
        construct_op_gadget!(dup5_gadget);
        construct_op_gadget!(dup6_gadget);
        construct_op_gadget!(dup7_gadget);
        construct_op_gadget!(dup8_gadget);
        construct_op_gadget!(dup9_gadget);
        construct_op_gadget!(dup10_gadget);
        construct_op_gadget!(dup11_gadget);
        construct_op_gadget!(dup12_gadget);
        construct_op_gadget!(dup13_gadget);
        construct_op_gadget!(dup14_gadget);
        construct_op_gadget!(dup15_gadget);
        construct_op_gadget!(dup16_gadget);
        let _ = qs_op_idx;

        for constraint in constraints.into_iter() {
            let Constraint {
                name,
                selector: qs_op_case,
                polys,
                lookups,
            } = constraint;

            let qs = qs_op_execution.clone() * qs_op_case.clone();

            meta.create_gate(name, |_| {
                if polys.is_empty() {
                    return vec![0.expr()];
                }
                polys
                    .into_iter()
                    .map(|poly| qs.clone() * poly)
                    .collect::<Vec<_>>()
            });

            independent_lookups.push((qs, lookups));
        }

        Self {
            r,
            qs_byte_lookups,
            state_curr,
            state_next,
            qs_ops: qs_ops.to_vec(),
            free_cells: free_cells.to_vec(),
            qs_op_idx_map,
            preset_map,
            resumption,
            add_gadget,
            push_gadget,
            lt_gadget,
            pop_gadget,
            dup1_gadget,
            dup2_gadget,
            dup3_gadget,
            dup4_gadget,
            dup5_gadget,
            dup6_gadget,
            dup7_gadget,
            dup8_gadget,
            dup9_gadget,
            dup10_gadget,
            dup11_gadget,
            dup12_gadget,
            dup13_gadget,
            dup14_gadget,
            dup15_gadget,
            dup16_gadget,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn construct_op_gadget<O: OpGadget<F>>(
        r: F,
        state_curr: &OpExecutionState<F>,
        state_next: &OpExecutionState<F>,
        qs_byte_lookups: &[Cell<F>],
        qs_ops: &[Cell<F>],
        qs_op_idx: usize,
        free_cells: &[Cell<F>],
        resumption: &Resumption<F>,
        qs_op_idx_map: &mut HashMap<OpcodeId, usize>,
        preset_map: &mut HashMap<(usize, Case), Preset<F>>,
        constraints: &mut Vec<Constraint<F>>,
    ) -> O {
        assert!(qs_op_idx < NUM_CELL_OP_GADGET_SELECTOR);

        let qs_op = &qs_ops[qs_op_idx];

        // opcode should only be handled by one gadget
        for opcode in O::RESPONSIBLE_OPCODES {
            assert!(
                qs_op_idx_map.insert(*opcode, qs_op_idx).is_none(),
                "opcode is already handled by another gadget"
            );
        }

        let case_configs = O::CASE_CONFIGS;
        let num_case = case_configs.len();
        let qs_cases = &free_cells[..num_case];

        constraints.push(Constraint {
            name: "case selectors",
            selector: qs_op.expr(),
            polys: bool_switches_constraints(qs_cases),
            lookups: vec![],
        });

        let case_allocations = case_configs
            .iter()
            .enumerate()
            .map(|(q_case_idx, case_config)| {
                let mut preset = Preset::default();

                // case selector values to assign
                for idx in 0..case_configs.len() {
                    preset
                        .free_cells
                        .push((idx, F::from_u64((idx == q_case_idx) as u64)));
                }

                let (word_ranges, cell_idxs, unused_idxs) =
                    case_config.allocate_indices(num_case, free_cells);

                let words = word_ranges
                    .into_iter()
                    .map(|range| {
                        for idx in range.clone() {
                            preset.qs_byte_lookups[free_cells[idx].rotation] =
                                F::one();
                        }
                        Word::new(&free_cells[range], r)
                    })
                    .collect::<Vec<_>>();

                let cells = cell_idxs
                    .into_iter()
                    .map(|idx| free_cells[idx].clone())
                    .collect();

                let resumption = if case_config.will_halt {
                    Some(resumption.clone())
                } else {
                    None
                };

                for idx in unused_idxs.iter() {
                    preset.free_cells.push((*idx, F::zero()));
                }

                let qs_case = &qs_cases[q_case_idx];
                constraints.push(Constraint {
                    name: "case qs_byte_lookups",
                    selector: qs_op.expr() * qs_case.expr(),
                    polys: preset
                        .qs_byte_lookups
                        .iter()
                        .enumerate()
                        .map(|(idx, value)| {
                            if value.is_zero() {
                                // constraint qs_byte_lookup to 0 by default
                                qs_byte_lookups[idx].expr()
                            } else {
                                // constraint qs_byte_lookup to 1 to enable byte lookup
                                1.expr() - qs_byte_lookups[idx].expr()
                            }
                        })
                        .collect(),
                    lookups: vec![],
                });
                constraints.push(Constraint {
                    name: "case unused",
                    selector: qs_op.expr() * qs_case.expr(),
                    polys: unused_idxs
                        .into_iter()
                        .map(|idx| free_cells[idx].expr())
                        .collect(),
                    lookups: vec![],
                });

                assert!(
                    preset_map
                        .insert((qs_op_idx, case_config.case), preset)
                        .is_none(),
                    "duplicated case configured"
                );

                CaseAllocation {
                    selector: qs_case.clone(),
                    words,
                    cells,
                    resumption,
                }
            })
            .collect::<Vec<_>>();

        let gadget = O::construct(case_allocations);

        constraints.append(
            &mut gadget
                .constraints(state_curr, state_next)
                .into_iter()
                .map(|mut constraint| {
                    assert!(
                        matches!(constraint.selector, Expression::Advice{ .. }),
                        "constraint selector of case should be a queried advice"
                    );

                    constraint.selector =
                        qs_op.expr() * constraint.selector.clone();
                    constraint
                })
                .collect(),
        );

        gadget
    }

    pub(crate) fn assign_execution_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        core_state: &mut CoreStateInstance,
        execution_step: Option<&ExecutionStep>,
    ) -> Result<(), Error> {
        assert!(core_state.is_executing);

        self.state_curr
            .is_executing
            .assign(region, offset, Some(F::one()))?;
        self.state_curr.global_counter.assign(
            region,
            offset,
            Some(F::from_u64(core_state.global_counter as u64)),
        )?;
        self.state_curr.call_id.assign(
            region,
            offset,
            Some(F::from_u64(core_state.call_id as u64)),
        )?;
        self.state_curr.program_counter.assign(
            region,
            offset,
            Some(F::from_u64(core_state.program_counter as u64)),
        )?;
        self.state_curr.stack_pointer.assign(
            region,
            offset,
            Some(F::from_u64(core_state.stack_pointer as u64)),
        )?;
        self.state_curr.gas_counter.assign(
            region,
            offset,
            Some(F::from_u64(core_state.gas_counter as u64)),
        )?;

        if let Some(execution_step) = execution_step {
            self.state_curr.opcode.assign(
                region,
                offset,
                Some(F::from_u64(execution_step.opcode.as_u8() as u64)),
            )?;

            let &qs_op_idx = self
                .qs_op_idx_map
                .get(&execution_step.opcode)
                .expect("opcode to be handled");
            for (idx, q_op) in self.qs_ops.iter().enumerate() {
                q_op.assign(
                    region,
                    offset,
                    Some(F::from_u64((idx == qs_op_idx) as u64)),
                )?;
            }

            let preset = self
                .preset_map
                .get(&(qs_op_idx, execution_step.case))
                .expect("case to be handled");
            for (cell, value) in self
                .qs_byte_lookups
                .iter()
                .zip(preset.qs_byte_lookups.iter())
            {
                cell.assign(region, offset, Some(*value))?;
            }

            for (idx, value) in &preset.free_cells {
                self.free_cells[*idx].assign(region, offset, Some(*value))?;
            }

            match (execution_step.opcode.is_push(), execution_step.opcode) {
                // PUSH1, ..., PUSH32
                (true, _) => self.push_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::ADD | OpcodeId::SUB) => self.add_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::LT | OpcodeId::GT) => self.lt_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::POP) => self.pop_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP1) => self.dup1_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP2) => self.dup2_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP3) => self.dup3_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP4) => self.dup4_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP5) => self.dup5_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP6) => self.dup6_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP7) => self.dup7_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP8) => self.dup8_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP9) => self.dup9_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP10) => self.dup10_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP11) => self.dup11_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP12) => self.dup12_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP13) => self.dup13_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP14) => self.dup14_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP15) => self.dup15_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                (_, OpcodeId::DUP16) => self.dup16_gadget.assign(
                    region,
                    offset,
                    core_state,
                    execution_step,
                )?,
                
                _ => unimplemented!(),
            }
        }

        Ok(())
    }
}
