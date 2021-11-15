//! The EVM circuit implementation.

use crate::util::Expr;
use bus_mapping::{evm::OpcodeId, operation::Target};
use halo2::{
    arithmetic::FieldExt,
    circuit::{self, Layouter, Region},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
    },
    poly::Rotation,
};
use num::BigUint;
use std::{convert::TryInto, iter};

mod op_execution;
use op_execution::{OpExecutionGadget, OpExecutionState};
mod param;
use param::{CIRCUIT_HEIGHT, CIRCUIT_WIDTH, NUM_CELL_OP_EXECUTION_STATE};

#[derive(Clone, Debug)]
pub(crate) enum CallField {
    // Transaction id.
    TxId,
    // Global counter at the begin of call.
    GlobalCounterBegin,
    // Global counter at the end of call, used for locating reverting section.
    GlobalCounterEnd,
    // Caller’s unique identifier.
    CallerID,
    // Offset of calldata.
    CalldataOffset,
    // Size of calldata.
    CalldataSize,
    // Depth of call, should be expected in range 0..=1024.
    Depth,
    // Address of caller.
    CallerAddress,
    // Address of code which interpreter is executing, could differ from
    // `ReceiverAddress` when delegate call.
    CodeAddress,
    // Address of receiver.
    ReceiverAddress,
    // Gas given of call.
    GasAvailable,
    // Value in wei of call.
    Value,
    // If call succeeds or not in the future.
    IsPersistent,
    // If call is within a static call.
    IsStatic,
    // If call is `CREATE*`. We lookup op from calldata when is create,
    // otherwise we lookup code under address.
    IsCreate,
}

#[derive(Clone, Debug)]
pub(crate) enum CallStateField {
    // Program counter.
    ProgramCounter,
    // Stack pointer.
    StackPointer,
    // Memory size.
    MemeorySize,
    // Gas counter.
    GasCounter,
    // State trie write counter.
    StateWriteCounter,
    // Last callee's unique identifier.
    CalleeID,
    // Offset of returndata.
    ReturndataOffset,
    // Size of returndata.
    ReturndataSize,
}

#[derive(Clone, Debug)]
pub(crate) enum BusMappingLookup<F> {
    // Read-Write
    OpExecutionState {
        is_write: bool,
        field: CallStateField,
        value: Expression<F>,
    },
    Stack {
        is_write: bool,
        // One can only access its own stack, so id is no needed to be
        // specified.
        // Stack index is always deterministic respect to stack pointer, so an
        // index offset is enough.
        index_offset: Expression<F>,
        value: Expression<F>,
    },
    Memory {
        is_write: bool,
        // Some ops like CALLDATALOAD can peek caller's memeory as calldata, so
        // we allow it to specify the call id.
        call_id: Expression<F>,
        index: Expression<F>,
        value: Expression<F>,
    },
    AccountStorage {
        is_write: bool,
        address: Expression<F>,
        location: Expression<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
    },
    // TODO: AccountNonce,
    // TODO: AccountBalance,
    // TODO: AccountCodeHash,

    // Read-Only
    Call {
        field: CallField,
        value: Expression<F>,
    },
    Bytecode {
        hash: Expression<F>,
        index: Expression<F>,
        push_rindex: Expression<F>,
        is_code: Expression<F>,
        value: Expression<F>,
    },
    /* TODO: Block,
     * TODO: Bytecode,
     * TODO: Tx,
     * TODO: TxCalldata, */
}

impl<F: FieldExt> BusMappingLookup<F> {
    fn rw_target(&self) -> Target {
        match self {
            Self::Stack { .. } => Target::Stack,
            Self::Memory { .. } => Target::Memory,
            Self::AccountStorage { .. } => Target::Storage,
            _ => unimplemented!(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialOrd, PartialEq, Eq, Ord)]
pub(crate) enum FixedLookup {
    // Noop provides [0, 0, 0, 0] row
    Noop,
    // meaningful tags start with 1
    Range256,
    Range32,
    Range17,
    Range16,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    SignByte,
}

#[derive(Clone, Copy, Debug, PartialOrd, PartialEq, Eq, Ord)]
pub(crate) enum BytecodeLookup {
    // Noop provides [0, 0, 0, 0,0] row
    Noop,
    // meaningful tags start with 1
    BytecodeTable,
    Memory,
    CallData,
}

impl<F: FieldExt> Expr<F> for FixedLookup {
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from_u64(*self as u64))
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Lookup<F> {
    FixedLookup(FixedLookup, [Expression<F>; 3]),
    BusMappingLookup(BusMappingLookup<F>),
    BytecodeLookup(BytecodeLookup, [Expression<F>; 5]),
}

#[derive(Clone, Debug)]
pub(crate) struct Constraint<F> {
    name: &'static str,
    selector: Expression<F>,
    polys: Vec<Expression<F>>,
    lookups: Vec<Lookup<F>>,
}

#[derive(Clone, Debug)]
pub(crate) struct Cell<F> {
    // expression for constraint
    expression: Expression<F>,
    column: Column<Advice>,
    // relative position to selector for synthesis
    rotation: usize,
}

impl<F: FieldExt> Cell<F> {
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Option<F>,
    ) -> Result<circuit::Cell, Error> {
        region.assign_advice(
            || {
                format!(
                    "Cell column: {:?} and rotation: {}",
                    self.column, self.rotation
                )
            },
            self.column,
            offset + self.rotation,
            || value.ok_or(Error::SynthesisError),
        )
    }
}

impl<F: FieldExt> Expr<F> for Cell<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

// TODO: Integrate with evm_word
#[derive(Clone, Debug)]
struct Word<F> {
    // random linear combination expression of cells
    expression: Expression<F>,
    // inner cells for synthesis
    cells: [Cell<F>; 32],
}

impl<F: FieldExt> Word<F> {
    fn new(cells: &[Cell<F>], r: F) -> Self {
        let r = Expression::Constant(r);
        Self {
            expression: cells
                .iter()
                .rev()
                .fold(0.expr(), |acc, byte| acc * r.clone() + byte.expr()),
            cells: cells.to_owned().try_into().unwrap(),
        }
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        word: Option<[u8; 32]>,
    ) -> Result<Vec<circuit::Cell>, Error> {
        word.map_or(Err(Error::SynthesisError), |word| {
            self.cells
                .iter()
                .zip(word.iter())
                .map(|(cell, byte)| {
                    cell.assign(region, offset, Some(F::from_u64(*byte as u64)))
                })
                .collect()
        })
    }
}

impl<F: FieldExt> Expr<F> for Word<F> {
    fn expr(&self) -> Expression<F> {
        self.expression.clone()
    }
}

// TODO: Should we maintain these state in circuit or we prepare all of them
// when parsing debug trace?
#[derive(Debug)]
pub(crate) struct CoreStateInstance {
    is_executing: bool,
    global_counter: usize,
    call_id: usize,
    program_counter: usize,
    stack_pointer: usize,
    gas_counter: usize,
}

impl CoreStateInstance {
    fn new(call_id: usize) -> Self {
        Self {
            is_executing: false,
            global_counter: 1,
            call_id,
            program_counter: 0,
            stack_pointer: 1024,
            gas_counter: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Case {
    Success,
    // out of gas
    OutOfGas,
    // call depth exceeded 1024
    DepthOverflow,
    // insufficient balance for transfer
    InsufficientBalance,
    // contract address collision
    ContractAddressCollision,
    // execution reverted
    Reverted,
    // max code size exceeded
    MaxCodeSizeExceeded,
    // invalid jump destination
    InvalidJump,
    // static call protection
    WriteProtection,
    // return data out of bound
    ReturnDataOutOfBounds,
    // contract must not begin with 0xef due to EIP #3541 EVM Object Format
    // (EOF)
    InvalidBeginningCode,
    // stack underflow
    StackUnderflow,
    // stack overflow
    StackOverflow,
    // invalid opcode
    InvalidCode,
}

// TODO: use ExecutionStep from bus_mapping
pub(crate) struct ExecutionStep {
    opcode: OpcodeId,
    case: Case,
    values: Vec<BigUint>,
}

// TODO: use Operation from bus_mapping
pub(crate) struct Operation<F> {
    gc: usize,
    target: Target,
    is_write: bool,
    values: [F; 4],
}

#[derive(Clone)]
struct EvmCircuit<F> {
    q_step: Selector,
    qs_byte_lookup: Column<Advice>,
    fixed_table: [Column<Fixed>; 4],
    rw_table: [Column<Advice>; 7],
    bytecode_table: [Column<Advice>; 5],
    op_execution_gadget: OpExecutionGadget<F>,
}

impl<F: FieldExt> EvmCircuit<F> {
    fn configure(meta: &mut ConstraintSystem<F>, r: F) -> Self {
        let q_step = meta.selector();
        let qs_byte_lookup = meta.advice_column();
        let advices = (0..CIRCUIT_WIDTH)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // TODO: consider encode first 3 information into one field element
        // rw_table contains read-write data in bus mapping for lookup
        let rw_table = [
            meta.advice_column(), // global_counter
            meta.advice_column(), // target
            meta.advice_column(), // is_write
            meta.advice_column(), // val1
            meta.advice_column(), // val2
            meta.advice_column(), // val3
            meta.advice_column(), // val4
        ];

        let bytecode_table = [
            meta.advice_column(), // code_hash
            meta.advice_column(), // index
            meta.advice_column(), // push_rindex
            meta.advice_column(), // is_code
            meta.advice_column(), // byte code
        ];

        // fixed_table contains pre-built tables identified by tag including:
        // - different size range tables
        // - bitwise table
        // - comparator table
        // - ...
        let fixed_table = [
            meta.fixed_column(), // tag
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        let (
            qs_op_execution,
            qs_byte_lookups,
            op_execution_state_curr,
            op_execution_state_next,
            op_execution_free_cells,
        ) = Self::configure_allocations(meta, q_step, qs_byte_lookup, advices);

        // independent_lookups collect lookups by independent selectors, which
        // means we can sum some of them together to save lookups.
        let mut independent_lookups =
            Vec::<(Expression<F>, Vec<Lookup<F>>)>::new();

        let op_execution_gadget = OpExecutionGadget::configure(
            meta,
            r,
            qs_op_execution,
            qs_byte_lookups,
            op_execution_state_curr.clone(),
            op_execution_state_next,
            op_execution_free_cells,
            &mut independent_lookups,
        );

        // TODO: call_initialization_gadget

        Self::configure_lookups(
            meta,
            qs_byte_lookup,
            advices,
            fixed_table,
            rw_table,
            bytecode_table,
            op_execution_state_curr,
            independent_lookups,
        );

        EvmCircuit {
            q_step,
            qs_byte_lookup,
            fixed_table,
            rw_table,
            bytecode_table,
            op_execution_gadget,
        }
    }

    // TODO: refactor return type
    #[allow(clippy::type_complexity)]
    fn configure_allocations(
        meta: &mut ConstraintSystem<F>,
        q_step: Selector,
        qs_byte_lookup: Column<Advice>,
        advices: [Column<Advice>; CIRCUIT_WIDTH],
    ) -> (
        Expression<F>,
        Vec<Cell<F>>,
        OpExecutionState<F>,
        OpExecutionState<F>,
        Vec<Cell<F>>,
    ) {
        let mut qs_byte_lookups = Vec::with_capacity(CIRCUIT_HEIGHT);
        meta.create_gate("Query byte lookup as a synthetic selector", |meta| {
            for h in 0..CIRCUIT_HEIGHT as i32 {
                qs_byte_lookups.push(Cell {
                    expression: meta.query_advice(qs_byte_lookup, Rotation(h)),
                    column: qs_byte_lookup,
                    rotation: h as usize,
                });
            }

            vec![0.expr()]
        });

        let mut cells_curr = Vec::with_capacity(CIRCUIT_WIDTH * CIRCUIT_HEIGHT);
        meta.create_gate("Query cells for current step", |meta| {
            for h in 0..CIRCUIT_HEIGHT as i32 {
                for &column in advices.iter() {
                    cells_curr.push(Cell {
                        expression: meta.query_advice(column, Rotation(h)),
                        column,
                        rotation: h as usize,
                    });
                }
            }

            vec![0.expr()]
        });

        let num_cells_next_asseccible = NUM_CELL_OP_EXECUTION_STATE;

        let cells_next =
            &mut cells_curr[..num_cells_next_asseccible].to_vec()[..];
        meta.create_gate("Query cells for next step", |meta| {
            for cell in cells_next.iter_mut() {
                cell.rotation += CIRCUIT_HEIGHT;
                cell.expression = meta.query_advice(
                    cell.column,
                    Rotation((cell.rotation) as i32),
                );
            }

            vec![0.expr()]
        });

        let op_execution_state_curr =
            OpExecutionState::new(&cells_curr[..NUM_CELL_OP_EXECUTION_STATE]);
        let op_execution_state_next =
            OpExecutionState::new(&cells_next[..NUM_CELL_OP_EXECUTION_STATE]);
        let op_execution_free_cells =
            cells_curr[NUM_CELL_OP_EXECUTION_STATE..].to_vec();

        let mut qs_op_execution = 0.expr();
        meta.create_gate(
            "Query synthetic selector for OpExecutionGadget",
            |meta| {
                qs_op_execution = meta.query_selector(q_step)
                    * op_execution_state_curr.is_executing.expr();

                vec![0.expr()]
            },
        );

        (
            qs_op_execution,
            qs_byte_lookups,
            op_execution_state_curr,
            op_execution_state_next,
            op_execution_free_cells,
        )
    }

    fn configure_lookups(
        meta: &mut ConstraintSystem<F>,
        qs_byte_lookup: Column<Advice>,
        advices: [Column<Advice>; CIRCUIT_WIDTH],
        fixed_table: [Column<Fixed>; 4],
        rw_table: [Column<Advice>; 7],
        bytecode_table: [Column<Advice>; 5],
        op_execution_state_curr: OpExecutionState<F>,
        independent_lookups: Vec<(Expression<F>, Vec<Lookup<F>>)>,
    ) {
        // TODO: call_lookups
        // TODO: bytecode_lookups

        let mut fixed_lookups = Vec::<[Expression<F>; 4]>::new();
        let mut rw_lookups = Vec::<[Expression<F>; 7]>::new();
        let mut bytecode_lookups = Vec::<[Expression<F>; 5]>::new();

        for (qs_lookup, lookups) in independent_lookups {
            let mut fixed_lookup_count = 0;
            let mut rw_lookup_count = 0;
            let mut bytecode_lookup_count = 0;

            for lookup in lookups {
                match lookup {
                    Lookup::FixedLookup(tag, exprs) => {
                        let exprs = iter::once(tag.expr()).chain(exprs.clone());

                        if fixed_lookups.len() == fixed_lookup_count {
                            fixed_lookups.push(
                                exprs
                                    .map(|expr| qs_lookup.clone() * expr)
                                    .collect::<Vec<_>>()
                                    .try_into()
                                    .unwrap(),
                            );
                        } else {
                            for (acc, expr) in fixed_lookups[fixed_lookup_count]
                                .iter_mut()
                                .zip(exprs)
                            {
                                *acc = acc.clone() + qs_lookup.clone() * expr;
                            }
                        }
                        fixed_lookup_count += 1;
                    }
                    Lookup::BusMappingLookup(
                        rw_lookup
                        @
                        (BusMappingLookup::Stack { .. }
                        | BusMappingLookup::Memory { .. }
                        | BusMappingLookup::AccountStorage {
                            ..
                        }),
                    ) => {
                        let OpExecutionState {
                            global_counter,
                            call_id,
                            stack_pointer,
                            ..
                        } = &op_execution_state_curr;

                        if rw_lookups.len() == rw_lookup_count {
                            rw_lookups
                                .push(vec![0.expr(); 7].try_into().unwrap());
                        }

                        let mut exprs = vec![
                            global_counter.expr() + rw_lookup_count.expr(),
                            rw_lookup.rw_target().expr(),
                        ];
                        exprs.extend(match rw_lookup {
                            BusMappingLookup::Stack {
                                is_write,
                                index_offset,
                                value,
                            } => [
                                is_write.expr(),
                                call_id.expr(),
                                stack_pointer.expr() + index_offset,
                                value,
                                0.expr(),
                            ],
                            BusMappingLookup::Memory {
                                is_write,
                                call_id,
                                index,
                                value,
                            } => [
                                is_write.expr(),
                                call_id,
                                index,
                                value,
                                0.expr(),
                            ],
                            BusMappingLookup::AccountStorage {
                                is_write,
                                address,
                                location,
                                value,
                                value_prev,
                            } => [
                                is_write.expr(),
                                address,
                                location,
                                value,
                                value_prev,
                            ],

                            // TODO:
                            _ => unimplemented!(),
                        });

                        for (acc, expr) in
                            rw_lookups[rw_lookup_count].iter_mut().zip(exprs)
                        {
                            *acc = acc.clone() + qs_lookup.clone() * expr;
                        }

                        rw_lookup_count += 1;
                    }
                    Lookup::BytecodeLookup(_tag, exprs) => {
                        // let exprs = iter::once(tag.expr()).chain(exprs.clone());
                        // TODO: add tag later but now omit for testing
                        let exprs = iter::empty().chain(exprs.clone());
                        if bytecode_lookups.len() == bytecode_lookup_count {
                            bytecode_lookups.push(
                                exprs
                                    .map(|expr| qs_lookup.clone() * expr)
                                    .collect::<Vec<_>>()
                                    .try_into()
                                    .unwrap(),
                            );
                        } else {
                            for (acc, expr) in bytecode_lookups
                                [bytecode_lookup_count]
                                .iter_mut()
                                .zip(exprs)
                            {
                                *acc = acc.clone() + qs_lookup.clone() * expr;
                            }
                        }
                        bytecode_lookup_count += 1;
                    }
                    _ => unimplemented!(),
                }
            }
        }

        // Configure whole row lookups by qs_byte_lookup
        for column in advices {
            meta.lookup(|meta| {
                let tag = FixedLookup::Range256.expr();
                let qs_byte_lookup =
                    meta.query_advice(qs_byte_lookup, Rotation::cur());
                [
                    qs_byte_lookup.clone() * tag,
                    qs_byte_lookup * meta.query_advice(column, Rotation::cur()),
                    0.expr(),
                    0.expr(),
                ]
                .iter()
                .zip(fixed_table.iter())
                .map(|(expr, column)| {
                    (expr.clone(), meta.query_fixed(*column, Rotation::cur()))
                })
                .collect::<Vec<_>>()
            });
        }

        // Configure fixed lookups
        for fixed_lookup in fixed_lookups.iter() {
            meta.lookup(|meta| {
                fixed_lookup
                    .iter()
                    .zip(fixed_table.iter())
                    .map(|(expr, column)| {
                        (
                            expr.clone(),
                            meta.query_fixed(*column, Rotation::cur()),
                        )
                    })
                    .collect::<Vec<_>>()
            });
        }

        // Configure byte code lookups
        for bytecode_lookup in bytecode_lookups.iter() {
            meta.lookup(|meta| {
                bytecode_lookup
                    .iter()
                    .zip(bytecode_table.iter())
                    .map(|(expr, column)| {
                        (
                            expr.clone(),
                            meta.query_advice(*column, Rotation::cur()),
                        )
                    })
                    .collect::<Vec<_>>()
            });
        }
        // Configure rw lookups
        for rw_lookup in rw_lookups.iter() {
            meta.lookup(|meta| {
                rw_lookup
                    .iter()
                    .zip(rw_table.iter())
                    .map(|(expr, column)| {
                        (
                            expr.clone(),
                            meta.query_advice(*column, Rotation::cur()),
                        )
                    })
                    .collect::<Vec<_>>()
            });
        }
    }

    fn load_fixed_tables(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                let mut offset = 0;

                // Noop
                for (idx, column) in self.fixed_table.iter().enumerate() {
                    region.assign_fixed(
                        || format!("Noop: {}", idx),
                        *column,
                        offset,
                        || Ok(F::zero()),
                    )?;
                }
                offset += 1;

                // Range256
                for idx in 0..256 {
                    region.assign_fixed(
                        || "Range256: tag",
                        self.fixed_table[0],
                        offset,
                        || Ok(F::from_u64(FixedLookup::Range256 as u64)),
                    )?;
                    region.assign_fixed(
                        || "Range256: value",
                        self.fixed_table[1],
                        offset,
                        || Ok(F::from_u64(idx as u64)),
                    )?;
                    for (idx, column) in
                        self.fixed_table[2..].iter().enumerate()
                    {
                        region.assign_fixed(
                            || format!("Range256: padding {}", idx),
                            *column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;
                }

                // Range32
                for idx in 0..32 {
                    region.assign_fixed(
                        || "Range32: tag",
                        self.fixed_table[0],
                        offset,
                        || Ok(F::from_u64(FixedLookup::Range32 as u64)),
                    )?;
                    region.assign_fixed(
                        || "Range32: value",
                        self.fixed_table[1],
                        offset,
                        || Ok(F::from_u64(idx as u64)),
                    )?;
                    for (idx, column) in
                        self.fixed_table[2..].iter().enumerate()
                    {
                        region.assign_fixed(
                            || format!("Range32: padding {}", idx),
                            *column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;
                }

                // Range17
                for idx in 0..17 {
                    region.assign_fixed(
                        || "Range17: tag",
                        self.fixed_table[0],
                        offset,
                        || Ok(F::from_u64(FixedLookup::Range17 as u64)),
                    )?;
                    region.assign_fixed(
                        || "Range17: value",
                        self.fixed_table[1],
                        offset,
                        || Ok(F::from_u64(idx as u64)),
                    )?;
                    for (idx, column) in
                        self.fixed_table[2..].iter().enumerate()
                    {
                        region.assign_fixed(
                            || format!("Range17: padding {}", idx),
                            *column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;
                }

                // Range16
                for idx in 0..16 {
                    region.assign_fixed(
                        || "Range16: tag",
                        self.fixed_table[0],
                        offset,
                        || Ok(F::from_u64(FixedLookup::Range16 as u64)),
                    )?;
                    region.assign_fixed(
                        || "Range16: value",
                        self.fixed_table[1],
                        offset,
                        || Ok(F::from_u64(idx as u64)),
                    )?;
                    for (idx, column) in
                        self.fixed_table[2..].iter().enumerate()
                    {
                        region.assign_fixed(
                            || format!("Range16: padding {}", idx),
                            *column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;
                }

                // SignByte
                for idx in 0..256 {
                    region.assign_fixed(
                        || "SignByte: tag",
                        self.fixed_table[0],
                        offset,
                        || Ok(F::from_u64(FixedLookup::SignByte as u64)),
                    )?;
                    region.assign_fixed(
                        || "SignByte: value",
                        self.fixed_table[1],
                        offset,
                        || Ok(F::from_u64(idx as u64)),
                    )?;
                    region.assign_fixed(
                        || "SignByte: sign",
                        self.fixed_table[2],
                        offset,
                        || Ok(F::from_u64((idx >> 7) * 0xFFu64)),
                    )?;
                    for (idx, column) in
                        self.fixed_table[3..].iter().enumerate()
                    {
                        region.assign_fixed(
                            || format!("SignByte: padding {}", idx),
                            *column,
                            offset,
                            || Ok(F::zero()),
                        )?;
                    }
                    offset += 1;
                }

                // TODO: BitwiseAnd
                // TODO: BitwiseOr
                // TODO: BitwiseXor

                Ok(())
            },
        )
    }

    fn load_rw_tables(
        &self,
        layouter: &mut impl Layouter<F>,
        operations: &[Operation<F>],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "rw table",
            |mut region| {
                let mut offset = 0;

                for column in self.rw_table.iter() {
                    region.assign_advice(
                        || "Read-Write noop",
                        *column,
                        offset,
                        || Ok(F::zero()),
                    )?;
                }
                offset += 1;

                for operation in operations.iter() {
                    // TODO: Ensure we got a sorted by gc operation from bus-mapping
                    assert_eq!(
                        operation.gc, offset,
                        "global counter uniqueness assumption is broken"
                    );

                    let values = [
                        vec![
                            F::from_u64(operation.gc as u64),
                            F::from_u64(operation.target as u64),
                            F::from_u64(operation.is_write as u64),
                        ],
                        operation.values.to_vec(),
                    ]
                    .concat();

                    for (column, value) in self.rw_table.iter().zip(values) {
                        region.assign_advice(
                            || "Read-Write table",
                            *column,
                            offset,
                            || Ok(value),
                        )?;
                    }
                    offset += 1;
                }

                Ok(())
            },
        )
    }

    fn load_bytecode_tables(
        &self,
        layouter: &mut impl Layouter<F>,
        bytecode_table: Vec<[u32; 5]>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "bytecode table",
            |mut region| {
                let mut offset = 0;

                for column in self.bytecode_table.iter() {
                    region.assign_advice(
                        || "bytecode noop",
                        *column,
                        offset,
                        || Ok(F::zero()),
                    )?;
                }
                offset += 1;

                for bytecode_entry in bytecode_table.iter() {
                    for (column, value) in
                        self.bytecode_table.iter().zip(bytecode_entry)
                    {
                        region.assign_advice(
                            || "bytecode table",
                            *column,
                            offset,
                            || Ok(F::from_u64(*value as u64)),
                        )?;
                    }
                    offset += 1;
                }

                Ok(())
            },
        )
    }

    fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        execution_steps: &[ExecutionStep],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "evm circuit",
            |mut region| {
                let mut core_state = CoreStateInstance::new(0);

                // TODO: call_initialization should maintain this
                core_state.is_executing = true;

                for (idx, execution_step) in execution_steps.iter().enumerate()
                {
                    let offset = idx * CIRCUIT_HEIGHT;

                    self.q_step.enable(&mut region, offset)?;

                    self.op_execution_gadget.assign_execution_step(
                        &mut region,
                        offset,
                        &mut core_state,
                        Some(execution_step),
                    )?;
                }

                self.op_execution_gadget.assign_execution_step(
                    &mut region,
                    execution_steps.len() * CIRCUIT_HEIGHT,
                    &mut core_state,
                    None,
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::{EvmCircuit, ExecutionStep, Operation};
    use halo2::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    };
    extern crate hex;
    extern crate num;
    use bus_mapping::evm::OpcodeId;

    #[derive(Clone)]
    pub(crate) struct TestCircuitConfig<F> {
        evm_circuit: EvmCircuit<F>,
    }

    // contruct byte codes from compiled by contract
    pub(crate) fn assgin_byte_table(bytecode_source: &str) -> Vec<[u32; 5]> {
        let byte_codes = hex::decode(bytecode_source).expect("Decoding failed");
        // TODO: add keccak hash (byte_codes)
        let code_hash = 0 as u32;
        let mut i = 0;
        let mut push_x = 0;
        let mut bytecode_table = Vec::<[u32; 5]>::new();
        for byte in byte_codes.iter() {
            if push_x != 0 {
                let push_rindex = push_x;
                for x in 0..push_rindex {
                    // rw_lookups
                    // .push(vec![0.expr(); 7].try_into().unwrap());
                    bytecode_table.push([
                        code_hash,
                        i,
                        push_rindex - x,
                        0,
                        *byte as u32,
                    ]);
                    i += 1;
                }
                push_x = 0;
            } else {
                bytecode_table.push([code_hash, i, 0, 1, *byte as u32]);
                if OpcodeId::PUSH1.as_u8() <= *byte
                    && *byte <= OpcodeId::PUSH32.as_u8()
                {
                    push_x = (*byte - OpcodeId::PUSH1.as_u8() + 1) as u32;
                }
                i += 1
            }
        }

        return bytecode_table;
    }

    // contruct byte code table from compiled by contract， .ie. bytecode_source = "6002565b00";
    pub(crate) fn assgin_byte_table_step(
        execution_steps: &[ExecutionStep],
    ) -> Vec<[u32; 5]> {
        // TODO: add keccak hash (byte_codes)
        let code_hash = 0 as u32;
        let mut i = 0;
        let mut bytecode_table = Vec::<[u32; 5]>::new();

        for curr_step in execution_steps.iter() {
            let byte = curr_step.opcode.as_u8();
            if OpcodeId::PUSH1.as_u8() <= byte
                && byte <= OpcodeId::PUSH32.as_u8()
            {
                bytecode_table.push([code_hash, i, 0, 1, byte as u32]);
                i += 1;
                // loading data segement
                let push_rindex = byte - OpcodeId::PUSH1.as_u8() + 1;
                let mut x = 0;
                for data in curr_step.values[0].to_bytes_le() {
                    bytecode_table.push([
                        code_hash,
                        i,
                        (push_rindex - x) as u32,
                        0,
                        data as u32,
                    ]);

                    i += 1; // next byte
                    x = x + 1;
                }
            } else {
                bytecode_table.push([code_hash, i, 0, 1, byte as u32]);
                i += 1
            }
        }

        return bytecode_table;
    }

    #[derive(Default)]
    pub(crate) struct TestCircuit<F> {
        execution_steps: Vec<ExecutionStep>,
        operations: Vec<Operation<F>>,
    }

    impl<F> TestCircuit<F> {
        pub fn new(
            execution_steps: Vec<ExecutionStep>,
            operations: Vec<Operation<F>>,
        ) -> Self {
            Self {
                execution_steps,
                operations,
            }
        }
    }

    impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
        type Config = TestCircuitConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            Self::Config {
                // TODO: use a random r instead of 1
                evm_circuit: EvmCircuit::configure(meta, F::one()),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.evm_circuit.load_fixed_tables(&mut layouter)?;
            config
                .evm_circuit
                .load_rw_tables(&mut layouter, &self.operations)?;

            // load bytecode source from test sequence
            let bytecode_table = assgin_byte_table_step(&self.execution_steps);

            config
                .evm_circuit
                .load_bytecode_tables(&mut layouter, bytecode_table)?;

            config
                .evm_circuit
                .assign(&mut layouter, &self.execution_steps)
        }
    }
}
