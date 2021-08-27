//! The EVM circuit implementation.

use halo2::{
    arithmetic::FieldExt,
    circuit::{self, Layouter, Region},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector,
    },
    poly::Rotation,
};
use std::convert::TryInto;

mod op_execution;
use op_execution::{OpExecutionGadget, OpExecutionState};

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
    IsPersistant,
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
        field: CallStateField,
        value: Expression<F>,
        is_write: bool,
    },
    Stack {
        // One can only access its own stack, so id is no needed to be
        // specified.
        // Stack index is always deterministic respect to stack pointer, so an
        // index offset is enough.
        index_offset: i32,
        value: Expression<F>,
        is_write: bool,
    },
    Memory {
        // Some ops like CALLDATALOAD can peek caller's memeory as calldata, so
        // we allow it to specify the id.
        id: Expression<F>,
        index: Expression<F>,
        value: Expression<F>,
        is_write: bool,
    },
    AccountStorage {
        address: Expression<F>,
        location: Expression<F>,
        value: Expression<F>,
        is_write: bool,
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
        value: Expression<F>,
    },
    // TODO: Block,
    // TODO: Bytecode,
    // TODO: Tx,
    // TODO: TxCalldata,
}

#[derive(Clone, Copy, Debug, PartialOrd, PartialEq, Eq, Ord)]
pub(crate) enum FixedLookup {
    // Noop provides [0, 0, 0, 0] row
    Noop,
    // meaningful tags start with 1
    Range256,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
}

#[derive(Clone, Debug)]
pub(crate) enum Lookup<F> {
    FixedLookup(FixedLookup, [Expression<F>; 3]),
    BusMappingLookup(BusMappingLookup<F>),
}

#[derive(Clone, Debug)]
struct Constraint<F> {
    name: &'static str,
    selector: Expression<F>,
    linear_combinations: Vec<Expression<F>>,
    lookups: Vec<Lookup<F>>,
}

#[derive(Clone, Debug)]
pub(crate) struct Cell<F> {
    // expression for constraint
    expression: Expression<F>,
    // relative position to selector for synthesis
    column: Column<Advice>,
    offset: usize,
}

impl<F: FieldExt> Cell<F> {
    fn exp(&self) -> Expression<F> {
        self.expression.clone()
    }

    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Option<F>,
    ) -> Result<circuit::Cell, Error> {
        region.assign_advice(
            || {
                format!(
                    "Cell {{ column: {:?}, offset: {}}}",
                    self.column, self.offset
                )
            },
            self.column,
            offset + self.offset,
            || value.ok_or(Error::SynthesisError),
        )
    }
}

// TODO: Integrate with evm_word
#[derive(Clone, Debug)]
struct Word<F> {
    // random linear combination exp for configuration
    expression: Expression<F>,
    // inner cells for syntesis
    cells: [Cell<F>; 32],
}

impl<F: FieldExt> Word<F> {
    fn encode(cells: &[Cell<F>], r: F) -> Self {
        let r = Expression::Constant(r);
        Self {
            expression: cells
                .iter()
                .rev()
                .fold(Expression::Constant(F::zero()), |acc, byte| {
                    acc * r.clone() + byte.exp()
                }),
            cells: cells.to_owned().try_into().unwrap(),
        }
    }

    fn exp(&self) -> Expression<F> {
        self.expression.clone()
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

#[derive(Debug)]
pub(crate) struct OpExecutionStateInstance {
    is_executing: bool,
    global_counter: usize,
    call_id: usize,
    program_counter: usize,
    stack_pointer: usize,
    gas_counter: usize,
}

impl OpExecutionStateInstance {
    fn new(call_id: usize) -> Self {
        OpExecutionStateInstance {
            is_executing: false,
            global_counter: 0,
            call_id,
            program_counter: 0,
            stack_pointer: 1024,
            gas_counter: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Case {
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
    // contract must not begin with 0xef due to EIP #3541 EVM Object Format (EOF)
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
    opcode: u8,
    case: Case,
    values: Vec<[u8; 32]>,
}

#[derive(Clone)]
struct EvmCircuit<F> {
    selector: Selector,
    fixed_table: [Column<Fixed>; 4],
    op_execution_gadget: OpExecutionGadget<F>,
}

impl<F: FieldExt> EvmCircuit<F> {
    // FIXME: naive estimation, should be optmize to fit in the future
    const WIDTH: usize = 32;
    const HEIGHT: usize = 8;

    fn configure(meta: &mut ConstraintSystem<F>, r: F) -> Self {
        let selector = meta.selector();
        let columns = (0..Self::WIDTH)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>();

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

        let mut selector_exp = Expression::Constant(F::zero());
        let mut cells = Vec::with_capacity(Self::WIDTH * Self::HEIGHT);
        meta.create_gate("Query cells for current step", |meta| {
            selector_exp = meta.query_selector(selector);

            for h in 0..Self::HEIGHT as i32 {
                for &column in columns.iter() {
                    cells.push(Cell {
                        expression: meta.query_advice(column, Rotation(h)),
                        column,
                        offset: h as usize,
                    });
                }
            }

            vec![Expression::Constant(F::zero())]
        });

        let (op_execution_state_curr_cells, free_cells) =
            cells.split_at(OpExecutionState::<F>::SIZE);

        let op_execution_state_next_cells =
            &mut op_execution_state_curr_cells.to_vec()[..];
        meta.create_gate("Query cells for next step", |meta| {
            for cell in op_execution_state_next_cells.iter_mut() {
                cell.expression = meta.query_advice(
                    cell.column,
                    Rotation((cell.offset + Self::HEIGHT) as i32),
                );
            }

            vec![Expression::Constant(F::zero())]
        });

        let op_execution_state_curr =
            OpExecutionState::new(op_execution_state_curr_cells);
        let op_execution_state_next =
            OpExecutionState::new(op_execution_state_next_cells);

        // independent_lookups collect lookups by independent selectors, which
        // means we can sum some of them together to save lookups.
        let mut independent_lookups =
            Vec::<(Expression<F>, Vec<Lookup<F>>)>::new();

        let op_execution_gadget = OpExecutionGadget::configure(
            meta,
            r,
            selector_exp,
            op_execution_state_curr,
            op_execution_state_next,
            free_cells,
            &mut independent_lookups,
        );

        // TODO: call_initialization_gadget

        Self::configure_lookups(meta, &fixed_table, independent_lookups);

        EvmCircuit {
            selector,
            fixed_table,
            op_execution_gadget,
        }
    }

    fn configure_lookups(
        meta: &mut ConstraintSystem<F>,
        fixed_table: &[Column<Fixed>; 4],
        independent_lookups: Vec<(Expression<F>, Vec<Lookup<F>>)>,
    ) {
        // TODO: call_lookups
        // TODO: bytecode_lookups
        // TODO: rw_lookups

        let mut fixed_lookups = Vec::<[Expression<F>; 4]>::new();

        for (lookup_selector, lookups) in independent_lookups {
            let mut fixed_lookup_count = 0;

            for lookup in lookups {
                match lookup {
                    Lookup::FixedLookup(tag, exps) => {
                        let tag_exp =
                            Expression::Constant(F::from_u64(tag as u64));

                        if fixed_lookups.len() == fixed_lookup_count {
                            fixed_lookups.push(
                                [tag_exp]
                                    .iter()
                                    .chain(exps.iter())
                                    .map(|exp| {
                                        lookup_selector.clone() * exp.clone()
                                    })
                                    .collect::<Vec<_>>()
                                    .try_into()
                                    .unwrap(),
                            );
                        } else {
                            for (acc, exp) in fixed_lookups[fixed_lookup_count]
                                .iter_mut()
                                .zip([tag_exp].iter().chain(exps.iter()))
                            {
                                *acc = acc.clone()
                                    + lookup_selector.clone() * exp.clone();
                            }
                        }
                        fixed_lookup_count += 1;
                    }
                    Lookup::BusMappingLookup(_) => {
                        // TODO:
                        unimplemented!()
                    }
                }
            }
        }

        for fixed_lookup in fixed_lookups.iter() {
            meta.lookup(|meta| {
                fixed_lookup
                    .iter()
                    .zip(fixed_table.iter())
                    .map(|(exp, fixed)| {
                        (exp.clone(), meta.query_fixed(*fixed, Rotation::cur()))
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
                let mut offest = 0;

                // Noop
                for (idx, column) in self.fixed_table.iter().enumerate() {
                    region.assign_fixed(
                        || format!("Noop: {}", idx),
                        *column,
                        offest,
                        || Ok(F::zero()),
                    )?;
                }
                offest += 1;

                // Range256
                for idx in 0..256 {
                    region.assign_fixed(
                        || "Range256: tag",
                        self.fixed_table[0],
                        offest,
                        || Ok(F::from_u64(FixedLookup::Range256 as u64)),
                    )?;
                    region.assign_fixed(
                        || "Range256: value",
                        self.fixed_table[1],
                        offest,
                        || Ok(F::from_u64(idx as u64)),
                    )?;
                    for (idx, column) in
                        self.fixed_table[2..].iter().enumerate()
                    {
                        region.assign_fixed(
                            || format!("Range256: padding {}", idx),
                            *column,
                            offest,
                            || Ok(F::zero()),
                        )?;
                    }
                    offest += 1;
                }

                // TODO: BitwiseAnd
                // TODO: BitwiseOr
                // TODO: BitwiseXor

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
                let mut op_execution_state = OpExecutionStateInstance::new(0);

                // TODO: call_initialization should maintain this
                op_execution_state.is_executing = true;

                for (idx, execution_step) in execution_steps.iter().enumerate()
                {
                    let offset = idx * Self::HEIGHT;

                    self.selector.enable(&mut region, offset)?;

                    self.op_execution_gadget.assign_execution_step(
                        &mut region,
                        offset,
                        &mut op_execution_state,
                        Some(execution_step),
                    )?;
                }

                self.op_execution_gadget.assign_execution_step(
                    &mut region,
                    execution_steps.len() * Self::HEIGHT,
                    &mut op_execution_state,
                    None,
                )?;

                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod test {
    use super::{EvmCircuit, ExecutionStep};
    use halo2::{
        arithmetic::FieldExt,
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use std::marker::PhantomData;

    #[derive(Clone)]
    pub(crate) struct TestCircuitConfig<F> {
        evm_circuit: EvmCircuit<F>,
    }

    #[derive(Default)]
    pub(crate) struct TestCircuit<F> {
        execution_steps: Vec<ExecutionStep>,
        _marker: PhantomData<F>,
    }

    impl<F> TestCircuit<F> {
        pub(crate) fn new(execution_steps: Vec<ExecutionStep>) -> Self {
            Self {
                execution_steps,
                _marker: PhantomData,
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
                .assign(&mut layouter, &self.execution_steps)
        }
    }
}
