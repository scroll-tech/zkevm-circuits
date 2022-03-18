use crate::{
    evm_circuit::{
        param::{STEP_HEIGHT, STEP_WIDTH},
        step::{ExecutionState, Preset, Step},
        table::{FixedTableTag, Lookup, LookupTable, Table},
        util::constraint_builder::ConstraintBuilder,
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region},
    plonk::{Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use std::{collections::HashMap, iter};

mod add;
mod begin_tx;
mod bitwise;
mod byte;
mod calldatacopy;
mod calldataload;
mod calldatasize;
mod caller;
mod callvalue;
mod coinbase;
mod comparator;
mod dup;
mod end_block;
mod end_tx;
mod error_oog_static_memory;
mod gas;
mod is_zero;
mod jump;
mod jumpdest;
mod jumpi;
mod memory;
mod memory_copy;
mod msize;
mod mul;
mod number;
mod pc;
mod pop;
mod push;
mod selfbalance;
mod signed_comparator;
mod signextend;
mod sload;
mod sstore;
mod stop;
mod swap;
mod timestamp;

use add::AddGadget;
use begin_tx::BeginTxGadget;
use bitwise::BitwiseGadget;
use byte::ByteGadget;
use calldatacopy::CallDataCopyGadget;
use calldataload::CallDataLoadGadget;
use calldatasize::CallDataSizeGadget;
use caller::CallerGadget;
use callvalue::CallValueGadget;
use coinbase::CoinbaseGadget;
use comparator::ComparatorGadget;
use dup::DupGadget;
use end_block::EndBlockGadget;
use end_tx::EndTxGadget;
use error_oog_static_memory::ErrorOOGStaticMemoryGadget;
use gas::GasGadget;
use jump::JumpGadget;
use is_zero::Is0Gadget;
use jumpdest::JumpdestGadget;
use jumpi::JumpiGadget;
use memory::MemoryGadget;
use memory_copy::CopyToMemoryGadget;
use msize::MsizeGadget;
use mul::MulGadget;
use number::NumberGadget;
use pc::PcGadget;
use pop::PopGadget;
use push::PushGadget;
use selfbalance::SelfbalanceGadget;
use signed_comparator::SignedComparatorGadget;
use signextend::SignextendGadget;
use sload::SloadGadget;
use sstore::SstoreGadget;
use stop::StopGadget;
use swap::SwapGadget;
use timestamp::TimestampGadget;

pub(crate) trait ExecutionGadget<F: FieldExt> {
    const NAME: &'static str;

    const EXECUTION_STATE: ExecutionState;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self;

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutionConfig<F> {
    q_step: Selector,
    q_step_first: Selector,
    q_step_last: Selector,
    step: Step<F>,
    presets_map: HashMap<ExecutionState, Vec<Preset<F>>>,
    add_gadget: AddGadget<F>,
    mul_gadget: MulGadget<F>,
    bitwise_gadget: BitwiseGadget<F>,
    begin_tx_gadget: BeginTxGadget<F>,
    byte_gadget: ByteGadget<F>,
    calldatacopy_gadget: CallDataCopyGadget<F>,
    calldataload_gadget: CallDataLoadGadget<F>,
    calldatasize_gadget: CallDataSizeGadget<F>,
    caller_gadget: CallerGadget<F>,
    call_value_gadget: CallValueGadget<F>,
    comparator_gadget: ComparatorGadget<F>,
    dup_gadget: DupGadget<F>,
    end_block_gadget: EndBlockGadget<F>,
    end_tx_gadget: EndTxGadget<F>,
    is0_gadget: Is0Gadget<F>,
    error_oog_static_memory_gadget: ErrorOOGStaticMemoryGadget<F>,
    jump_gadget: JumpGadget<F>,
    jumpdest_gadget: JumpdestGadget<F>,
    jumpi_gadget: JumpiGadget<F>,
    gas_gadget: GasGadget<F>,
    memory_gadget: MemoryGadget<F>,
    copy_to_memory_gadget: CopyToMemoryGadget<F>,
    pc_gadget: PcGadget<F>,
    pop_gadget: PopGadget<F>,
    push_gadget: PushGadget<F>,
    signed_comparator_gadget: SignedComparatorGadget<F>,
    signextend_gadget: SignextendGadget<F>,
    stop_gadget: StopGadget<F>,
    swap_gadget: SwapGadget<F>,
    msize_gadget: MsizeGadget<F>,
    coinbase_gadget: CoinbaseGadget<F>,
    timestamp_gadget: TimestampGadget<F>,
    selfbalance_gadget: SelfbalanceGadget<F>,
    number_gadget: NumberGadget<F>,
    sload_gadget: SloadGadget<F>,
    sstore_gadget: SstoreGadget<F>,
}

impl<F: Field> ExecutionConfig<F> {
    pub(crate) fn configure<TxTable, RwTable, BytecodeTable, BlockTable>(
        meta: &mut ConstraintSystem<F>,
        power_of_randomness: [Expression<F>; 31],
        fixed_table: [Column<Fixed>; 4],
        tx_table: TxTable,
        rw_table: RwTable,
        bytecode_table: BytecodeTable,
        block_table: BlockTable,
    ) -> Self
    where
        TxTable: LookupTable<F, 4>,
        RwTable: LookupTable<F, 11>,
        BytecodeTable: LookupTable<F, 4>,
        BlockTable: LookupTable<F, 3>,
    {
        let q_step = meta.complex_selector();
        let q_step_first = meta.complex_selector();
        let q_step_last = meta.complex_selector();
        let qs_byte_lookup = meta.advice_column();
        let advices = [(); STEP_WIDTH].map(|_| meta.advice_column());

        let step_curr = Step::new(meta, qs_byte_lookup, advices, false);
        let step_next = Step::new(meta, qs_byte_lookup, advices, true);
        let mut independent_lookups = Vec::new();
        let mut presets_map = HashMap::new();

        meta.create_gate("Constrain execution state", |meta| {
            let q_step = meta.query_selector(q_step);
            let q_step_first = meta.query_selector(q_step_first);
            let q_step_last = meta.query_selector(q_step_last);

            // Only one of execution_state should be enabled
            let sum_to_one = (
                "Only one of execution_state should be enabled",
                step_curr
                    .state
                    .execution_state
                    .iter()
                    .fold(1u64.expr(), |acc, cell| acc - cell.expr()),
            );

            // Cells representation for execution_state should be bool.
            let bool_checks = step_curr.state.execution_state.iter().map(|cell| {
                (
                    "Representation for execution_state should be bool",
                    cell.expr() * (1u64.expr() - cell.expr()),
                )
            });

            // ExecutionState transition should be correct.
            let execution_state_transition = {
                let q_step_last = q_step_last.clone();
                iter::empty()
                    .chain(
                        [
                            (
                                "EndTx can only transit to BeginTx or EndBlock",
                                ExecutionState::EndTx,
                                vec![ExecutionState::BeginTx, ExecutionState::EndBlock],
                            ),
                            (
                                "EndBlock can only transit to EndBlock",
                                ExecutionState::EndBlock,
                                vec![ExecutionState::EndBlock],
                            ),
                        ]
                        .map(|(name, from, to)| {
                            (
                                name,
                                step_curr.execution_state_selector([from])
                                    * (1.expr() - step_next.execution_state_selector(to)),
                            )
                        }),
                    )
                    .chain(
                        [
                            (
                                "Only EndTx can transit to BeginTx",
                                ExecutionState::BeginTx,
                                vec![ExecutionState::EndTx],
                            ),
                            (
                                "Only ExecutionState which halts or BeginTx can transit to EndTx",
                                ExecutionState::EndTx,
                                ExecutionState::iterator()
                                    .filter(ExecutionState::halts)
                                    .chain(iter::once(ExecutionState::BeginTx))
                                    .collect(),
                            ),
                            (
                                "Only EndTx or EndBlock can transit to EndBlock",
                                ExecutionState::EndBlock,
                                vec![ExecutionState::EndTx, ExecutionState::EndBlock],
                            ),
                            (
                                "Only ExecutionState which copies memory to memory can transit to CopyToMemory",
                                ExecutionState::CopyToMemory,
                                vec![ExecutionState::CopyToMemory, ExecutionState::CALLDATACOPY],
                            ),
                        ]
                        .map(|(name, to, from)| {
                            (
                                name,
                                step_next.execution_state_selector([to])
                                    * (1.expr() - step_curr.execution_state_selector(from)),
                            )
                        }),
                    )
                    .map(move |(name, poly)| (name, (1.expr() - q_step_last.clone()) * poly))
            };

            let _first_step_check = {
                let begin_tx_selector =
                    step_curr.execution_state_selector([ExecutionState::BeginTx]);
                iter::once((
                    "First step should be BeginTx",
                    q_step_first * (1.expr() - begin_tx_selector),
                ))
            };

            let _last_step_check = {
                let end_block_selector =
                    step_curr.execution_state_selector([ExecutionState::EndBlock]);
                iter::once((
                    "Last step should be EndBlock",
                    q_step_last * (1.expr() - end_block_selector),
                ))
            };

            iter::once(sum_to_one)
                .chain(bool_checks)
                .chain(execution_state_transition)
                .map(move |(name, poly)| (name, q_step.clone() * poly))
                // TODO: Enable these after test of CALLDATACOPY is complete.
                // .chain(first_step_check)
                // .chain(last_step_check)
        });

        // Use qs_byte_lookup as selector to do byte range lookup on each advice
        // column. In this way, ExecutionGadget could enable the byte range
        // lookup by enable qs_byte_lookup.
        for advice in advices {
            meta.lookup_any("Qs byte", |meta| {
                let advice = meta.query_advice(advice, Rotation::cur());
                let qs_byte_lookup = meta.query_advice(qs_byte_lookup, Rotation::cur());

                vec![
                    qs_byte_lookup.clone() * FixedTableTag::Range256.expr(),
                    qs_byte_lookup * advice,
                    0u64.expr(),
                    0u64.expr(),
                ]
                .into_iter()
                .zip(fixed_table.table_exprs(meta).to_vec().into_iter())
                .collect::<Vec<_>>()
            });
        }

        macro_rules! configure_gadget {
            () => {
                Self::configure_gadget(
                    meta,
                    q_step,
                    q_step_first,
                    &power_of_randomness,
                    &step_curr,
                    &step_next,
                    &mut independent_lookups,
                    &mut presets_map,
                )
            };
        }

        let config = Self {
            q_step,
            q_step_first,
            q_step_last,
            is0_gadget: configure_gadget!(),
            add_gadget: configure_gadget!(),
            mul_gadget: configure_gadget!(),
            bitwise_gadget: configure_gadget!(),
            begin_tx_gadget: configure_gadget!(),
            byte_gadget: configure_gadget!(),
            calldatacopy_gadget: configure_gadget!(),
            calldataload_gadget: configure_gadget!(),
            calldatasize_gadget: configure_gadget!(),
            caller_gadget: configure_gadget!(),
            call_value_gadget: configure_gadget!(),
            comparator_gadget: configure_gadget!(),
            dup_gadget: configure_gadget!(),
            end_block_gadget: configure_gadget!(),
            end_tx_gadget: configure_gadget!(),
            error_oog_static_memory_gadget: configure_gadget!(),
            jump_gadget: configure_gadget!(),
            jumpdest_gadget: configure_gadget!(),
            jumpi_gadget: configure_gadget!(),
            gas_gadget: configure_gadget!(),
            memory_gadget: configure_gadget!(),
            copy_to_memory_gadget: configure_gadget!(),
            pc_gadget: configure_gadget!(),
            pop_gadget: configure_gadget!(),
            push_gadget: configure_gadget!(),
            selfbalance_gadget: configure_gadget!(),
            signed_comparator_gadget: configure_gadget!(),
            signextend_gadget: configure_gadget!(),
            stop_gadget: configure_gadget!(),
            swap_gadget: configure_gadget!(),
            msize_gadget: configure_gadget!(),
            coinbase_gadget: configure_gadget!(),
            timestamp_gadget: configure_gadget!(),
            number_gadget: configure_gadget!(),
            sload_gadget: configure_gadget!(),
            sstore_gadget: configure_gadget!(),
            step: step_curr,
            presets_map,
        };

        Self::configure_lookup(
            meta,
            q_step,
            fixed_table,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            independent_lookups,
        );

        config
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_gadget<G: ExecutionGadget<F>>(
        meta: &mut ConstraintSystem<F>,
        q_step: Selector,
        q_step_first: Selector,
        power_of_randomness: &[Expression<F>; 31],
        step_curr: &Step<F>,
        step_next: &Step<F>,
        independent_lookups: &mut Vec<Vec<Lookup<F>>>,
        presets_map: &mut HashMap<ExecutionState, Vec<Preset<F>>>,
    ) -> G {
        let mut cb = ConstraintBuilder::new(
            step_curr,
            step_next,
            power_of_randomness,
            G::EXECUTION_STATE,
        );

        let gadget = G::configure(&mut cb);

        let (constraints, constraints_first_step, lookups, presets) = cb.build();
        debug_assert!(
            presets_map.insert(G::EXECUTION_STATE, presets).is_none(),
            "execution state already configured"
        );

        for (selector, constraints) in [
            (q_step, constraints),
            (q_step_first, constraints_first_step),
        ] {
            if !constraints.is_empty() {
                meta.create_gate(G::NAME, |meta| {
                    let selector = meta.query_selector(selector);

                    constraints
                        .into_iter()
                        .map(move |(name, constraint)| (name, selector.clone() * constraint))
                });
            }
        }

        // Push lookups of this ExecutionState to independent_lookups for
        // further configuration in configure_lookup.
        independent_lookups.push(lookups.iter().map(|(_, lookup)| lookup.clone()).collect());

        gadget
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_lookup<TxTable, RwTable, BytecodeTable, BlockTable>(
        meta: &mut ConstraintSystem<F>,
        q_step: Selector,
        fixed_table: [Column<Fixed>; 4],
        tx_table: TxTable,
        rw_table: RwTable,
        bytecode_table: BytecodeTable,
        block_table: BlockTable,
        independent_lookups: Vec<Vec<Lookup<F>>>,
    ) where
        TxTable: LookupTable<F, 4>,
        RwTable: LookupTable<F, 11>,
        BytecodeTable: LookupTable<F, 4>,
        BlockTable: LookupTable<F, 3>,
    {
        // Because one and only one ExecutionState is enabled at a step, we then
        // know only one of independent_lookups will be enabled at a step, so we
        // can add up them together to reduce the amount of lookup arguments.
        // This map holds all added up independent lookups as accumulated
        // lookups, and will be used in configuring lookup arguments later.
        let mut acc_lookups_of_table = HashMap::new();

        for lookups in independent_lookups {
            let mut index_of_table = HashMap::new();

            for lookup in lookups {
                let table = lookup.table();
                let acc_lookups = acc_lookups_of_table.entry(table).or_insert_with(Vec::new);
                let index = index_of_table.entry(table).or_insert(0);

                if *index == acc_lookups.len() {
                    acc_lookups.push(lookup.input_exprs());
                } else {
                    // Add up independent lookup together
                    for (acc, expr) in acc_lookups[*index]
                        .iter_mut()
                        .zip(lookup.input_exprs().into_iter())
                    {
                        *acc = acc.clone() + expr;
                    }
                }
                *index += 1;
            }
        }

        macro_rules! lookup {
            ($id:path, $table:ident, $descrip:expr) => {
                if let Some(acc_lookups) = acc_lookups_of_table.remove(&$id) {
                    for (lookup_idx, input_exprs) in acc_lookups.into_iter().enumerate() {
                        let idx = meta.lookup_any(concat!("LOOKUP: ", stringify!($descrip)), |meta| {
                            let q_step = meta.query_selector(q_step);
                            input_exprs
                                .into_iter()
                                .zip($table.table_exprs(meta).to_vec().into_iter())
                                .map(|(input, table)| (q_step.clone() * input, table))
                                .collect::<Vec<_>>()
                        });
                        println!("LOOKUP TABLE {} <=> {} {}", idx, stringify!($descrip), lookup_idx);
                    }
                }
            };
        }

        lookup!(Table::Fixed, fixed_table, "Fixed table");
        lookup!(Table::Tx, tx_table, "Tx table");
        lookup!(Table::Rw, rw_table, "RW table");
        lookup!(Table::Bytecode, bytecode_table, "Bytecode table");
        lookup!(Table::Block, block_table, "Block table");
    }

    pub fn assign_block(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Execution step",
            |mut region| {
                let mut offset = 0;

                self.q_step_first.enable(&mut region, offset)?;

                for transaction in &block.txs {
                    for step in &transaction.steps {
                        let call = &transaction.calls[step.call_index];

                        self.q_step.enable(&mut region, offset)?;
                        self.assign_exec_step(&mut region, offset, block, transaction, call, step)?;

                        offset += STEP_HEIGHT;
                    }
                }
                Ok(())
            },
        )?;

        // TODO: Pad leftover region to the desired capacity
        // TODO: Enable q_step_last

        Ok(())
    }

    /// Assign exact steps in block without padding for unit test purpose
    pub fn assign_block_exact(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Execution step",
            |mut region| {
                let mut offset = 0;

                self.q_step_first.enable(&mut region, offset)?;

                for transaction in &block.txs {
                    for step in &transaction.steps {
                        let call = &transaction.calls[step.call_index];

                        self.q_step.enable(&mut region, offset)?;
                        self.assign_exec_step(&mut region, offset, block, transaction, call, step)?;

                        offset += STEP_HEIGHT;
                    }
                }

                self.q_step_last.enable(&mut region, offset - STEP_HEIGHT)?;

                Ok(())
            },
        )
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.step
            .assign_exec_step(region, offset, block, transaction, call, step)?;

        for (cell, value) in self
            .presets_map
            .get(&step.execution_state)
            .expect("not implemented")
        {
            cell.assign(region, offset, Some(*value))?;
        }

        macro_rules! assign_exec_step {
            ($gadget:expr) => {
                $gadget.assign_exec_step(region, offset, block, transaction, call, step)?
            };
        }

        match step.execution_state {
            ExecutionState::BeginTx => assign_exec_step!(self.begin_tx_gadget),
            ExecutionState::EndTx => assign_exec_step!(self.end_tx_gadget),
            ExecutionState::EndBlock => {
                assign_exec_step!(self.end_block_gadget)
            }
            ExecutionState::STOP => assign_exec_step!(self.stop_gadget),
            ExecutionState::ADD => assign_exec_step!(self.add_gadget),
            ExecutionState::MUL => assign_exec_step!(self.mul_gadget),
            ExecutionState::BITWISE => assign_exec_step!(self.bitwise_gadget),
            ExecutionState::SIGNEXTEND => {
                assign_exec_step!(self.signextend_gadget)
            }
            ExecutionState::ISZERO => assign_exec_step!(self.is0_gadget),
            ExecutionState::CMP => assign_exec_step!(self.comparator_gadget),
            ExecutionState::SCMP => {
                assign_exec_step!(self.signed_comparator_gadget)
            }
            ExecutionState::BYTE => assign_exec_step!(self.byte_gadget),
            ExecutionState::POP => assign_exec_step!(self.pop_gadget),
            ExecutionState::MEMORY => assign_exec_step!(self.memory_gadget),
            ExecutionState::PC => assign_exec_step!(self.pc_gadget),
            ExecutionState::MSIZE => assign_exec_step!(self.msize_gadget),
            ExecutionState::JUMP => assign_exec_step!(self.jump_gadget),
            ExecutionState::JUMPI => assign_exec_step!(self.jumpi_gadget),
            ExecutionState::JUMPDEST => {
                assign_exec_step!(self.jumpdest_gadget)
            }
            ExecutionState::GAS => assign_exec_step!(self.gas_gadget),
            ExecutionState::PUSH => assign_exec_step!(self.push_gadget),
            ExecutionState::DUP => assign_exec_step!(self.dup_gadget),
            ExecutionState::SWAP => assign_exec_step!(self.swap_gadget),
            ExecutionState::CALLER => assign_exec_step!(self.caller_gadget),
            ExecutionState::CALLVALUE => {
                assign_exec_step!(self.call_value_gadget)
            }
            ExecutionState::COINBASE => assign_exec_step!(self.coinbase_gadget),
            ExecutionState::TIMESTAMP => {
                assign_exec_step!(self.timestamp_gadget)
            }
            ExecutionState::NUMBER => {
                assign_exec_step!(self.number_gadget)
            }
            ExecutionState::SELFBALANCE => assign_exec_step!(self.selfbalance_gadget),
            ExecutionState::SLOAD => assign_exec_step!(self.sload_gadget),
            ExecutionState::SSTORE => assign_exec_step!(self.sstore_gadget),
            ExecutionState::CALLDATACOPY => {
                assign_exec_step!(self.calldatacopy_gadget)
            }
            ExecutionState::CopyToMemory => {
                assign_exec_step!(self.copy_to_memory_gadget)
            }
            ExecutionState::CALLDATALOAD => {
                assign_exec_step!(self.calldataload_gadget)
            }
            ExecutionState::ErrorOutOfGasStaticMemoryExpansion => {
                assign_exec_step!(self.error_oog_static_memory_gadget)
            }
            ExecutionState::CALLDATASIZE => {
                assign_exec_step!(self.calldatasize_gadget)
            }
            _ => unimplemented!(),
        }

        Ok(())
    }
}
