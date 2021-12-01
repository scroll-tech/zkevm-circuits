use crate::{
    evm_circuit::{
        param::{STEP_HEIGHT, STEP_WIDTH},
        step::{ExecutionResult, Preset, Step},
        table::{FixedTableTag, Lookup, LookupTable, Table},
        util::constraint_builder::ConstraintBuilder,
    },
    util::Expr,
};
use halo2::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region},
    plonk::{
        Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};
use std::collections::HashMap;

mod add;
mod and;
mod byte;
mod comparator;
mod dup;
mod error_oog_pure_memory;
mod jumpdest;
mod memory;
mod pc;
mod pop;
mod push;
mod signextend;
mod stop;
mod swap;
use add::AddGadget;
use and::AndGadget;
use byte::ByteGadget;
use comparator::ComparatorGadget;
use dup::DupGadget;
use error_oog_pure_memory::ErrorOOGPureMemoryGadget;
use jumpdest::JumpdestGadget;
use memory::MemoryGadget;
use pc::PcGadget;
use pop::PopGadget;
use push::PushGadget;
use signextend::SignextendGadget;
use stop::StopGadget;
use swap::SwapGadget;

#[allow(missing_docs)]
pub mod bus_mapping_tmp {
    use crate::evm_circuit::{
        step::ExecutionResult,
        table::{RwTableTag, TxContextFieldTag},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{Address, ToLittleEndian, ToScalar, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use sha3::{Digest, Keccak256};

    #[derive(Debug, Default)]
    pub struct Block<F> {
        // randomness for random linear combination
        pub randomness: F,
        pub txs: Vec<Transaction<F>>,
        pub rws: Vec<Rw>,
        pub bytecodes: Vec<Bytecode>,
    }

    #[derive(Debug, Default)]
    pub struct Transaction<F> {
        // Context
        pub id: usize,
        pub nonce: u64,
        pub gas: u64,
        pub gas_tip_cap: Word,
        pub gas_fee_cap: Word,
        pub caller_address: Address,
        pub callee_address: Address,
        pub is_create: bool,
        pub value: Word,
        pub calldata_length: usize,
        pub calldata: Vec<u8>,

        pub calls: Vec<Call<F>>,
        pub steps: Vec<ExecStep>,
    }

    impl<F: FieldExt> Transaction<F> {
        pub fn table_assignments(&self, randomness: F) -> Vec<[F; 4]> {
            [
                vec![
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::Nonce as u64),
                        F::zero(),
                        F::from_u64(self.nonce),
                    ],
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::Gas as u64),
                        F::zero(),
                        F::from_u64(self.gas),
                    ],
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::GasTipCap as u64),
                        F::zero(),
                        RandomLinearCombination::random_linear_combine(
                            self.gas_tip_cap.to_le_bytes(),
                            randomness,
                        ),
                    ],
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::GasFeeCap as u64),
                        F::zero(),
                        RandomLinearCombination::random_linear_combine(
                            self.gas_fee_cap.to_le_bytes(),
                            randomness,
                        ),
                    ],
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::CallerAddress as u64),
                        F::zero(),
                        self.caller_address.to_scalar().unwrap(),
                    ],
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::CalleeAddress as u64),
                        F::zero(),
                        self.callee_address.to_scalar().unwrap(),
                    ],
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::IsCreate as u64),
                        F::zero(),
                        F::from_u64(self.is_create as u64),
                    ],
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::Value as u64),
                        F::zero(),
                        RandomLinearCombination::random_linear_combine(
                            self.value.to_le_bytes(),
                            randomness,
                        ),
                    ],
                    [
                        F::from_u64(self.id as u64),
                        F::from_u64(TxContextFieldTag::CalldataLength as u64),
                        F::zero(),
                        F::from_u64(self.calldata_length as u64),
                    ],
                ],
                self.calldata
                    .iter()
                    .enumerate()
                    .map(|(idx, byte)| {
                        [
                            F::from_u64(self.id as u64),
                            F::from_u64(TxContextFieldTag::Calldata as u64),
                            F::from_u64(idx as u64),
                            F::from_u64(*byte as u64),
                        ]
                    })
                    .collect(),
            ]
            .concat()
        }
    }

    #[derive(Debug, Default)]
    pub struct Call<F> {
        pub id: usize,
        pub is_root: bool,
        pub is_create: bool,
        pub opcode_source: F,
    }

    #[derive(Debug, Default)]
    pub struct ExecStep {
        pub call_idx: usize,
        pub rw_indices: Vec<usize>,
        pub execution_result: ExecutionResult,
        pub rw_counter: usize,
        pub program_counter: u64,
        pub stack_pointer: usize,
        pub gas_left: u64,
        pub gas_cost: u64,
        pub memory_size: u64,
        pub state_write_counter: usize,
        pub opcode: Option<OpcodeId>,
    }

    #[derive(Debug)]
    pub struct Bytecode {
        pub hash: Word,
        pub bytes: Vec<u8>,
    }

    impl Bytecode {
        pub fn new(bytes: Vec<u8>) -> Self {
            Self {
                hash: Word::from_big_endian(
                    Keccak256::digest(&bytes).as_slice(),
                ),
                bytes,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub enum Rw {
        TxAccessListAccount {
            rw_counter: usize,
            is_write: bool,
        },
        TxAccessListStorageSlot {
            rw_counter: usize,
            is_write: bool,
        },
        TxRefund {
            rw_counter: usize,
            is_write: bool,
        },
        Account {
            rw_counter: usize,
            is_write: bool,
        },
        AccountStorage {
            rw_counter: usize,
            is_write: bool,
        },
        AccountDestructed {
            rw_counter: usize,
            is_write: bool,
        },
        CallContext {
            rw_counter: usize,
            is_write: bool,
        },
        Stack {
            rw_counter: usize,
            is_write: bool,
            call_id: usize,
            stack_pointer: usize,
            value: Word,
        },
        Memory {
            rw_counter: usize,
            is_write: bool,
            call_id: usize,
            memory_address: u64,
            byte: u8,
        },
    }

    impl Rw {
        pub fn stack_value(&self) -> Word {
            match self {
                Self::Stack { value, .. } => *value,
                _ => unreachable!(),
            }
        }

        pub fn table_assignment<F: FieldExt>(&self, randomness: F) -> [F; 8] {
            match self {
                Self::Stack {
                    rw_counter,
                    is_write,
                    call_id,
                    stack_pointer,
                    value,
                } => [
                    F::from_u64(*rw_counter as u64),
                    F::from_u64(*is_write as u64),
                    F::from_u64(RwTableTag::Stack as u64),
                    F::from_u64(*call_id as u64),
                    F::from_u64(*stack_pointer as u64),
                    RandomLinearCombination::random_linear_combine(
                        value.to_le_bytes(),
                        randomness,
                    ),
                    F::zero(),
                    F::zero(),
                ],
                Self::Memory {
                    rw_counter,
                    is_write,
                    call_id,
                    memory_address,
                    byte,
                } => [
                    F::from_u64(*rw_counter as u64),
                    F::from_u64(*is_write as u64),
                    F::from_u64(RwTableTag::Memory as u64),
                    F::from_u64(*call_id as u64),
                    F::from_u64(*memory_address),
                    F::from_u64(*byte as u64),
                    F::zero(),
                    F::zero(),
                ],
                _ => unimplemented!(),
            }
        }
    }
}

use bus_mapping_tmp::{Block, Call, ExecStep, Transaction};

// convert from bus_mapping to bus_mapping_tmp
#[allow(missing_docs)]
pub mod bus_mapping_tmp_convert {
    use crate::evm_circuit::{
        bus_mapping_tmp::Rw, step::ExecutionResult,
        util::RandomLinearCombination,
    };
    use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
    use halo2::arithmetic::FieldExt;
    use num::traits::ops;
    use pasta_curves::pallas::Base;
    use std::convert::TryInto;

    use super::bus_mapping_tmp;

    fn get_execution_result_from_step(
        step: &bus_mapping::circuit_input_builder::ExecStep,
    ) -> ExecutionResult {
        // TODO: convert error (circuit_input_builder.rs)
        assert!(step.error.is_none());
        if step.op.is_dup() {
            return ExecutionResult::DUP;
        }
        if step.op.is_push() {
            return ExecutionResult::PUSH;
        }
        if step.op.is_swap() {
            return ExecutionResult::SWAP;
        }
        match step.op {
            OpcodeId::ADD => ExecutionResult::ADD,
            OpcodeId::SUB => ExecutionResult::ADD,
            OpcodeId::EQ => ExecutionResult::LT,
            OpcodeId::GT => ExecutionResult::LT,
            OpcodeId::LT => ExecutionResult::LT,
            OpcodeId::SIGNEXTEND => ExecutionResult::SIGNEXTEND,
            OpcodeId::STOP => ExecutionResult::STOP,
            OpcodeId::AND => ExecutionResult::AND,
            OpcodeId::XOR => ExecutionResult::AND,
            OpcodeId::OR => ExecutionResult::AND,
            OpcodeId::POP => ExecutionResult::POP,
            OpcodeId::PUSH32 => ExecutionResult::PUSH,
            OpcodeId::BYTE => ExecutionResult::BYTE,
            OpcodeId::MLOAD => ExecutionResult::MLOAD,
            OpcodeId::MSTORE => ExecutionResult::MLOAD,
            OpcodeId::MSTORE8 => ExecutionResult::MLOAD,
            OpcodeId::JUMPDEST => ExecutionResult::JUMPDEST,
            OpcodeId::PC => ExecutionResult::PC,
            _ => unimplemented!("invalid opcode {:?}", step.op),
        }
    }

    fn bytecode_convert(
        b: &bus_mapping::bytecode::Bytecode,
    ) -> bus_mapping_tmp::Bytecode {
        bus_mapping_tmp::Bytecode::new(b.to_bytes())
    }

    fn step_convert(
        prev: Option<&bus_mapping::circuit_input_builder::ExecStep>,
        step: &bus_mapping::circuit_input_builder::ExecStep,
        ops_len: (usize, usize, usize),
    ) -> bus_mapping_tmp::ExecStep {
        let (stack_ops_len, memory_ops_len, _storage_ops_len) = ops_len;
        //println!("prev is {:#?}", prev);
        let result = bus_mapping_tmp::ExecStep {
            rw_indices: step
                .bus_mapping_instance
                .iter()
                .map(|x| {
                    let index = x.as_usize() - 1;
                    match x.target() {
                        bus_mapping::operation::Target::Stack => index,
                        bus_mapping::operation::Target::Memory => {
                            index + stack_ops_len
                        }
                        bus_mapping::operation::Target::Storage => {
                            index + stack_ops_len + memory_ops_len
                        }
                    }
                })
                .collect(),
            execution_result: get_execution_result_from_step(step),
            rw_counter: usize::from(step.gc),
            program_counter: usize::from(step.pc) as u64,
            stack_pointer: 1024 - step.stack_size,
            gas_left: step.gas_left.0,
            gas_cost: step.gas_cost.as_u64(),
            opcode: Some(step.op),
            memory_size: match prev {
                None => 0,
                Some(prev_step) => (prev_step.memory_size as u64) / 32, /* memory size in word */
            },
            ..Default::default()
        };
        result
    }
    fn tx_convert(
        randomness: Base,
        bytecode: &bus_mapping_tmp::Bytecode,
        tx: &bus_mapping::circuit_input_builder::Transaction,
        ops_len: (usize, usize, usize),
    ) -> bus_mapping_tmp::Transaction<Base> {
        let mut result: bus_mapping_tmp::Transaction<Base> = Default::default();
        result.calls = vec![bus_mapping_tmp::Call {
            id: 1,
            is_root: true,
            is_create: tx.is_create(),
            opcode_source: RandomLinearCombination::random_linear_combine(
                bytecode.hash.to_le_bytes(),
                randomness,
            ),
        }];
        for idx in 0..tx.steps().len() {
            let cur_step = &tx.steps()[idx];
            let prev_step = if idx == 0 {
                None
            } else {
                Some(&tx.steps()[idx - 1])
            };
            result
                .steps
                .push(step_convert(prev_step, cur_step, ops_len));
        }
        result
    }

    pub fn block_convert(
        bytecode: &bus_mapping::bytecode::Bytecode,
        b: &bus_mapping::circuit_input_builder::Block,
    ) -> bus_mapping_tmp::Block<Base> {
        let randomness = Base::rand();
        let bytecode = bytecode_convert(bytecode);

        // here stack_ops/memory_ops/etc are merged into a single array
        // in EVM circuit, we need gc-sorted ops
        let mut stack_ops = b.container.sorted_stack();
        stack_ops.sort_by_key(|s| usize::from(s.gc()));
        let mut memory_ops = b.container.sorted_memory();
        memory_ops.sort_by_key(|s| usize::from(s.gc()));
        let mut storage_ops = b.container.sorted_storage();
        storage_ops.sort_by_key(|s| usize::from(s.gc()));

        let mut block = bus_mapping_tmp::Block {
            randomness,
            txs: b
                .txs()
                .iter()
                .map(|tx| {
                    tx_convert(
                        randomness,
                        &bytecode,
                        tx,
                        (stack_ops.len(), memory_ops.len(), storage_ops.len()),
                    )
                })
                .collect(),
            bytecodes: vec![bytecode],
            ..Default::default()
        };

        block.rws.extend(stack_ops.iter().map(|s| Rw::Stack {
            rw_counter: s.gc().into(),
            is_write: s.op().rw().is_write(),
            call_id: 1,
            stack_pointer: usize::from(*s.op().address()),
            value: *s.op().value(),
        }));
        block.rws.extend(memory_ops.iter().map(|s| Rw::Memory {
            rw_counter: s.gc().into(),
            is_write: s.op().rw().is_write(),
            call_id: 1,
            memory_address: u64::from_le_bytes(
                s.op().address().to_le_bytes()[..8].try_into().unwrap(),
            ),
            byte: s.op().value(),
        }));
        // TODO add storage ops

        block
    }

    pub fn build_block_from_trace_code_at_start(
        bytecode: &bus_mapping::bytecode::Bytecode,
    ) -> bus_mapping_tmp::Block<pasta_curves::pallas::Base> {
        let block =
            bus_mapping::mock::BlockData::new_single_tx_trace_code_at_start(
                &bytecode,
            )
            .unwrap();
        let mut builder =
            bus_mapping::circuit_input_builder::CircuitInputBuilder::new(
                block.eth_block.clone(),
                block.block_ctants.clone(),
            );
        builder.handle_tx(&block.eth_tx, &block.geth_trace).unwrap();

        super::bus_mapping_tmp_convert::block_convert(
            &bytecode,
            &builder.block,
        )
    }
}

pub(crate) trait ExecutionGadget<F: FieldExt> {
    const NAME: &'static str;

    const EXECUTION_RESULT: ExecutionResult;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self;

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction<F>,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutionConfig<F> {
    q_step: Selector,
    step: Step<F>,
    presets_map: HashMap<ExecutionResult, Vec<Preset<F>>>,
    add_gadget: AddGadget<F>,
    and_gadget: AndGadget<F>,
    byte_gadget: ByteGadget<F>,
    comparator_gadget: ComparatorGadget<F>,
    dup_gadget: DupGadget<F>,
    error_oog_pure_memory_gadget: ErrorOOGPureMemoryGadget<F>,
    jumpdest_gadget: JumpdestGadget<F>,
    memory_gadget: MemoryGadget<F>,
    pc_gadget: PcGadget<F>,
    pop_gadget: PopGadget<F>,
    push_gadget: PushGadget<F>,
    signextend_gadget: SignextendGadget<F>,
    stop_gadget: StopGadget<F>,
    swap_gadget: SwapGadget<F>,
}

impl<F: FieldExt> ExecutionConfig<F> {
    pub(crate) fn configure<TxTable, RwTable, BytecodeTable>(
        meta: &mut ConstraintSystem<F>,
        randomness: Column<Instance>,
        fixed_table: [Column<Fixed>; 4],
        tx_table: TxTable,
        rw_table: RwTable,
        bytecode_table: BytecodeTable,
    ) -> Self
    where
        TxTable: LookupTable<F, 4>,
        RwTable: LookupTable<F, 8>,
        BytecodeTable: LookupTable<F, 3>,
    {
        let q_step = meta.selector();
        let qs_byte_lookup = meta.advice_column();
        let advices = [(); STEP_WIDTH].map(|_| meta.advice_column());

        let randomness = {
            let mut expr = None;
            meta.create_gate("Query randomness", |meta| {
                expr = Some(meta.query_instance(randomness, Rotation::cur()));
                vec![0.expr()]
            });
            expr.unwrap()
        };

        let step_curr = Step::new(meta, qs_byte_lookup, advices, false);
        let step_next = Step::new(meta, qs_byte_lookup, advices, true);
        let mut independent_lookups = Vec::new();
        let mut presets_map = HashMap::new();

        meta.create_gate("Constrain execution result", |meta| {
            let q_step = meta.query_selector(q_step);
            let sum_to_one = step_curr
                .state
                .execution_result
                .iter()
                .fold(1.expr(), |acc, cell| acc - cell.expr());
            let bool_checks = step_curr
                .state
                .execution_result
                .iter()
                .map(|cell| cell.expr() * (1.expr() - cell.expr()));

            std::iter::once(sum_to_one)
                .chain(bool_checks)
                .map(move |poly| q_step.clone() * poly)
        });

        for advice in advices {
            meta.lookup(|meta| {
                let advice = meta.query_advice(advice, Rotation::cur());
                let qs_byte_lookup =
                    meta.query_advice(qs_byte_lookup, Rotation::cur());

                vec![
                    qs_byte_lookup.clone() * FixedTableTag::Range256.expr(),
                    qs_byte_lookup * advice,
                    0.expr(),
                    0.expr(),
                ]
                .into_iter()
                .zip(fixed_table.table_exprs(meta).to_vec().into_iter())
                .map(|(input, table)| (input, table))
                .collect::<Vec<_>>()
            });
        }

        macro_rules! configure_gadget {
            () => {
                Self::configure_gadget(
                    meta,
                    q_step,
                    &randomness,
                    &step_curr,
                    &step_next,
                    &mut independent_lookups,
                    &mut presets_map,
                )
            };
        }

        let config = Self {
            q_step,
            add_gadget: configure_gadget!(),
            and_gadget: configure_gadget!(),
            byte_gadget: configure_gadget!(),
            comparator_gadget: configure_gadget!(),
            dup_gadget: configure_gadget!(),
            error_oog_pure_memory_gadget: configure_gadget!(),
            jumpdest_gadget: configure_gadget!(),
            memory_gadget: configure_gadget!(),
            pc_gadget: configure_gadget!(),
            pop_gadget: configure_gadget!(),
            push_gadget: configure_gadget!(),
            signextend_gadget: configure_gadget!(),
            stop_gadget: configure_gadget!(),
            swap_gadget: configure_gadget!(),
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
            independent_lookups,
        );

        config
    }

    fn configure_gadget<G: ExecutionGadget<F>>(
        meta: &mut ConstraintSystem<F>,
        q_step: Selector,
        randomness: &Expression<F>,
        step_curr: &Step<F>,
        step_next: &Step<F>,
        independent_lookups: &mut Vec<Vec<Lookup<F>>>,
        presets_map: &mut HashMap<ExecutionResult, Vec<Preset<F>>>,
    ) -> G {
        let mut cb = ConstraintBuilder::new(
            step_curr,
            step_next,
            randomness.clone(),
            G::EXECUTION_RESULT,
        );

        let gadget = G::configure(&mut cb);

        let (constraints, lookups, presets) = cb.build();
        assert!(
            presets_map.insert(G::EXECUTION_RESULT, presets).is_none(),
            "execution result already configured"
        );

        if !constraints.is_empty() {
            meta.create_gate(G::NAME, |meta| {
                let q_step = meta.query_selector(q_step);

                constraints.into_iter().map(move |(name, constraint)| {
                    (name, q_step.clone() * constraint)
                })
            });
        }

        independent_lookups.push(lookups);

        gadget
    }

    fn configure_lookup<TxTable, RwTable, BytecodeTable>(
        meta: &mut ConstraintSystem<F>,
        q_step: Selector,
        fixed_table: [Column<Fixed>; 4],
        tx_table: TxTable,
        rw_table: RwTable,
        bytecode_table: BytecodeTable,
        independent_lookups: Vec<Vec<Lookup<F>>>,
    ) where
        TxTable: LookupTable<F, 4>,
        RwTable: LookupTable<F, 8>,
        BytecodeTable: LookupTable<F, 3>,
    {
        let mut input_exprs_map = HashMap::new();

        for lookups in independent_lookups {
            let mut index_map = HashMap::new();

            for lookup in lookups {
                let table = lookup.table();
                let input_exprs =
                    input_exprs_map.entry(table).or_insert_with(Vec::new);
                let index = index_map.entry(table).or_insert(0);

                if *index == input_exprs.len() {
                    input_exprs.push(lookup.input_exprs());
                } else {
                    for (acc, expr) in input_exprs[*index]
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
            ($id:path, $table:ident) => {
                if let Some(input_exprs) = input_exprs_map.remove(&$id) {
                    for input_exprs in input_exprs {
                        meta.lookup(|meta| {
                            let q_step = meta.query_selector(q_step);
                            input_exprs
                                .into_iter()
                                .zip(
                                    $table
                                        .table_exprs(meta)
                                        .to_vec()
                                        .into_iter(),
                                )
                                .map(|(input, table)| {
                                    (q_step.clone() * input, table)
                                })
                                .collect::<Vec<_>>()
                        });
                    }
                }
            };
        }

        lookup!(Table::Fixed, fixed_table);
        lookup!(Table::Tx, tx_table);
        lookup!(Table::Rw, rw_table);
        lookup!(Table::Bytecode, bytecode_table);
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
                for transaction in &block.txs {
                    for step in &transaction.steps {
                        let call = &transaction.calls[step.call_idx];

                        self.q_step.enable(&mut region, offset)?;
                        self.assign_exec_step(
                            &mut region,
                            offset,
                            block,
                            transaction,
                            call,
                            step,
                        )?;

                        offset += STEP_HEIGHT;
                    }
                }
                Ok(())
            },
        )
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction<F>,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.step.assign_exec_step(region, offset, call, step)?;

        for (cell, value) in self
            .presets_map
            .get(&step.execution_result)
            .expect("not implemented")
        {
            cell.assign(region, offset, Some(*value))?;
        }

        macro_rules! assign_exec_step {
            ($gadget:expr) => {
                $gadget.assign_exec_step(
                    region,
                    offset,
                    block,
                    transaction,
                    call,
                    step,
                )?
            };
        }

        match step.execution_result {
            ExecutionResult::STOP => assign_exec_step!(self.stop_gadget),
            ExecutionResult::ADD => assign_exec_step!(self.add_gadget),
            ExecutionResult::AND => assign_exec_step!(self.and_gadget),
            ExecutionResult::SIGNEXTEND => {
                assign_exec_step!(self.signextend_gadget)
            }
            ExecutionResult::LT => assign_exec_step!(self.comparator_gadget),
            ExecutionResult::BYTE => assign_exec_step!(self.byte_gadget),
            ExecutionResult::POP => assign_exec_step!(self.pop_gadget),
            ExecutionResult::MLOAD => assign_exec_step!(self.memory_gadget),
            ExecutionResult::PC => assign_exec_step!(self.pc_gadget),
            ExecutionResult::JUMPDEST => {
                assign_exec_step!(self.jumpdest_gadget)
            }
            ExecutionResult::PUSH => assign_exec_step!(self.push_gadget),
            ExecutionResult::DUP => assign_exec_step!(self.dup_gadget),
            ExecutionResult::SWAP => assign_exec_step!(self.swap_gadget),
            ExecutionResult::ErrorOutOfGasPureMemory => {
                assign_exec_step!(self.error_oog_pure_memory_gadget)
            }
            _ => unimplemented!(),
        }

        Ok(())
    }
}
