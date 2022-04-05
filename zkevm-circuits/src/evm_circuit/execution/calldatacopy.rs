use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        table::{CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            Cell, MemoryAddress,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use eth_types::ToLittleEndian;
use halo2_proofs::{circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct CallDataCopyGadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddressGadget<F>,
    data_offset: MemoryAddress<F>,
    tx_id: Cell<F>,
    call_data_length: Cell<F>,
    call_data_offset: Cell<F>, // Only used in the internal call
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for CallDataCopyGadget<F> {
    const NAME: &'static str = "CALLDATACOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATACOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let memory_offset = cb.query_cell();
        let data_offset = cb.query_rlc();
        let length = cb.query_rlc();

        // Pop memory_offset, data_offset, length from stack
        cb.stack_pop(memory_offset.expr());
        cb.stack_pop(data_offset.expr());
        cb.stack_pop(length.expr());

        let memory_address = MemoryAddressGadget::construct(cb, memory_offset, length);
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let call_data_length = cb.query_cell();
        let call_data_offset = cb.query_cell();

        // Lookup the calldata_length and caller_address in Tx context table or
        // Call context table
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            cb.tx_context_lookup(
                tx_id.expr(),
                TxContextFieldTag::CallDataLength,
                None,
                call_data_length.expr(),
            );
            cb.require_zero(
                "call_data_offset == 0 in the root call",
                call_data_offset.expr(),
            )
        });
        cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallDataLength,
                call_data_length.expr(),
            );
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallDataOffset,
                call_data_offset.expr(),
            )
        });

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_word_size.expr(),
            [memory_address.address()],
        );
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        // Constrain the next step CopyToMemory if length != 0
        cb.constrain_next_step(
            ExecutionState::CopyToMemory,
            Some(memory_address.has_length()),
            |cb| {
                let next_src_addr = cb.query_cell();
                let next_dst_addr = cb.query_cell();
                let next_bytes_left = cb.query_cell();
                let next_src_addr_end = cb.query_cell();
                let next_from_tx = cb.query_cell();
                let next_tx_id = cb.query_cell();
                cb.require_equal(
                    "next_src_addr = data_offset + call_data_offset",
                    next_src_addr.expr(),
                    from_bytes::expr(&data_offset.cells) + call_data_offset.expr(),
                );
                cb.require_equal(
                    "next_dst_addr = memory_offset",
                    next_dst_addr.expr(),
                    memory_address.offset(),
                );
                cb.require_equal(
                    "next_bytes_left = length",
                    next_bytes_left.expr(),
                    memory_address.length(),
                );
                cb.require_equal(
                    "next_src_addr_end = call_data_length + call_data_offset",
                    next_src_addr_end.expr(),
                    call_data_length.expr() + call_data_offset.expr(),
                );
                cb.require_equal(
                    "next_from_tx = is_root",
                    next_from_tx.expr(),
                    cb.curr.state.is_root.expr(),
                );
                cb.require_equal("next_tx_id = tx_id", next_tx_id.expr(), tx_id.expr());
            },
        );

        // State transition
        let step_state_transition = StepStateTransition {
            // 1 tx id lookup + 3 stack pop + option(calldatalength lookup)
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(3.expr()),
            gas_left: Delta(
                -(OpcodeId::CALLDATACOPY.constant_gas_cost().expr() + memory_copier_gas.gas_cost()),
            ),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            data_offset,
            tx_id,
            call_data_length,
            call_data_offset,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [memory_offset, data_offset, length] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
                .map(|idx| block.rws[idx].stack_value());
        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, length, block.randomness)?;
        self.data_offset.assign(
            region,
            offset,
            Some(
                data_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;

        // Call data length and call data offset
        let (call_data_length, call_data_offset) = if call.is_root {
            (tx.call_data_length as u64, 0_u64)
        } else {
            (call.call_data_length, call.call_data_offset)
        };
        self.call_data_length
            .assign(region, offset, Some(F::from(call_data_length as u64)))?;
        self.call_data_offset
            .assign(region, offset, Some(F::from(call_data_offset as u64)))?;

        // Memory expansion
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;

        self.memory_copier_gas.assign(
            region,
            offset,
            length.as_u64(),
            memory_expansion_gas_cost as u64,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::memory_copy::test::make_memory_copy_steps,
        step::ExecutionState,
        table::{CallContextFieldTag, RwTableTag},
        test::{rand_bytes, run_test_circuit_incomplete_fixed_table},
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };
    use crate::test_util::run_test_circuits;
    use eth_types::{
        bytecode,
        evm_types::{gas_utils::memory_copier_gas_cost, GasCost, OpcodeId},
        ToBigEndian, Word,
    };
    use halo2_proofs::arithmetic::BaseExt;
    use mock::test_ctx::{helpers::*, TestContext};
    use pairing::bn256::Fr as Fp;

    fn test_ok_root(call_data_length: usize, memory_offset: Word, data_offset: Word, length: Word) {
        let bytecode = bytecode! {
            PUSH32(length)
            PUSH32(data_offset)
            PUSH32(memory_offset)
            #[start]
            CALLDATACOPY
            STOP
        };
        let call_data = rand_bytes(call_data_length);

        // Get the execution steps from the external tracer
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(bytecode),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .input(call_data.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }

    fn test_ok_internal(
        call_data_offset: Word,
        call_data_length: Word,
        memory_offset: Word,
        data_offset: Word,
        length: Word,
    ) {
        let randomness = Fp::rand();
        let bytecode = Bytecode::new(
            [
                vec![OpcodeId::PUSH32.as_u8()],
                length.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                data_offset.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                memory_offset.to_be_bytes().to_vec(),
                vec![OpcodeId::CALLDATACOPY.as_u8(), OpcodeId::STOP.as_u8()],
            ]
            .concat(),
        );
        let call_id = 1;
        let call_data = rand_bytes(call_data_length.as_usize());

        let mut rws = RwMap(
            [
                (
                    RwTableTag::Stack,
                    vec![
                        Rw::Stack {
                            rw_counter: 1,
                            is_write: false,
                            call_id,
                            stack_pointer: 1021,
                            value: memory_offset,
                        },
                        Rw::Stack {
                            rw_counter: 2,
                            is_write: false,
                            call_id,
                            stack_pointer: 1022,
                            value: data_offset,
                        },
                        Rw::Stack {
                            rw_counter: 3,
                            is_write: false,
                            call_id,
                            stack_pointer: 1023,
                            value: length,
                        },
                    ],
                ),
                (
                    RwTableTag::CallContext,
                    vec![
                        Rw::CallContext {
                            rw_counter: 4,
                            is_write: false,
                            call_id,
                            field_tag: CallContextFieldTag::TxId,
                            value: Word::one(),
                        },
                        Rw::CallContext {
                            rw_counter: 5,
                            is_write: false,
                            call_id,
                            field_tag: CallContextFieldTag::CallDataLength,
                            value: call_data_length,
                        },
                        Rw::CallContext {
                            rw_counter: 6,
                            is_write: false,
                            call_id,
                            field_tag: CallContextFieldTag::CallDataOffset,
                            value: call_data_offset,
                        },
                    ],
                ),
            ]
            .into(),
        );
        let mut rw_counter = 7;

        let curr_memory_word_size =
            (call_data_length.as_u64() + call_data_length.as_u64() + 31) / 32;
        let next_memory_word_size = if length.is_zero() {
            curr_memory_word_size
        } else {
            std::cmp::max(
                curr_memory_word_size,
                (memory_offset.as_u64() + length.as_u64() + 31) / 32,
            )
        };
        let gas_cost = GasCost::FASTEST.as_u64()
            + memory_copier_gas_cost(
                curr_memory_word_size,
                next_memory_word_size,
                length.as_u64(),
            );
        let mut steps = vec![ExecStep {
            rw_indices: vec![
                (RwTableTag::Stack, 0),
                (RwTableTag::Stack, 1),
                (RwTableTag::Stack, 2),
                (RwTableTag::CallContext, 0),
                (RwTableTag::CallContext, 1),
                (RwTableTag::CallContext, 2),
            ],
            execution_state: ExecutionState::CALLDATACOPY,
            rw_counter: 1,
            program_counter: 99,
            stack_pointer: 1021,
            gas_left: gas_cost,
            gas_cost,
            memory_size: curr_memory_word_size * 32,
            opcode: Some(OpcodeId::CALLDATACOPY),
            ..Default::default()
        }];

        if !length.is_zero() {
            make_memory_copy_steps(
                call_id,
                &call_data,
                call_data_offset.as_u64(),
                call_data_offset.as_u64() + data_offset.as_u64(),
                memory_offset.as_u64(),
                length.as_usize(),
                false,
                100,
                1024,
                next_memory_word_size * 32,
                &mut rw_counter,
                &mut rws,
                &mut steps,
            );
        }

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter: 100,
            stack_pointer: 1024,
            opcode: Some(OpcodeId::STOP),
            memory_size: next_memory_word_size * 32,
            ..Default::default()
        });

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                calls: vec![Call {
                    id: call_id,
                    is_root: false,
                    is_create: false,
                    call_data_length: call_data_length.as_u64(),
                    call_data_offset: call_data_offset.as_u64(),
                    code_source: CodeSource::Account(bytecode.hash),
                    ..Default::default()
                }],
                steps,
                ..Default::default()
            }],
            rws,
            bytecodes: vec![bytecode],
            ..Default::default()
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn calldatacopy_gadget_simple() {
        test_ok_root(64, Word::from(0x40), Word::from(0), Word::from(10));
        test_ok_internal(
            Word::from(0x40),
            Word::from(64),
            Word::from(0xA0),
            Word::from(16),
            Word::from(10),
        );
    }

    #[test]
    fn calldatacopy_gadget_multi_step() {
        test_ok_root(128, Word::from(0x40), Word::from(16), Word::from(90));
        test_ok_internal(
            Word::from(0x40),
            Word::from(128),
            Word::from(0x100),
            Word::from(16),
            Word::from(90),
        );
    }

    #[test]
    fn calldatacopy_gadget_out_of_bound() {
        test_ok_root(64, Word::from(0x40), Word::from(32), Word::from(40));
        test_ok_internal(
            Word::from(0x40),
            Word::from(32),
            Word::from(0xA0),
            Word::from(40),
            Word::from(10),
        );
    }

    #[test]
    fn calldatacopy_gadget_zero_length() {
        test_ok_root(64, Word::from(0x40), Word::from(0), Word::from(0));
        test_ok_internal(
            Word::from(0x40),
            Word::from(64),
            Word::from(0xA0),
            Word::from(16),
            Word::from(0),
        );
    }
}
