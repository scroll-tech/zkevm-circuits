use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            not, select, CachedRegion, Cell, MemoryAddress,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};

use std::cmp::min;

#[derive(Clone, Debug)]
pub(crate) struct CallDataCopyGadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddressGadget<F>,
    data_offset: MemoryAddress<F>,
    src_id: Cell<F>,
    call_data_length: Cell<F>,
    call_data_offset: Cell<F>, // Only used in the internal call
    copy_rwc_inc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
}

impl<F: Field> ExecutionGadget<F> for CallDataCopyGadget<F> {
    const NAME: &'static str = "CALLDATACOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATACOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let memory_offset = cb.query_cell_phase2();
        let data_offset = cb.query_word_rlc();
        let length = cb.query_word_rlc();

        // Pop memory_offset, data_offset, length from stack
        cb.stack_pop(memory_offset.expr());
        cb.stack_pop(data_offset.expr());
        cb.stack_pop(length.expr());

        let memory_address = MemoryAddressGadget::construct(cb, memory_offset, length);
        let src_id = cb.query_cell();
        let call_data_length = cb.query_cell();
        let call_data_offset = cb.query_cell();

        // Lookup the calldata_length and caller_address in Tx context table or
        // Call context table
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            cb.call_context_lookup(false.expr(), None, CallContextFieldTag::TxId, src_id.expr());
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallDataLength,
                call_data_length.expr(),
            );
            cb.require_zero(
                "call_data_offset == 0 in the root call",
                call_data_offset.expr(),
            );
        });
        cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::CallerId,
                src_id.expr(),
            );
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
            );
        });

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        let copy_rwc_inc = cb.query_cell();
        let src_tag = select::expr(
            cb.curr.state.is_root.expr(),
            CopyDataType::TxCalldata.expr(),
            CopyDataType::Memory.expr(),
        );
        cb.condition(memory_address.has_length(), |cb| {
            cb.copy_table_lookup(
                src_id.expr(),
                src_tag,
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                call_data_offset.expr() + from_bytes::expr(&data_offset.cells),
                call_data_offset.expr() + call_data_length.expr(),
                memory_address.offset(),
                memory_address.length(),
                0.expr(), // for CALLDATACOPY rlc_acc is 0
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(memory_address.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

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
            src_id,
            call_data_length,
            call_data_offset,
            copy_rwc_inc,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
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
        let memory_address = self
            .memory_address
            .assign(region, offset, memory_offset, length)?;
        self.data_offset.assign(
            region,
            offset,
            Some(
                data_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        let src_id = if call.is_root { tx.id } else { call.caller_id };
        self.src_id.assign(
            region,
            offset,
            Value::known(F::from(u64::try_from(src_id).unwrap())),
        )?;

        // Call data length and call data offset
        let (call_data_length, call_data_offset) = if call.is_root {
            (tx.call_data_length as u64, 0_u64)
        } else {
            (call.call_data_length, call.call_data_offset)
        };
        self.call_data_length
            .assign(region, offset, Value::known(F::from(call_data_length)))?;
        self.call_data_offset
            .assign(region, offset, Value::known(F::from(call_data_offset)))?;

        // rw_counter increase from copy lookup is `length` memory writes + a variable
        // number of memory reads.
        let copy_rwc_inc = length
            + if call.is_root {
                // no memory reads when reading from tx call data.
                0
            } else {
                // memory reads when reading from memory of caller is capped by call_data_length
                // - data_offset.
                min(
                    length.low_u64(),
                    call_data_length
                        .checked_sub(data_offset.low_u64())
                        .unwrap_or_default(),
                )
            };
        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                copy_rwc_inc
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

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
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{bytecode, ToWord, Word};
    use mock::test_ctx::{helpers::*, TestContext};

    fn test_ok_root(
        call_data_length: usize,
        memory_offset: usize,
        data_offset: usize,
        length: usize,
    ) {
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

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_calldata: 600,
                ..CircuitsParams::default()
            })
            .run();
    }

    fn test_ok_internal(
        call_data_offset: usize,
        call_data_length: usize,
        dst_offset: usize,
        offset: usize,
        length: usize,
    ) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = bytecode! {
            PUSH32(length)  // size
            PUSH32(offset)     // offset
            PUSH32(dst_offset) // dst_offset
            CALLDATACOPY
            STOP
        };

        // code A calls code B.
        let pushdata = rand_bytes(8);
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn calldatacopy_gadget_simple() {
        test_ok_root(0x40, 0x40, 0x00, 10);
        test_ok_internal(0x40, 0x40, 0xA0, 0x10, 10);
    }

    #[test]
    fn calldatacopy_gadget_large() {
        test_ok_root(0x204, 0x103, 0x102, 0x101);
        test_ok_internal(0x30, 0x204, 0x103, 0x102, 0x101);
    }

    #[test]
    fn calldatacopy_gadget_out_of_bound() {
        test_ok_root(0x40, 0x40, 0x20, 40);
        test_ok_internal(0x40, 0x20, 0xA0, 0x28, 10);
    }

    #[test]
    fn calldatacopy_gadget_zero_length() {
        test_ok_root(0x40, 0x40, 0x00, 0);
        test_ok_internal(0x40, 0x40, 0xA0, 0x10, 0);
    }
}
