use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        table::CallContextFieldTag,
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
    src_id: Cell<F>,
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
                let next_src_id = cb.query_cell();
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
                cb.require_equal("next_src_id = src_id", next_src_id.expr(), src_id.expr());
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
            src_id,
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
        let src_id = if call.is_root { tx.id } else { call.caller_id };
        self.src_id
            .assign(region, offset, Some(F::from(src_id as u64)))?;

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
    use crate::{evm_circuit::test::rand_bytes, test_util::run_test_circuits};
    use eth_types::{address, bytecode, Address, ToWord, Word};
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

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }

    fn test_ok_internal(
        call_data_offset: usize,
        call_data_length: usize,
        dst_offset: usize,
        offset: usize,
        copy_size: usize,
    ) {
        let addr_a = address!("0x000000000000000000000000000000000cafe00a");
        let addr_b = address!("0x000000000000000000000000000000000cafe00b");

        // code B gets called by code A, so the call is an internal call.
        let code_b = bytecode! {
            PUSH32(copy_size)  // size
            PUSH32(offset)     // offset
            PUSH32(dst_offset) // dst_offset
            CALLDATACOPY
            STOP
        };

        // code A calls code B.
        let pushdata = hex::decode("1234567890abcdef").unwrap();
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH1(call_data_length) // argsLength
            PUSH1(call_data_offset) // argsOffset
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
                    .address(Address::random())
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }

    #[test]
    fn calldatacopy_gadget_simple() {
        test_ok_root(0x40, 0x40, 0x00, 0x0A);
        test_ok_internal(0x40, 0x40, 0xA0, 0x10, 0x0A);
    }

    #[test]
    fn calldatacopy_gadget_multi_step() {
        test_ok_root(0x80, 0x40, 0x10, 0x5A);
        test_ok_internal(0x30, 0x70, 0x20, 0x10, 0x5A);
    }

    #[test]
    fn calldatacopy_gadget_out_of_bound() {
        test_ok_root(0x40, 0x40, 0x20, 0x28);
        test_ok_internal(0x40, 0x20, 0xA0, 0x28, 0x0A);
    }

    #[test]
    fn calldatacopy_gadget_zero_length() {
        test_ok_root(0x40, 0x40, 0x00, 0x00);
        test_ok_internal(0x40, 0x40, 0xA0, 0x10, 0x00);
    }
}
