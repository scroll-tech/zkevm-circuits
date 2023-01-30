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
            math_gadget::RangeCheckGadget,
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            CachedRegion, Cell, MemoryAddress,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::not;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ReturnDataCopyGadget<F> {
    same_context: SameContextGadget<F>,
    /// Holds the last_called_id for copy table.
    last_callee_id: Cell<F>,
    /// Holds the memory address for return data from where we read.
    return_data_offset: Cell<F>,
    /// Holds the size of the return data.
    return_data_size: Cell<F>,
    /// The data is copied to memory. To verify this
    /// copy operation we need the MemoryAddressGadget.
    dst_memory_addr: MemoryAddressGadget<F>,
    /// Holds the memory address for the offset in return data from where we
    /// read.
    data_offset: MemoryAddress<F>,
    /// Opcode RETURNDATACOPY has a dynamic gas cost:
    /// gas_code = static_gas * minimum_word_size + memory_expansion_cost
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    /// Opcode RETURNDATAECOPY needs to copy data into memory. We account for
    /// the copying costs using the memory copier gas gadget.
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
    /// RW inverse counter from the copy table at the start of related copy
    /// steps.
    copy_rwc_inc: Cell<F>,
    /// Out of bound check circuit.
    in_bound_check: RangeCheckGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for ReturnDataCopyGadget<F> {
    const NAME: &'static str = "RETURNDATACOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::RETURNDATACOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let dest_offset = cb.query_cell_phase2();
        let data_offset = cb.query_word_rlc();
        let size = cb.query_word_rlc();

        // 1. Pop dest_offset, offset, length from stack
        cb.stack_pop(dest_offset.expr());
        cb.stack_pop(data_offset.expr());
        cb.stack_pop(size.expr());

        // 2. Add lookup constraint in the call context for the returndatacopy field.
        let last_callee_id = cb.query_cell();
        let return_data_offset = cb.query_cell();
        let return_data_size = cb.query_cell();
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::LastCalleeId,
            last_callee_id.expr(),
        );
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::LastCalleeReturnDataOffset,
            return_data_offset.expr(),
        );
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::LastCalleeReturnDataLength,
            return_data_size.expr(),
        );

        // 3. contraints for copy: copy overflow check
        // i.e., offset + size <= return_data_size
        let in_bound_check = RangeCheckGadget::construct(
            cb,
            return_data_size.expr()
                - (from_bytes::expr(&data_offset.cells) + from_bytes::expr(&size.cells)),
        );

        // 4. memory copy
        // Construct memory address in the destination (memory) to which we copy memory.
        let dst_memory_addr = MemoryAddressGadget::construct(cb, dest_offset, size);

        // Calculate the next memory size and the gas cost for this memory
        // access. This also accounts for the dynamic gas required to copy bytes to
        // memory.
        let memory_expansion = MemoryExpansionGadget::construct(cb, [dst_memory_addr.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            dst_memory_addr.length(),
            memory_expansion.gas_cost(),
        );

        let copy_rwc_inc = cb.query_cell();
        cb.condition(dst_memory_addr.has_length(), |cb| {
            cb.copy_table_lookup(
                last_callee_id.expr(),
                CopyDataType::Memory.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                return_data_offset.expr() + from_bytes::expr(&data_offset.cells),
                return_data_offset.expr() + return_data_size.expr(),
                dst_memory_addr.offset(),
                dst_memory_addr.length(),
                0.expr(), // for RETURNDATACOPY rlc_acc is 0
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(dst_memory_addr.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(3.expr()),
            gas_left: Delta(
                -(OpcodeId::RETURNDATACOPY.constant_gas_cost().expr()
                    + memory_copier_gas.gas_cost()),
            ),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            last_callee_id,
            return_data_offset,
            return_data_size,
            dst_memory_addr,
            data_offset,
            memory_expansion,
            memory_copier_gas,
            copy_rwc_inc,
            in_bound_check,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [dest_offset, data_offset, size] =
            [0, 1, 2].map(|i| block.rws[step.rw_indices[i as usize]].stack_value());

        self.data_offset.assign(
            region,
            offset,
            Some(
                data_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        let [last_callee_id, return_data_offset, return_data_size] = [
            (3, CallContextFieldTag::LastCalleeId),
            (4, CallContextFieldTag::LastCalleeReturnDataOffset),
            (5, CallContextFieldTag::LastCalleeReturnDataLength),
        ]
        .map(|(i, tag)| {
            let rw = block.rws[step.rw_indices[i as usize]];
            assert_eq!(rw.field_tag(), Some(tag as u64));
            rw.call_context_value()
        });
        self.last_callee_id.assign(
            region,
            offset,
            Value::known(
                last_callee_id
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;
        self.return_data_offset.assign(
            region,
            offset,
            Value::known(
                return_data_offset
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;
        self.return_data_size.assign(
            region,
            offset,
            Value::known(
                return_data_size
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        // assign the destination memory offset.
        let memory_address = self
            .dst_memory_addr
            .assign(region, offset, dest_offset, size)?;

        // assign to gadgets handling memory expansion cost and copying cost.
        let (_, memory_expansion_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        self.memory_copier_gas
            .assign(region, offset, size.as_u64(), memory_expansion_cost)?;

        // rw_counter always increases by `size` reads and `size` writes
        let copy_rwc_inc = size + size;
        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                copy_rwc_inc
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        self.in_bound_check.assign(
            region,
            offset,
            (return_data_size - (data_offset + size))
                .to_scalar()
                .expect("unexpected U256 -> Scalar conversion failure"),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::run_test_circuits_with_params;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{bytecode, ToWord, Word};
    use mock::test_ctx::TestContext;

    fn test_ok_internal(
        return_data_offset: usize,
        return_data_size: usize,
        dest_offset: usize,
        offset: usize,
        size: usize,
    ) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        let pushdata = rand_bytes(32);
        let return_offset =
            std::cmp::max((return_data_offset + return_data_size) as i64 - 32, 0) as usize;
        let code_b = bytecode! {
            PUSH32(Word::from_big_endian(&pushdata))
            PUSH32(return_offset)
            MSTORE

            PUSH32(return_data_size)
            PUSH32(return_data_offset)
            RETURN
            STOP
        };

        // code A calls code B.
        let code_a = bytecode! {
            // call ADDR_B.
            PUSH32(return_data_size) // retLength
            PUSH32(return_data_offset) // retOffset
            PUSH1(0x00) // argsLength
            PUSH1(0x00) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            PUSH32(size) // size
            PUSH32(offset) // offset
            PUSH32(dest_offset) // dest_offset
            RETURNDATACOPY
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_a).code(code_a);
                accs[1].address(addr_b).code(code_b);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        assert_eq!(
            run_test_circuits_with_params(
                ctx,
                None,
                CircuitsParams {
                    max_rws: 2048,
                    ..Default::default()
                }
            ),
            Ok(())
        );
    }

    #[test]
    fn returndatacopy_gadget_do_nothing() {
        test_ok_internal(0x00, 0x02, 0x10, 0x00, 0x00);
    }

    #[test]
    fn returndatacopy_gadget_simple() {
        test_ok_internal(0x00, 0x02, 0x10, 0x00, 0x02);
    }

    #[test]
    fn returndatacopy_gadget_large() {
        test_ok_internal(0x00, 0x20, 0x20, 0x00, 0x20);
    }

    #[test]
    fn returndatacopy_gadget_large_partial() {
        test_ok_internal(0x00, 0x20, 0x20, 0x10, 0x10);
    }

    #[test]
    fn returndatacopy_gadget_zero_length() {
        test_ok_internal(0x00, 0x00, 0x20, 0x00, 0x00);
    }

    #[test]
    fn returndatacopy_gadget_long_length() {
        // rlc value matters only if length > 255, i.e., size.cells.len() > 1
        test_ok_internal(0x00, 0x200, 0x20, 0x00, 0x150);
    }

    #[test]
    fn returndatacopy_gadget_big_offset() {
        // rlc value matters only if length > 255, i.e., size.cells.len() > 1
        test_ok_internal(0x200, 0x200, 0x200, 0x00, 0x150);
    }

    // TODO: Add negative cases for out-of-bound and out-of-gas
    // #[test]
    // #[should_panic]
    // fn returndatacopy_gadget_out_of_bound() {
    //     test_ok_internal(0x00, 0x10, 0x20, 0x10, 0x10);
    // }

    // #[test]
    // #[should_panic]
    // fn returndatacopy_gadget_out_of_gas() {
    //     test_ok_internal(0x00, 0x10, 0x2000000, 0x00, 0x10);
    // }
}
