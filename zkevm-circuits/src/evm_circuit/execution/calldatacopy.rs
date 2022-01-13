use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{MAX_GAS_SIZE_IN_BYTES, NUM_ADDRESS_BYTES_USED},
        step::ExecutionState,
        table::{CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            memory_gadget::{MemoryCopierGasGadget, MemoryExpansionGadget},
            Cell, MemoryAddress, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::eth_types::ToLittleEndian;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct CallDataCopyGadget<F> {
    same_context: SameContextGadget<F>,
    memory_offset: MemoryAddress<F>,
    data_offset: MemoryAddress<F>,
    length: RandomLinearCombination<F, 4>,
    tx_id: Cell<F>,
    call_data_length: Cell<F>,
    call_data_offset: Cell<F>, // Only used in the internal call
    memory_expansion: MemoryExpansionGadget<F, MAX_GAS_SIZE_IN_BYTES>,
    memory_copier_gas: MemoryCopierGasGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallDataCopyGadget<F> {
    const NAME: &'static str = "CALLDATACOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATACOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let bytes_memory_offset =
            MemoryAddress::new(cb.query_bytes(), cb.randomness());
        let bytes_data_offset =
            MemoryAddress::new(cb.query_bytes(), cb.randomness());
        let bytes_length =
            RandomLinearCombination::new(cb.query_bytes(), cb.randomness());
        let memory_offset = from_bytes::expr(&bytes_memory_offset.cells);
        let data_offset = from_bytes::expr(&bytes_data_offset.cells);
        let length = from_bytes::expr(&bytes_length.cells);

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
                None,
                CallContextFieldTag::CallDataLength,
                call_data_length.expr(),
            );
            cb.call_context_lookup(
                None,
                CallContextFieldTag::CallerAddress,
                call_data_offset.expr(),
            )
        });

        // The src address of the call data to be copied
        let src_addr = data_offset + call_data_offset.expr();
        // The address boundary of call data buffer
        let src_addr_end = call_data_length.expr() + call_data_offset.expr();

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_size.expr(),
            memory_offset.clone() + length.clone(),
        );
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            length.clone(),
            memory_expansion.gas_cost(),
        );

        // Pop memory_offset, data_offset, length from stack
        cb.stack_pop(bytes_memory_offset.expr());
        cb.stack_pop(bytes_data_offset.expr());
        cb.stack_pop(bytes_length.expr());

        // Constraint on the next step CopyToMemory
        let next_src_addr = cb.query_cell_next_step();
        let next_dst_addr = cb.query_cell_next_step();
        let next_bytes_left = cb.query_cell_next_step();
        let next_src_addr_end = cb.query_cell_next_step();
        let next_from_tx = cb.query_cell_next_step();
        let next_tx_id = cb.query_cell_next_step();
        cb.require_next_state(ExecutionState::CopyToMemory);
        cb.add_constraint(
            "next_src_addr = data_offset",
            next_src_addr.expr() - src_addr,
        );
        cb.add_constraint(
            "next_dst_addr = memory_offset",
            next_dst_addr.expr() - memory_offset,
        );
        cb.add_constraint(
            "next_bytes_left = length",
            next_bytes_left.expr() - length,
        );
        cb.add_constraint(
            "next_src_addr_end = data_offset + calldata_length",
            next_src_addr_end.expr() - src_addr_end,
        );
        cb.add_constraint(
            "next_from_tx = is_root",
            next_from_tx.expr() - cb.curr.state.is_root.expr(),
        );
        cb.add_constraint(
            "next_tx_id = tx_id",
            next_tx_id.expr() - tx_id.expr(),
        );

        // State transition
        let step_state_transition = StepStateTransition {
            // 1 tx id lookup + 3 stack pop + option(calldatalength lookup)
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(3.expr()),
            memory_size: To(memory_expansion.next_memory_size()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            Some(memory_copier_gas.gas_cost()),
        );

        Self {
            same_context,
            memory_offset: bytes_memory_offset,
            data_offset: bytes_data_offset,
            length: bytes_length,
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
        tx: &Transaction<F>,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [memory_offset, data_offset, length] =
            [step.rw_indices[1], step.rw_indices[2], step.rw_indices[3]]
                .map(|idx| block.rws[idx].stack_value());
        println!("mem_offset = {}", memory_offset);
        println!("data_offset = {}", data_offset);
        println!("length = {}", length);
        self.memory_offset.assign(
            region,
            offset,
            Some(
                memory_offset.to_le_bytes()[..NUM_ADDRESS_BYTES_USED]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.data_offset.assign(
            region,
            offset,
            Some(
                data_offset.to_le_bytes()[..NUM_ADDRESS_BYTES_USED]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.length.assign(
            region,
            offset,
            Some(length.to_le_bytes()[..4].try_into().unwrap()),
        )?;
        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;

        let (call_data_length, call_data_offset) = if call.is_root {
            (tx.call_data_length, 0)
        } else {
            (call.call_data_length, call.call_data_offset)
        };
        self.call_data_length.assign(
            region,
            offset,
            Some(F::from(call_data_length as u64)),
        )?;
        self.call_data_offset.assign(
            region,
            offset,
            Some(F::from(call_data_offset as u64)),
        )?;

        // Memory expansion
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_size,
            memory_offset.as_u64() + length.as_u64(),
        )?;

        let gas_cost = self.memory_copier_gas.assign(
            region,
            offset,
            length.as_u64(),
            memory_expansion_gas_cost as u64,
        )?;
        println!("copy gas cost = {}", gas_cost);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::memory_copy::test::make_memory_copy_steps,
        step::ExecutionState,
        table::CallContextFieldTag,
        test::{
            calc_memory_copier_gas_cost, calc_memory_expension_gas_cost,
            rand_bytes, run_test_circuit_incomplete_fixed_table,
        },
        util::RandomLinearCombination,
        witness::{Block, Bytecode, Call, ExecStep, Rw, Transaction},
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::{GasCost, OpcodeId},
    };
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;

    fn test_ok_root(
        calldata_length: usize,
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
        let mut steps = Vec::new();
        let calldata = rand_bytes(calldata_length);
        let gas_cost = GasCost::FASTEST.as_u64()
            + calc_memory_expension_gas_cost(
                0,
                memory_offset.as_u64() + length.as_u64(),
            )
            + calc_memory_copier_gas_cost(length.as_u64());
        println!("total gas cost = {}", gas_cost);

        let mut rws = vec![
            Rw::CallContext {
                rw_counter: 1,
                is_write: false,
                call_id: call_id,
                field_tag: CallContextFieldTag::TxId,
                value: Word::one(),
            },
            Rw::Stack {
                rw_counter: 2,
                is_write: false,
                call_id: call_id,
                stack_pointer: 1021,
                value: memory_offset,
            },
            Rw::Stack {
                rw_counter: 3,
                is_write: false,
                call_id: call_id,
                stack_pointer: 1022,
                value: data_offset,
            },
            Rw::Stack {
                rw_counter: 4,
                is_write: false,
                call_id: call_id,
                stack_pointer: 1023,
                value: length,
            },
        ];
        let mut rw_counter = rws.len() + 1;
        println!("{:?}", rws[0]);
        println!("{:?}", rws[1]);
        println!("{:?}", rws[2]);
        println!("{:?}", rws[3]);
        println!("rw_counter = {}", rw_counter);

        steps.push(ExecStep {
            rw_indices: vec![0, 1, 2, 3],
            execution_state: ExecutionState::CALLDATACOPY,
            rw_counter: 1,
            program_counter: 99,
            stack_pointer: 1021,
            gas_left: gas_cost,
            gas_cost,
            memory_size: 0,
            opcode: Some(OpcodeId::CALLDATACOPY),
            ..Default::default()
        });
        let memory_size = (memory_offset.as_u64() + length.as_u64() + 31) / 32;
        println!("calc mem size = {}", memory_size);

        make_memory_copy_steps(
            call_id,
            &calldata,
            0,
            data_offset.as_u64(),
            memory_offset.as_u64(),
            length.as_usize(),
            true,
            100,
            1024,
            memory_size,
            &mut rw_counter,
            &mut rws,
            &mut steps,
        );
        println!("rw_counter = {}", rw_counter);

        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter: 100,
            stack_pointer: 1024,
            opcode: Some(OpcodeId::STOP),
            memory_size,
            ..Default::default()
        });

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                call_data: calldata,
                call_data_length: calldata_length,
                calls: vec![Call {
                    id: call_id,
                    is_root: true,
                    is_create: false,
                    opcode_source:
                        RandomLinearCombination::random_linear_combine(
                            bytecode.hash.to_le_bytes(),
                            randomness,
                        ),
                    ..Default::default()
                }],
                steps,
                ..Default::default()
            }],
            rws,
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn calldatacopy_gadget_simple() {
        test_ok_root(64, Word::from(0x40), Word::from(0), Word::from(64));
    }
}
