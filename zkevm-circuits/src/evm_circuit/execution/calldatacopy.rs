use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition::Delta,
            },
            math_gadget::{AddWordsGadget, PairSelectGadget},
            select,
        },
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

const MAX_COPY_BYTES: usize = 32;

#[derive(Clone, Debug)]
pub(crate) struct CallDataCopyGadget<F> {
    //opcode: Cell<F>,
    mem_offset: MemoryAddress<F>,
    data_offset: MemoryAddress<F>,
    length: RandomLinearCombination<F, 5>,
    call_data_length: Cell<F>,
    finished: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, MAX_GAS_SIZE_IN_BYTES>,
    data: [Cell<F>; MAX_COPY_BYTES],
    selectors: [Cell<F>; MAX_COPY_BYTES],
    bound_dist: [Cell<F>; MAX_COPY_BYTES],
    first_bound_is_zero: IsZeroGadget<F>,
}

#[derive(Clone, Debug)]
pub(crate) struct CallDataCopyExtGadget<F> {
    //opcode: Cell<F>,
    mem_offset: Cell<F>,
    data_offset: Cell<F>,
    length: Cell<F>,
    tx_id: Cell<F>,
    call_data_length: Cell<F>,
    finished: Cell<F>,
    data: [Cell<F>; MAX_COPY_BYTES],
    selectors: [Cell<F>; MAX_COPY_BYTES],
    bound_dist: [Cell<F>; MAX_COPY_BYTES],
    first_bound_is_zero: IsZeroGadget<F>,
}


impl<F: FieldExt> ExecutionGadget<F> for CallDataCopyGadget<F> {
    const NAME: &'static str = "CALLDATACOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATACOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        //let opcode = cb.query_cell();
        //cb.opcode_lookup(opcode.expr(), 1.expr());

        //let finished = cb.query_cell();

        // Verify memory
        let bytes_mem_offset = MemoryAddress::new(cb.query_bytes(), cb.randomness());
        let bytes_data_offset = MemoryAddress::new(cb.query_bytes(), cb.randomness());
        let bytes_length = RandomLinearCombination::new(cb.query_bytes(), cb.randomness());

        mem_offset = from_bytes::expr(bytes_mem_offset.cells);
        data_offset = from_bytes::expr(bytes_data_offset.cells);
        length = from_bytes::expr(bytes_length.cells);

        let tx_id = cb.query_cell();
        cb.call_context_lookup(0.expr(), None, CallContextFieldTag::TxId, tx_id.expr());

        let call_data_length = cb.query_cell();
        cb.condition(cb.curr.is_root.expr(), |cb| {
            cb.tx_lookup(tx_id, TxContextFieldTag::CallDataLength, None, call_data_length)
        });
        cb.condition(1 - cb.curr.is_root.expr(), |cb| {
            cb.call_context_lookup(
                0.expr(), None, CallContextFieldTag::CallDataLength,
                call_data_length)
        });

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_size.expr(),
            data_offset + length,
        );
        let (next_memory_size, memory_gas_cost) = memory_expansion.expr();



        // Swap a and c if opcode is SUB
        let is_sub = PairSelectGadget::construct(
            cb,
            opcode.expr(),
            OpcodeId::SUB.expr(),
            OpcodeId::ADD.expr(),
        );

        // ADD: Pop a and b from the stack, push c on the stack
        // SUB: Pop c and b from the stack, push a on the stack
        cb.stack_pop(select::expr(is_sub.expr().0, c.expr(), a.expr()));
        cb.stack_pop(b.expr());
        cb.stack_push(select::expr(is_sub.expr().0, a.expr(), c.expr()));

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            add_words,
            is_sub,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();
        let indices = if opcode == OpcodeId::SUB {
            [step.rw_indices[2], step.rw_indices[1], step.rw_indices[0]]
        } else {
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
        };
        let [a, b, c] = indices.map(|idx| block.rws[idx].stack_value());
        self.add_words.assign(region, offset, [a, b], c)?;
        self.is_sub.assign(
            region,
            offset,
            F::from(opcode.as_u64()),
            F::from(OpcodeId::SUB.as_u64()),
            F::from(OpcodeId::ADD.as_u64()),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{
            Block, Bytecode, Call, ExecStep, Rw, Transaction,
        },
        step::ExecutionState,
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr as Fp;

    fn test_ok(opcode: OpcodeId, a: Word, b: Word, c: Word) {
        let randomness = Fp::rand();
        let bytecode = Bytecode::new(
            [
                vec![OpcodeId::PUSH32.as_u8()],
                b.to_be_bytes().to_vec(),
                vec![OpcodeId::PUSH32.as_u8()],
                a.to_be_bytes().to_vec(),
                vec![opcode.as_u8(), OpcodeId::STOP.as_u8()],
            ]
            .concat(),
        );
        let block = Block {
            randomness,
            txs: vec![Transaction {
                calls: vec![Call {
                    id: 1,
                    is_root: false,
                    is_create: false,
                    opcode_source:
                        RandomLinearCombination::random_linear_combine(
                            bytecode.hash.to_le_bytes(),
                            randomness,
                        ),
                }],
                steps: vec![
                    ExecStep {
                        rw_indices: vec![0, 1, 2],
                        execution_state: ExecutionState::ADD,
                        rw_counter: 1,
                        program_counter: 66,
                        stack_pointer: 1022,
                        gas_left: 3,
                        gas_cost: 3,
                        opcode: Some(opcode),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 4,
                        program_counter: 67,
                        stack_pointer: 1023,
                        gas_left: 0,
                        opcode: Some(OpcodeId::STOP),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            rws: vec![
                Rw::Stack {
                    rw_counter: 1,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1022,
                    value: a,
                },
                Rw::Stack {
                    rw_counter: 2,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: b,
                },
                Rw::Stack {
                    rw_counter: 3,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: c,
                },
            ],
            bytecodes: vec![bytecode],
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn add_gadget_simple() {
        test_ok(
            OpcodeId::ADD,
            0x030201.into(),
            0x060504.into(),
            0x090705.into(),
        );
        test_ok(
            OpcodeId::SUB,
            0x090705.into(),
            0x060504.into(),
            0x030201.into(),
        );
    }

    #[test]
    fn add_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(OpcodeId::ADD, a, b, a.overflowing_add(b).0);
        test_ok(OpcodeId::SUB, a, b, a.overflowing_sub(b).0);
    }
}
