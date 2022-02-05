use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

use crate::{
    evm_circuit::{
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CallDataSizeGadget<F> {
    same_context: SameContextGadget<F>,
    call_data_size: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallDataSizeGadget<F> {
    const NAME: &'static str = "CALLDATASIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATASIZE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Calldatasize can be looked up in the above tx_id's context.
        let call_data_size = cb.query_cell();

        // Add lookup constraint in the call context for the calldatasize field.
        cb.call_context_lookup(
            None,
            CallContextFieldTag::CallDataLength,
            call_data_size.expr(),
        );

        // The calldatasize should be pushed to the top of the stack.
        cb.stack_push(call_data_size.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(2.expr()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta((-1).expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            call_data_size,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        _block: &Block<F>,
        _tx: &Transaction<F>,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        self.call_data_size
            .assign(region, offset, Some(F::from(call.call_data_length as u64)))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use bus_mapping::evm::OpcodeId;
    use eth_types::{bytecode, ToLittleEndian, Word};
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr;

    use crate::evm_circuit::{
        step::ExecutionState,
        table::CallContextFieldTag,
        test::{rand_bytes, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
        witness::{Block, Bytecode, Call, ExecStep, Rw, Transaction},
    };

    fn test_ok(call_data_size: usize, is_root: bool) {
        let randomness = Fr::rand();
        let bytecode = bytecode! {
            #[start]
            CALLDATASIZE
            STOP
        };
        let bytecode = Bytecode::new(bytecode.to_vec());
        let call_id = 1;
        let call_data = rand_bytes(call_data_size);

        let rws = vec![
            Rw::CallContext {
                rw_counter: 9,
                is_write: false,
                call_id,
                field_tag: CallContextFieldTag::CallDataLength,
                value: Word::from(call_data_size),
            },
            Rw::Stack {
                rw_counter: 10,
                is_write: true,
                call_id,
                stack_pointer: 1023,
                value: Word::from(call_data_size),
            },
        ];

        let steps = vec![
            ExecStep {
                execution_state: ExecutionState::CALLDATASIZE,
                rw_indices: vec![0, 1],
                rw_counter: 9,
                program_counter: 0,
                stack_pointer: 1024,
                gas_left: OpcodeId::CALLDATASIZE.constant_gas_cost().as_u64(),
                gas_cost: OpcodeId::CALLDATASIZE.constant_gas_cost().as_u64(),
                opcode: Some(OpcodeId::CALLDATASIZE),
                ..Default::default()
            },
            ExecStep {
                execution_state: ExecutionState::STOP,
                rw_counter: 11,
                program_counter: 1,
                stack_pointer: 1023,
                gas_left: 0,
                opcode: Some(OpcodeId::STOP),
                ..Default::default()
            },
        ];

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                call_data,
                call_data_length: call_data_size,
                steps,
                calls: vec![Call {
                    id: call_id,
                    is_root,
                    is_create: false,
                    call_data_length: call_data_size,
                    opcode_source: RandomLinearCombination::random_linear_combine(
                        bytecode.hash.to_le_bytes(),
                        randomness,
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            rws,
            bytecodes: vec![bytecode],
            ..Default::default()
        };

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn calldatasize_gadget_root() {
        test_ok(32, true);
        test_ok(64, true);
        test_ok(96, true);
    }
}
