use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_CALLDATASIZE,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Region, plonk::Error};
use std::convert::TryInto;

#[derive(Clone, Debug)]
pub(crate) struct CallDataSizeGadget<F> {
    same_context: SameContextGadget<F>,
    call_data_size: RandomLinearCombination<F, N_BYTES_CALLDATASIZE>,
}

impl<F: Field> ExecutionGadget<F> for CallDataSizeGadget<F> {
    const NAME: &'static str = "CALLDATASIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATASIZE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Add lookup constraint in the call context for the calldatasize field.
        let call_data_size = cb.query_rlc();
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::CallDataLength,
            from_bytes::expr(&call_data_size.cells),
        );

        // The calldatasize should be pushed to the top of the stack.
        cb.stack_push(call_data_size.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::CALLDATASIZE.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            call_data_size,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let call_data_size = block.rws[step.rw_indices[1]].stack_value();

        self.call_data_size.assign(
            region,
            offset,
            Some(
                call_data_size.to_le_bytes()[..N_BYTES_CALLDATASIZE]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use bus_mapping::evm::OpcodeId;
    use eth_types::{bytecode, Word};
    use halo2_proofs::arithmetic::BaseExt;
    use pairing::bn256::Fr;

    use crate::evm_circuit::{
        step::ExecutionState,
        table::{CallContextFieldTag, RwTableTag},
        test::{rand_bytes, run_test_circuit_incomplete_fixed_table},
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };

    fn test_ok(call_data_size: usize, is_root: bool) {
        let randomness = Fr::rand();
        let bytecode = bytecode! {
            CALLDATASIZE
            STOP
        };
        let bytecode = Bytecode::new(bytecode.to_vec());
        let call_id = 1;
        let call_data = rand_bytes(call_data_size);

        let mut rw_map = HashMap::new();
        rw_map.insert(
            RwTableTag::CallContext,
            vec![Rw::CallContext {
                rw_counter: 9,
                is_write: false,
                call_id,
                field_tag: CallContextFieldTag::CallDataLength,
                value: Word::from(call_data_size),
            }],
        );
        rw_map.insert(
            RwTableTag::Stack,
            vec![Rw::Stack {
                rw_counter: 10,
                is_write: true,
                call_id,
                stack_pointer: 1023,
                value: Word::from(call_data_size),
            }],
        );

        let steps = vec![
            ExecStep {
                execution_state: ExecutionState::CALLDATASIZE,
                rw_indices: vec![(RwTableTag::CallContext, 0), (RwTableTag::Stack, 0)],
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
                    call_data_length: call_data_size as u64,
                    code_source: CodeSource::Account(bytecode.hash),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            rws: RwMap(rw_map),
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
        test_ok(128, true);
        test_ok(256, true);
        test_ok(512, true);
        test_ok(1024, true);
    }
}
