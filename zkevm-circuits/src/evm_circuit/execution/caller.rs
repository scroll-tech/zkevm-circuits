use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
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
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct CallerGadget<F> {
    same_context: SameContextGadget<F>,
    caller: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallerGadget<F> {
    const NAME: &'static str = "CALLER";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLER;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let caller = cb.query_rlc();
        cb.call_context_lookup(
            None,
            CallContextFieldTag::CallerAddress,
            from_bytes::expr(&caller.cells),
        );
        cb.stack_push(caller.expr());

        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition, None);

        Self {
            same_context,
            caller,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        _: &Block<F>,
        _: &Transaction<F>,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // H160's are big endian, so we need to reverse the bytes to get the little
        // endian encoding the EVM uses.
        let mut le_bytes = call.caller_address.0;
        le_bytes.reverse();

        self.caller.assign(region, offset, Some(le_bytes))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        step::ExecutionState,
        table::CallContextFieldTag,
        test::run_test_circuit_incomplete_fixed_table,
        util::RandomLinearCombination,
        witness::{Block, Bytecode, Call, ExecStep, Rw, Transaction},
    };
    use bus_mapping::evm::OpcodeId;
    use eth_types::{address, bytecode, ToLittleEndian, ToWord};
    use halo2::arithmetic::BaseExt;
    use pairing::bn256::Fr;

    #[test]
    fn caller_gadget_test() {
        let bytecode = Bytecode::new(
            bytecode! {
                #[start]
                CALLER
                STOP
            }
            .to_vec(),
        );

        let caller = address!("0x11332200000000000000000023000400000000fe");

        let tx_id = 1;
        let call_id = 1;

        let caller_gas_cost = OpcodeId::CALLER.constant_gas_cost().as_u64();

        let randomness = Fr::rand();
        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: tx_id,
                caller_address: caller,
                steps: vec![
                    ExecStep {
                        execution_state: ExecutionState::CALLER,
                        rw_indices: vec![0, 1],
                        rw_counter: 1,
                        program_counter: 0,
                        stack_pointer: 1024,
                        gas_left: caller_gas_cost,
                        gas_cost: caller_gas_cost,
                        opcode: Some(OpcodeId::CALLER),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 3,
                        program_counter: 1,
                        stack_pointer: 1023,
                        opcode: Some(OpcodeId::STOP),
                        ..Default::default()
                    },
                ],
                calls: vec![Call {
                    id: 1,
                    is_root: true,
                    is_create: false,
                    caller_address: caller,
                    opcode_source: RandomLinearCombination::random_linear_combine(
                        bytecode.hash.to_le_bytes(),
                        randomness,
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            rws: vec![
                Rw::CallContext {
                    call_id,
                    rw_counter: 1,
                    is_write: false,
                    field_tag: CallContextFieldTag::CallerAddress,
                    value: caller.to_word(),
                },
                Rw::Stack {
                    call_id,
                    rw_counter: 2,
                    is_write: true,
                    stack_pointer: 1023,
                    value: caller.to_word(),
                },
            ],
            bytecodes: vec![bytecode],
            ..Default::default()
        };

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }
}
