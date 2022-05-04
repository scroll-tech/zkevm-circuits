use super::Opcode;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::{CallContextField, CallContextOp, RW},
    Error,
};
use eth_types::{GethExecStep, ToWord};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::STOP`](crate::evm::OpcodeId::STOP)
/// `OpcodeId`. This is responsible of generating all of the associated
/// operations and place them inside the trace's
/// [`OperationContainer`](crate::operation::OperationContainer). In the case of
/// STOP, it simply does not add anything.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Stop;

impl Opcode for Stop {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let call = state.call()?.clone();

        state.push_op(
            &mut exec_step,
            RW::READ,
            CallContextOp {
                call_id: call.call_id,
                field: CallContextField::IsSuccess,
                value: 1.into(),
            },
        );

        if call.is_root {
            state.push_op(
                &mut exec_step,
                RW::READ,
                CallContextOp {
                    call_id: call.call_id,
                    field: CallContextField::IsPersistent,
                    value: 1.into(),
                },
            );
        } else {
            let caller = state.caller()?.clone();
            state.push_op(
                &mut exec_step,
                RW::READ,
                CallContextOp {
                    call_id: call.call_id,
                    field: CallContextField::CallerId,
                    value: caller.call_id.into(),
                },
            );

            let geth_step_next = &geth_steps[1];
            let caller_gas_left = geth_step_next.gas.0 - geth_step.gas.0;
            for (field, value) in [
                (CallContextField::IsRoot, (caller.is_root as u64).into()),
                (
                    CallContextField::IsCreate,
                    (caller.is_create() as u64).into(),
                ),
                (CallContextField::CodeSource, caller.code_hash.to_word()),
                (CallContextField::ProgramCounter, geth_step_next.pc.0.into()),
                (
                    CallContextField::StackPointer,
                    geth_step_next.stack.stack_pointer().0.into(),
                ),
                (CallContextField::GasLeft, caller_gas_left.into()),
                (
                    CallContextField::MemorySize,
                    geth_step_next.memory.word_size().into(),
                ),
                (
                    CallContextField::ReversibleWriteCounter,
                    state.caller_ctx()?.reversible_write_counter.into(),
                ),
            ] {
                state.push_op(
                    &mut exec_step,
                    RW::READ,
                    CallContextOp {
                        call_id: caller.call_id,
                        field,
                        value,
                    },
                );
            }

            for (field, value) in [
                (CallContextField::LastCalleeId, call.call_id.into()),
                (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                (CallContextField::LastCalleeReturnDataLength, 0.into()),
            ] {
                state.push_op(
                    &mut exec_step,
                    RW::WRITE,
                    CallContextOp {
                        call_id: caller.call_id,
                        field,
                        value,
                    },
                );
            }
        }

        state.handle_return()?;

        Ok(vec![exec_step])
    }
}
