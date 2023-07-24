use eth_types::{GethExecStep, ToWord, Word};

use crate::{
    circuit_input_builder::{Call, CircuitInputStateRef, ExecState, ExecStep},
    operation::CallContextField,
    precompile::PrecompileCalls,
    Error,
};

mod ec_add;
mod ec_mul;
mod ecrecover;

use ec_add::handle as handle_ec_add;
use ec_mul::handle as handle_ec_mul;
use ecrecover::handle as handle_ecrecover;

type InOutRetData = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

pub fn gen_associated_ops(
    state: &mut CircuitInputStateRef,
    geth_step: GethExecStep,
    call: Call,
    precompile: PrecompileCalls,
    (input_bytes, output_bytes, _returned_bytes): InOutRetData,
) -> Result<ExecStep, Error> {
    assert_eq!(call.code_address(), Some(precompile.into()));
    let mut exec_step = state.new_step(&geth_step)?;
    exec_step.exec_state = ExecState::Precompile(precompile);

    common_call_ctx_reads(state, &mut exec_step, &call);

    match precompile {
        PrecompileCalls::Ecrecover => {
            handle_ecrecover(input_bytes, output_bytes, state, &mut exec_step)
        }
        PrecompileCalls::Bn128Add => {
            handle_ec_add(input_bytes, output_bytes, state, &mut exec_step)
        }
        PrecompileCalls::Bn128Mul => {
            handle_ec_mul(input_bytes, output_bytes, state, &mut exec_step)
        }
        _ => {}
    }

    Ok(exec_step)
}

fn common_call_ctx_reads(state: &mut CircuitInputStateRef, exec_step: &mut ExecStep, call: &Call) {
    for (field, value) in [
        (
            CallContextField::IsSuccess,
            Word::from(call.is_success as u64),
        ),
        (
            CallContextField::CalleeAddress,
            call.code_address().unwrap().to_word(),
        ),
        (CallContextField::CallerId, call.caller_id.into()),
        (
            CallContextField::CallDataOffset,
            call.call_data_offset.into(),
        ),
        (
            CallContextField::CallDataLength,
            call.call_data_length.into(),
        ),
        (
            CallContextField::ReturnDataOffset,
            call.return_data_offset.into(),
        ),
        (
            CallContextField::ReturnDataLength,
            call.return_data_length.into(),
        ),
    ] {
        state.call_context_read(exec_step, call.call_id, field, value);
    }
}
