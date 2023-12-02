use eth_types::{GethExecStep, ToWord, Word};

use crate::{
    circuit_input_builder::{
        Call, CircuitInputStateRef, ExecState, ExecStep, PrecompileEvent, SHA256,
    },
    operation::CallContextField,
    precompile::{PrecompileAuxData, PrecompileCalls},
    Error,
};

mod ec_add;
mod ec_mul;
mod ec_pairing;
mod ecrecover;
mod modexp;

use ec_add::opt_data as opt_data_ec_add;
use ec_mul::opt_data as opt_data_ec_mul;
use ec_pairing::opt_data as opt_data_ec_pairing;
use ecrecover::opt_data as opt_data_ecrecover;
use modexp::opt_data as opt_data_modexp;

pub fn gen_associated_ops(
    state: &mut CircuitInputStateRef,
    geth_step: GethExecStep,
    call: Call,
    precompile: PrecompileCalls,
    input_bytes: &[u8],
    output_bytes: &[u8],
    return_bytes: &[u8],
) -> Result<ExecStep, Error> {
    assert_eq!(call.code_address(), Some(precompile.into()));
    let mut exec_step = state.new_step(&geth_step)?;
    exec_step.exec_state = ExecState::Precompile(precompile);

    common_call_ctx_reads(state, &mut exec_step, &call)?;

    let (opt_event, aux_data) = match precompile {
        PrecompileCalls::Ecrecover => opt_data_ecrecover(input_bytes, output_bytes, return_bytes),
        PrecompileCalls::Bn128Add => opt_data_ec_add(input_bytes, output_bytes, return_bytes),
        PrecompileCalls::Bn128Mul => opt_data_ec_mul(input_bytes, output_bytes, return_bytes),
        PrecompileCalls::Bn128Pairing => {
            opt_data_ec_pairing(input_bytes, output_bytes, return_bytes)
        }
        PrecompileCalls::Modexp => opt_data_modexp(input_bytes, output_bytes, return_bytes),
        PrecompileCalls::Identity => (
            None,
            Some(PrecompileAuxData::Identity {
                input_bytes: input_bytes.to_vec(),
                output_bytes: output_bytes.to_vec(),
                return_bytes: return_bytes.to_vec(),
            }),
        ),
        PrecompileCalls::Sha256 => (
            if output_bytes.is_empty() {
                None
            } else {
                Some(PrecompileEvent::SHA256(SHA256 {
                    input: input_bytes.to_vec(),
                    digest: output_bytes
                        .try_into()
                        .expect("output bytes must be 32 bytes"),
                }))
            },
            Some(PrecompileAuxData::SHA256 {
                input_bytes: input_bytes.to_vec(),
                output_bytes: output_bytes.to_vec(),
                return_bytes: return_bytes.to_vec(),
            }),
        ),
        _ => {
            log::warn!("precompile {:?} unsupported in circuits", precompile);
            (
                None,
                Some(PrecompileAuxData::Base {
                    input_bytes: input_bytes.to_vec(),
                    output_bytes: output_bytes.to_vec(),
                    return_bytes: return_bytes.to_vec(),
                }),
            )
        }
    };
    log::trace!("precompile event {opt_event:?}, aux data {aux_data:?}");
    if let Some(event) = opt_event {
        state.push_precompile_event(event);
    }
    exec_step.aux_data = aux_data;

    Ok(exec_step)
}

fn common_call_ctx_reads(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    call: &Call,
) -> Result<(), Error> {
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
        state.call_context_read(exec_step, call.call_id, field, value)?;
    }
    Ok(())
}
