use eth_types::{
    evm_types::GasCost,
    GethExecStep, ToWord, Word,
};

use crate::{
    circuit_input_builder::{
        Call, CircuitInputStateRef, ExecState, ExecStep, PrecompileEvent, SHA256,
    },
    operation::CallContextField,
    precompile::{PrecompileAuxData, PrecompileCalls, execute_precompiled},
    Error,
};
use super::error_oog_precompile::ErrorOOGPrecompile;

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

    let input_step = state.new_step(&geth_step)?;

    gen_ops(
        state,
        input_step,
        call,
        precompile,
        input_bytes,
        output_bytes,
        return_bytes,
    )
}

fn gen_ops(
    state: &mut CircuitInputStateRef,
    mut exec_step: ExecStep,
    call: Call,
    precompile: PrecompileCalls,
    input_bytes: &[u8],
    output_bytes: &[u8],
    return_bytes: &[u8],
) -> Result<ExecStep, Error> {
    assert_eq!(call.code_address(), Some(precompile.into()));
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

/// generate precompile step for *successful* precompile call
pub fn gen_ops_for_begin_tx(
    state: &mut CircuitInputStateRef,
    begin_step: &ExecStep,
    precompile: PrecompileCalls,
    input_bytes: &[u8],
) -> Result<ExecStep, Error> {

    let call = state.call()?.clone();
    let precompile_step = state.new_post_begin_tx_step(begin_step);

    let (result, precompile_call_gas_cost, has_oog_err) = execute_precompiled(
        &precompile.into(),
        input_bytes,
        precompile_step.gas_left.0,
    );

    // modexp's oog error is handled in ModExpGadget
    let mut step = if has_oog_err && precompile != PrecompileCalls::Modexp {
        log::debug!(
            "precompile call ({:?}) runs out of gas: callee_gas_left = {}",
            precompile,
            precompile_step.gas_left.0,
        );

        let oog_step = ErrorOOGPrecompile::gen_ops(
            state,
            precompile_step,
            call,
        )?;

        oog_step
    } else {
        gen_ops(
            state,
            precompile_step,
            call,
            precompile,
            input_bytes,
            &result,
            &[], // notice we suppose return is omitted
        )?
    };

    // adjust gas cost
    step.gas_cost = GasCost(precompile_call_gas_cost);    

    Ok(step)
}