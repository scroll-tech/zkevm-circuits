use eth_types::{
    sign_types::{recover_pk, SignData},
    Bytes, GethExecStep, ToBigEndian, ToWord, Word,
};
use halo2_proofs::halo2curves::secp256k1::Fq;

use crate::{
    circuit_input_builder::{Call, CircuitInputStateRef, ExecState, ExecStep},
    operation::CallContextField,
    precompile::{EcrecoverAuxData, PrecompileAuxData, PrecompileCalls},
    Error,
};

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

    // TODO: refactor and replace with `match` once we have more branches.
    if precompile == PrecompileCalls::Ecrecover {
        let input_bytes = input_bytes.map_or(vec![0u8; 128], |mut bytes| {
            bytes.resize(128, 0u8);
            bytes
        });
        let output_bytes = output_bytes.map_or(vec![0u8; 32], |mut bytes| {
            bytes.resize(32, 0u8);
            bytes
        });
        let aux_data = EcrecoverAuxData::new(input_bytes, output_bytes);

        // only if sig_v was a valid recovery ID, then we proceed to populate the ecrecover events.
        if let Some(sig_v) = aux_data.recovery_id() {
            if let Ok(recovered_pk) = recover_pk(
                sig_v,
                &aux_data.sig_r,
                &aux_data.sig_s,
                &aux_data.msg_hash.to_be_bytes(),
            ) {
                let sign_data = SignData {
                    signature: (
                        Fq::from_bytes(&aux_data.sig_r.to_be_bytes()).unwrap(),
                        Fq::from_bytes(&aux_data.sig_s.to_be_bytes()).unwrap(),
                        sig_v,
                    ),
                    pk: recovered_pk,
                    msg: Bytes::default(),
                    msg_hash: Fq::from_bytes(&aux_data.msg_hash.to_be_bytes()).unwrap(),
                };
                assert_eq!(aux_data.recovered_addr, sign_data.get_addr());
                state.push_ecrecover(sign_data);
            }
        }

        exec_step.aux_data = Some(PrecompileAuxData::Ecrecover(aux_data));
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
