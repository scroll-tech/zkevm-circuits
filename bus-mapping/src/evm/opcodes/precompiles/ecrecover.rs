use eth_types::{
    sign_types::{recover_pk, SignData},
    Bytes, ToBigEndian,
};
use halo2_proofs::halo2curves::secp256k1::Fq;

use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep, PrecompileEvent},
    precompile::{EcrecoverAuxData, PrecompileAuxData},
};

pub(crate) fn handle(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
) {
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
            state.push_precompile_event(PrecompileEvent::Ecrecover(sign_data));
        } else {
            log::warn!(
                "could not recover pubkey. ecrecover aux_data={:?}",
                aux_data
            );
        }
    } else {
        log::warn!(
            "invalid recoveryId for ecrecover. sig_v={:?}",
            aux_data.sig_v
        );
    }

    exec_step.aux_data = Some(PrecompileAuxData::Ecrecover(aux_data));
}
