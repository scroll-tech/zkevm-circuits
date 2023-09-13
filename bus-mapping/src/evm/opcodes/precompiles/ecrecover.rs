use eth_types::{
    sign_types::{biguint_to_32bytes_le, recover_pk, SignData, SECP256K1_Q},
    Bytes, ToBigEndian, ToLittleEndian,
};
use halo2_proofs::halo2curves::{
    group::{ff::PrimeField, prime::PrimeCurveAffine},
    secp256k1::{Fq, Secp256k1Affine},
};
use num::{BigUint, Integer};

use crate::{
    circuit_input_builder::PrecompileEvent,
    precompile::{EcrecoverAuxData, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    let input_bytes = input_bytes.map_or(vec![0u8; 128], |mut bytes| {
        bytes.resize(128, 0u8);
        bytes
    });
    let output_bytes = output_bytes.map_or(vec![0u8; 32], |mut bytes| {
        bytes.resize(32, 0u8);
        bytes
    });
    let aux_data = EcrecoverAuxData::new(input_bytes, output_bytes);

    // We skip the validation through sig circuit if r or s was not in canonical form.
    let opt_sig_r: Option<Fq> = Fq::from_bytes(&aux_data.sig_r.to_le_bytes()).into();
    let opt_sig_s: Option<Fq> = Fq::from_bytes(&aux_data.sig_s.to_le_bytes()).into();
    if opt_sig_r.zip(opt_sig_s).is_none() {
        return (None, Some(PrecompileAuxData::Ecrecover(aux_data)));
    }

    if let Some(sig_v) = aux_data.recovery_id() {
        let recovered_pk = recover_pk(
            sig_v,
            &aux_data.sig_r,
            &aux_data.sig_s,
            &aux_data.msg_hash.to_be_bytes(),
        )
        .unwrap_or(Secp256k1Affine::identity());
        let sign_data = SignData {
            signature: (
                Fq::from_bytes(&aux_data.sig_r.to_le_bytes()).unwrap(),
                Fq::from_bytes(&aux_data.sig_s.to_le_bytes()).unwrap(),
                sig_v,
            ),
            pk: recovered_pk,
            msg: Bytes::default(),
            msg_hash: {
                let msg_hash = BigUint::from_bytes_be(&aux_data.msg_hash.to_be_bytes());
                let msg_hash = msg_hash.mod_floor(&*SECP256K1_Q);
                let msg_hash_le = biguint_to_32bytes_le(msg_hash);
                Fq::from_repr(msg_hash_le).unwrap()
            },
        };
        (
            Some(PrecompileEvent::Ecrecover(sign_data)),
            Some(PrecompileAuxData::Ecrecover(aux_data)),
        )
    } else {
        (None, Some(PrecompileAuxData::Ecrecover(aux_data)))
    }
}
