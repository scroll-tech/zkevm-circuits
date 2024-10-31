use eth_types::{
    sign_types::{biguint_to_32bytes_le, SignData, SECP256R1_Q},
    Bytes, ToBigEndian, ToLittleEndian,
};
use halo2_proofs::halo2curves::{
    group::{ff::PrimeField, prime::PrimeCurveAffine},
    secp256r1::{Fq, Fp, Secp256r1Affine},
};
use halo2_proofs::arithmetic::CurveAffine;
use num::{BigUint, Integer};

use crate::{
    circuit_input_builder::PrecompileEvent,
    precompile::{P256VerifyAuxData, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: &[u8],
    output_bytes: &[u8],
    return_bytes: &[u8],
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    let aux_data = P256VerifyAuxData::new(input_bytes, output_bytes, return_bytes);

    // We skip the validation through sig circuit if r or s was not in canonical form.
    let opt_sig_r: Option<Fq> = Fq::from_bytes(&aux_data.sig_r.to_le_bytes()).into();
    let opt_sig_s: Option<Fq> = Fq::from_bytes(&aux_data.sig_s.to_le_bytes()).into();
    let opt_x: Option<Fp> = Fp::from_bytes(&aux_data.pubkey_x.to_le_bytes()).into();
    let opt_y: Option<Fp> = Fp::from_bytes(&aux_data.pubkey_y.to_le_bytes()).into();

    if opt_sig_r.zip(opt_sig_s).is_none() {
        return (None, Some(PrecompileAuxData::P256Verify(aux_data)));
    }
    if opt_x.zip(opt_y).is_none() {
        return (None, Some(PrecompileAuxData::P256Verify(aux_data)));
    }

    let pk = Secp256r1Affine::from_xy(opt_x.unwrap(), opt_y.unwrap());
    let sign_data = SignData::<Fq, Secp256r1Affine> {
        signature: (
            Fq::from_bytes(&aux_data.sig_r.to_le_bytes()).unwrap(),
            Fq::from_bytes(&aux_data.sig_s.to_le_bytes()).unwrap(),
            // p256verify has no v field, set 0 
            0,
        ),
        pk: pk.unwrap(),
        msg: Bytes::default(),
        msg_hash: {
            let msg_hash = BigUint::from_bytes_be(&aux_data.msg_hash.to_be_bytes());
            let msg_hash = msg_hash.mod_floor(&*SECP256R1_Q);
            let msg_hash_le = biguint_to_32bytes_le(msg_hash);
            Fq::from_repr(msg_hash_le).unwrap()
        },
    };
    (
        Some(PrecompileEvent::P256Verify(sign_data)),
        Some(PrecompileAuxData::P256Verify(aux_data)),
    )
}
