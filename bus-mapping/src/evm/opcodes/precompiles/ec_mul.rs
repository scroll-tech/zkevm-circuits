use crate::{
    circuit_input_builder::{EcMulOp, PrecompileEvent},
    precompile::{EcMulAuxData, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: &[u8],
    output_bytes: &[u8],
    return_bytes: &[u8],
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    let aux_data = EcMulAuxData::new(input_bytes, output_bytes, return_bytes);
    let ec_mul_op = EcMulOp::new_from_bytes(input_bytes, output_bytes);

    (
        Some(PrecompileEvent::EcMul(ec_mul_op)),
        Some(PrecompileAuxData::EcMul(aux_data)),
    )
}
