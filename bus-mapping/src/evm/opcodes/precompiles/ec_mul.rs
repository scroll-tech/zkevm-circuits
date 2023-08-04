use crate::{
    circuit_input_builder::{EcMulOp, PrecompileEvent},
    precompile::{EcMulAuxData, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    let input_bytes = input_bytes.map_or(vec![0u8; 96], |mut bytes| {
        bytes.resize(96, 0u8);
        bytes
    });
    let output_bytes = output_bytes.map_or(vec![0u8; 64], |mut bytes| {
        bytes.resize(64, 0u8);
        bytes
    });

    let aux_data = EcMulAuxData::new(&input_bytes, &output_bytes);
    let ec_mul_op = EcMulOp::new_from_bytes(&input_bytes, &output_bytes);

    (
        Some(PrecompileEvent::EcMul(ec_mul_op)),
        Some(PrecompileAuxData::EcMul(aux_data)),
    )
}
