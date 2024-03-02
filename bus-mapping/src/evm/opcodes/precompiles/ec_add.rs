use crate::{
    circuit_input_builder::{EcAddOp, PrecompileEvent},
    precompile::{EcAddAuxData, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: &[u8],
    output_bytes: &[u8],
    return_bytes: &[u8],
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    let aux_data = EcAddAuxData::new(input_bytes, output_bytes, return_bytes);
    let ec_add_op = EcAddOp::new_from_bytes(input_bytes, output_bytes);

    (
        Some(PrecompileEvent::EcAdd(ec_add_op)),
        Some(PrecompileAuxData::EcAdd(aux_data)),
    )
}
