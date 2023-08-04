use crate::{
    circuit_input_builder::{EcAddOp, PrecompileEvent},
    precompile::{EcAddAuxData, PrecompileAuxData},
};

pub(crate) fn opt_data(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    let input_bytes = input_bytes.map_or(vec![0u8; 128], |mut bytes| {
        bytes.resize(128, 0u8);
        bytes
    });
    let output_bytes = output_bytes.map_or(vec![0u8; 64], |mut bytes| {
        bytes.resize(64, 0u8);
        bytes
    });

    let aux_data = EcAddAuxData::new(&input_bytes, &output_bytes);
    let ec_add_op = EcAddOp::new_from_bytes(&input_bytes, &output_bytes);

    (
        Some(PrecompileEvent::EcAdd(ec_add_op)),
        Some(PrecompileAuxData::EcAdd(aux_data)),
    )
}
