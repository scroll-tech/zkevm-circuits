use crate::{
    circuit_input_builder::{CircuitInputStateRef, EcMulOp, ExecStep, PrecompileEvent},
    precompile::{EcMulAuxData, PrecompileAuxData},
};

pub(crate) fn handle(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
) {
    let input_bytes = input_bytes.map_or(vec![0u8; 96], |mut bytes| {
        bytes.resize(96, 0u8);
        bytes
    });
    let output_bytes = output_bytes.map_or(vec![0u8; 64], |mut bytes| {
        bytes.resize(64, 0u8);
        bytes
    });

    let aux_data = EcMulAuxData::new(&input_bytes, &output_bytes);
    exec_step.aux_data = Some(PrecompileAuxData::EcMul(aux_data));

    let ec_mul_op = EcMulOp::new_from_bytes(&input_bytes, &output_bytes);
    state.push_precompile_event(PrecompileEvent::EcMul(ec_mul_op));
}
