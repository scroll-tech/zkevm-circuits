use crate::{
    circuit_input_builder::{BigModExp, PrecompileEvent},
    precompile::{ModExpAuxData, PrecompileAuxData},
};

use eth_types::Word;

pub(crate) fn opt_data(
    input_bytes: Option<Vec<u8>>,
    output_bytes: Option<Vec<u8>>,
) -> (Option<PrecompileEvent>, Option<PrecompileAuxData>) {
    let aux_data = ModExpAuxData::new(
        input_bytes.unwrap_or_default(),
        output_bytes.unwrap_or_default(),
    );
    if aux_data.valid {
        let event = BigModExp {
            base: Word::from_big_endian(&aux_data.inputs[0]),
            exponent: Word::from_big_endian(&aux_data.inputs[1]),
            modulus: Word::from_big_endian(&aux_data.inputs[2]),
            result: Word::from_big_endian(&aux_data.output),
        };
        (
            Some(PrecompileEvent::ModExp(event)),
            Some(PrecompileAuxData::Modexp(aux_data)),
        )
    } else {
        (None, Some(PrecompileAuxData::Modexp(aux_data)))
    }
}
