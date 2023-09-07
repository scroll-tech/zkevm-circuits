use crate::{
    common, config::INNER_DEGREE, io::deserialize_vk, utils::load_params,
    zkevm::circuit::TargetCircuit,
};
use halo2_proofs::plonk::keygen_vk;
use snark_verifier_sdk::Snark;

#[derive(Debug)]
pub struct Verifier<C: TargetCircuit> {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Verifier<C::Inner>,
}

impl<C: TargetCircuit> From<common::Verifier<C::Inner>> for Verifier<C> {
    fn from(inner: common::Verifier<C::Inner>) -> Self {
        Self { inner }
    }
}

impl<C: TargetCircuit> Verifier<C> {
    pub fn from_params_dir(params_dir: &str, raw_vk: Option<&[u8]>) -> Self {
        let params = load_params(params_dir, *INNER_DEGREE, None).unwrap();

        let vk = raw_vk.map_or_else(
            || {
                let dummy_circuit = C::dummy_inner_circuit();
                keygen_vk(&params, &dummy_circuit).unwrap()
            },
            deserialize_vk::<C::Inner>,
        );

        common::Verifier::new(params, vk).into()
    }

    pub fn verify_inner_snark(&self, snark: Snark) -> bool {
        self.inner.verify_snark(snark)
    }
}
