use std::collections::BTreeMap;

use crate::{common, config::INNER_DEGREE, io::deserialize_vk, zkevm::circuit::TargetCircuit};
use halo2_proofs::{halo2curves::bn256::Bn256, plonk::keygen_vk, poly::kzg::commitment::ParamsKZG};
use snark_verifier_sdk::Snark;

#[derive(Debug)]
pub struct Verifier<'params, C: TargetCircuit> {
    // Make it public for testing with inner functions (unnecessary for FFI).
    pub inner: common::Verifier<'params, C::Inner>,
}

impl<'params, C: TargetCircuit> From<common::Verifier<'params, C::Inner>> for Verifier<'params, C> {
    fn from(inner: common::Verifier<'params, C::Inner>) -> Self {
        Self { inner }
    }
}

impl<'params, C: TargetCircuit> Verifier<'params, C> {
    pub fn from_params_map(
        params_map: &'params BTreeMap<u32, ParamsKZG<Bn256>>,
        raw_vk: Option<&[u8]>,
    ) -> Self {
        let params = params_map.get(&*INNER_DEGREE).expect("should be loaded");

        let vk = raw_vk.map_or_else(
            || {
                let dummy_circuit = C::dummy_inner_circuit().expect("gen dummy circuit");
                keygen_vk(params, &dummy_circuit).unwrap()
            },
            deserialize_vk::<C::Inner>,
        );

        let verifier = common::Verifier::new(params, vk);
        verifier.into()
    }

    pub fn verify_inner_snark(&self, snark: Snark) -> bool {
        self.inner.verify_snark(snark)
    }
}
