use super::Prover;
use crate::io::serialize_vk;
use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk2, Circuit, ProvingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};
use rand::Rng;
use snark_verifier_sdk::{gen_snark_shplonk, CircuitExt, Snark};

impl Prover {
    pub fn gen_snark<C: CircuitExt<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        rng: &mut (impl Rng + Send),
        circuit: C,
    ) -> Result<Snark> {
        Self::assert_if_mock_prover(id, degree, &circuit);

        let (params, pk) = self.params_and_pk(id, degree, &circuit)?;

        Ok(gen_snark_shplonk(params, pk, circuit, rng, None::<String>))
    }

    pub fn params(&mut self, degree: u32) -> &ParamsKZG<Bn256> {
        if self.params_map.contains_key(&degree) {
            return &self.params_map[&degree];
        }

        log::warn!("Optimization: download params{degree} to params dir");

        log::info!("Before generate params of {degree}");
        let mut new_params = self
            .params_map
            .range(degree..)
            .next()
            .unwrap_or_else(|| panic!("Must have params of degree-{degree}"))
            .1
            .clone();
        new_params.downsize(degree);
        log::info!("After generate params of {degree}");

        self.params_map.insert(degree, new_params);
        &self.params_map[&degree]
    }

    pub fn pk(&self, id: &str) -> Option<&ProvingKey<G1Affine>> {
        self.pk_map.get(id)
    }

    pub fn params_and_pk<C: Circuit<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        circuit: &C,
    ) -> Result<(&ParamsKZG<Bn256>, &ProvingKey<G1Affine>)> {
        // Reuse pk.
        if self.pk_map.contains_key(id) {
            return Ok((&self.params_map[&degree], &self.pk_map[id]));
        }

        log::info!("Before generate pk of {}", &id);
        let pk = keygen_pk2(self.params(degree), circuit)?;
        log::info!("After generate pk of {}", &id);

        self.pk_map.insert(id.to_string(), pk);

        Ok((&self.params_map[&degree], &self.pk_map[id]))
    }

    pub fn raw_vk(&self, id: &str) -> Option<Vec<u8>> {
        self.pk_map.get(id).map(|pk| serialize_vk(pk.get_vk()))
    }
}
