use anyhow::Result;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk2, Circuit, ProvingKey},
    poly::kzg::commitment::ParamsKZG,
};
use rand::Rng;
use snark_verifier_sdk::{gen_snark_shplonk, CircuitExt, Snark};

use crate::utils::serialize_vk;

impl<'params> super::Prover<'params> {
    pub fn gen_snark<C: CircuitExt<Fr>>(
        &mut self,
        id: &str,
        degree: u32,
        rng: &mut (impl Rng + Send),
        circuit: C,
        desc: &str,
    ) -> Result<Snark> {
        Self::assert_if_mock_prover(id, degree, &circuit);

        let (params, pk) = self.params_and_pk(id, degree, &circuit)?;

        log::info!(
            "gen_snark id {} desc {} vk transcript_repr {:?}",
            id,
            desc,
            pk.get_vk().transcript_repr()
        );
        let snark = gen_snark_shplonk(params, pk, circuit, rng, None::<String>)?;
        Ok(snark)
    }

    pub fn params(&self, degree: u32) -> &ParamsKZG<Bn256> {
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

    pub fn clear_pks(&mut self) {
        self.pk_map.clear();
    }
}
