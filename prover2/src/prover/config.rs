use std::{
    collections::BTreeMap,
    fs::{create_dir, create_dir_all},
    marker::PhantomData,
    path::PathBuf,
};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};

use crate::{
    types::ProverType,
    util::{
        default_cache_dir, default_kzg_params_dir, default_non_native_params_dir, kzg_params_path,
        non_native_params_path as nn_params_path, read_json, read_kzg_params, CACHE_PATH_EVM,
        CACHE_PATH_PI, CACHE_PATH_PROOFS, CACHE_PATH_TASKS,
    },
    Params, ProofLayer, ProverError,
};

/// Configuration for a generic prover.
#[derive(Default)]
pub struct ProverConfig<Type> {
    /// KZG setup parameters by proof layer.
    pub kzg_params: BTreeMap<ProofLayer, ParamsKZG<Bn256>>,
    /// Config parameters for non-native field arithmetics by proof layer.
    pub nn_params: BTreeMap<ProofLayer, Params>,
    /// Proving keys by proof layer.
    pub pks: BTreeMap<ProofLayer, ProvingKey<G1Affine>>,
    /// Optional directory to locate KZG setup parameters.
    pub kzg_params_dir: Option<PathBuf>,
    /// Optional directory to locate non-native field arithmetic config params.
    pub non_native_params_dir: Option<PathBuf>,
    /// Optional directory to cache proofs.
    pub cache_dir: Option<PathBuf>,

    _prover_type: PhantomData<Type>,
}

impl<Type> ProverConfig<Type> {
    /// Returns prover config after inserting the non-native field arithmetic config for the given
    /// proof layer.
    pub fn with_nn_params(mut self, layer: ProofLayer, params: Params) -> Self {
        self.nn_params.insert(layer, params);
        self
    }

    /// Returns prover config after inserting KZG setup params for the given proof layer.
    pub fn with_kzg_params(mut self, layer: ProofLayer, params: ParamsKZG<Bn256>) -> Self {
        self.kzg_params.insert(layer, params);
        self
    }

    /// Returns prover config after inserting the proving key for the given proof layer.
    pub fn with_pk(mut self, layer: ProofLayer, pk: ProvingKey<G1Affine>) -> Self {
        self.pks.insert(layer, pk);
        self
    }

    /// Returns prover config with a directory to load KZG params from.
    pub fn with_kzg_params_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.kzg_params_dir = Some(dir.into());
        self
    }

    /// Returns prover config with a directory to load non-native field arithmetic config params
    /// from.
    pub fn with_non_native_params_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.non_native_params_dir = Some(dir.into());
        self
    }

    /// Returns prover config with a cache directory configured.
    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(dir.into());
        self
    }
}

impl<Type: ProverType> ProverConfig<Type> {
    /// Setup the prover config by reading relevant config files from storage.
    pub fn setup(mut self) -> Result<Self, ProverError> {
        // The proof layers that this prover needs to generate proofs for.
        let proof_layers = Type::layers();

        // Use the configured directories or fallback to current working directory.
        let nn_params_dir = self
            .non_native_params_dir
            .clone()
            .unwrap_or(default_non_native_params_dir()?);
        let kzg_params_dir = self
            .kzg_params_dir
            .clone()
            .unwrap_or(default_kzg_params_dir()?);
        let cache_dir = self.cache_dir.clone().unwrap_or(default_cache_dir()?);

        // Read and store non-native field arithmetic config params for each layer.
        for layer in proof_layers {
            let params_path = nn_params_path(nn_params_dir.as_path(), layer);
            let params = read_json(params_path.as_path())?;
            self.nn_params.insert(layer, params);
        }

        // Read and store KZG setup params for each layer.
        for (&layer, nn_params) in self.nn_params.iter() {
            let params_path = kzg_params_path(kzg_params_dir.as_path(), nn_params.degree);
            let params = read_kzg_params(params_path.as_path())?;
            self.kzg_params.insert(layer, params);
        }

        // Setup the cache directory's structure.
        create_dir_all(cache_dir.as_path())?;
        create_dir(cache_dir.join(CACHE_PATH_TASKS))?;
        create_dir(cache_dir.join(CACHE_PATH_PROOFS))?;
        create_dir(cache_dir.join(CACHE_PATH_PI))?;
        create_dir(cache_dir.join(CACHE_PATH_EVM))?;

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use std::env::current_dir;

    use crate::{
        types::{ProverTypeBatch, ProverTypeBundle, ProverTypeChunk},
        ProverConfig,
    };

    #[test]
    fn setup_prover() -> anyhow::Result<()> {
        let test_dir = current_dir()?.join("test_data");

        let _chunk_prover_config = ProverConfig::<ProverTypeChunk>::default()
            .with_non_native_params_dir(test_dir.join(".config"))
            .with_kzg_params_dir(test_dir.join(".params"))
            .with_cache_dir(test_dir.join(".cache"))
            .setup()?;
        let _batch_prover_config = ProverConfig::<ProverTypeBatch>::default()
            .with_non_native_params_dir(test_dir.join(".config"))
            .with_kzg_params_dir(test_dir.join(".params"))
            .with_cache_dir(test_dir.join(".cache"))
            .setup()?;
        let _bundle_prover_config = ProverConfig::<ProverTypeBundle>::default()
            .with_non_native_params_dir(test_dir.join(".config"))
            .with_kzg_params_dir(test_dir.join(".params"))
            .with_cache_dir(test_dir.join(".cache"))
            .setup()?;

        Ok(())
    }
}
