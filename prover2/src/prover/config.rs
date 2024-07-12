use std::{collections::BTreeMap, fs::create_dir_all, marker::PhantomData, path::PathBuf};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
};
use tracing::{debug, info, instrument, trace};

use crate::{
    types::ProverType,
    util::{
        default_cache_dir, default_kzg_params_dir, default_non_native_params_dir, kzg_params_path,
        non_native_params_path as nn_params_path, read_env_or_default, read_json, read_kzg_params,
        CACHE_PATH_EVM, CACHE_PATH_PI, CACHE_PATH_PROOFS, CACHE_PATH_SNARKS, CACHE_PATH_TASKS,
        DEFAULT_DEGREE_LAYER0, ENV_DEGREE_LAYER0, JSON_EXT,
    },
    Params, ProofLayer, ProverError,
};

/// Configuration for a generic prover.
#[derive(Default, Debug)]
pub struct ProverConfig<Type> {
    /// Polynomial degree used by proof generation layer.
    pub degrees: BTreeMap<ProofLayer, u32>,
    /// KZG setup parameters by proof layer.
    pub kzg_params: BTreeMap<ProofLayer, ParamsKZG<Bn256>>,
    /// Config parameters for non-native field arithmetics by proof layer.
    pub nn_params: BTreeMap<ProofLayer, Params>,
    /// Proving keys by proof layer.
    pub pks: BTreeMap<ProofLayer, ProvingKey<G1Affine>>,
    /// Optional directory to locate KZG setup parameters.
    pub kzg_params_dir: Option<PathBuf>,
    /// Optional directory to locate non-native field arithmetic config params.
    pub nn_params_dir: Option<PathBuf>,
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
    pub fn with_nn_params_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.nn_params_dir = Some(dir.into());
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
    #[instrument(name = "ProverConfig::setup", skip(self))]
    pub fn setup(mut self) -> Result<Self, ProverError> {
        info!("setting up ProverConfig");

        // The proof layers that this prover needs to generate proofs for.
        let proof_layers = Type::layers();

        // Use the configured directories or fallback to current working directory.
        let nn_params_dir = self
            .nn_params_dir
            .clone()
            .unwrap_or(default_non_native_params_dir()?);
        let kzg_params_dir = self
            .kzg_params_dir
            .clone()
            .unwrap_or(default_kzg_params_dir()?);
        let cache_dir = self.cache_dir.clone().unwrap_or(default_cache_dir()?);

        // Read and store non-native field arithmetic config params for each layer.
        trace!("loading non-native field arithmetic params");
        for layer in proof_layers {
            // Layer0 (SuperCircuit) does not have non-native field arithmetics.
            if layer != ProofLayer::Layer0 {
                let params_path = nn_params_path(nn_params_dir.as_path(), layer);
                debug!("reading config params for {:?}: {:?}", layer, params_path);
                let params = read_json::<Params>(params_path.as_path())?;
                self.degrees.insert(layer, params.degree);
                self.nn_params.insert(layer, params);
            }

            if layer == ProofLayer::Layer0 {
                let layer0_degree = read_env_or_default(ENV_DEGREE_LAYER0, DEFAULT_DEGREE_LAYER0);
                self.degrees.insert(ProofLayer::Layer0, layer0_degree);
            }
        }

        // Read and store KZG setup params for each layer.
        trace!("loading KZG setup params");
        for (&layer, &degree) in self.degrees.iter() {
            let params_path = kzg_params_path(kzg_params_dir.as_path(), degree);
            debug!(
                "reading kzg params for {:?} (degree = {:?}): {:?}",
                layer, degree, params_path
            );
            let params = read_kzg_params(params_path.as_path())?;
            self.kzg_params.insert(layer, params);
        }

        // Setup the cache directory's structure.
        trace!("setting up cache");
        create_dir_all(cache_dir.join(CACHE_PATH_TASKS))?;
        create_dir_all(cache_dir.join(CACHE_PATH_SNARKS))?;
        create_dir_all(cache_dir.join(CACHE_PATH_PROOFS))?;
        create_dir_all(cache_dir.join(CACHE_PATH_PI))?;
        create_dir_all(cache_dir.join(CACHE_PATH_EVM))?;

        // Update directories in self.
        self.nn_params_dir.replace(nn_params_dir);
        self.kzg_params_dir.replace(kzg_params_dir);
        self.cache_dir.replace(cache_dir);

        info!("setup ProverConfig");

        Ok(self)
    }
}

impl<Type> ProverConfig<Type> {
    /// Returns the path to a proof with the given identifier if caching is enabled in the prover's
    /// config.
    pub fn path_proof(&self, id: &str) -> Option<PathBuf> {
        self.cache_dir
            .as_ref()
            .map(|dir| dir.join(CACHE_PATH_PROOFS).join(id).join(JSON_EXT))
    }
}

#[cfg(test)]
mod tests {
    use std::env::current_dir;

    use aggregator::MAX_AGG_SNARKS;

    use crate::{
        types::{ProverTypeBatch, ProverTypeChunk},
        ProverConfig,
    };

    #[test]
    fn setup_prover() -> anyhow::Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .pretty()
            .init();

        let test_dir = current_dir()?.join("test_data");

        let _chunk_prover_config = ProverConfig::<ProverTypeChunk>::default()
            .with_nn_params_dir(test_dir.join(".config"))
            .with_kzg_params_dir(test_dir.join(".params"))
            .with_cache_dir(test_dir.join(".cache"))
            .setup()?;

        let _batch_prover_config = ProverConfig::<ProverTypeBatch<MAX_AGG_SNARKS>>::default()
            .with_nn_params_dir(test_dir.join(".config"))
            .with_kzg_params_dir(test_dir.join(".params"))
            .with_cache_dir(test_dir.join(".cache"))
            .setup()?;

        Ok(())
    }
}
