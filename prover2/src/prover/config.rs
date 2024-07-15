use std::{collections::HashMap, fs::create_dir_all, marker::PhantomData, path::PathBuf};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_pk2, Circuit, ProvingKey},
    poly::kzg::commitment::ParamsKZG,
};
use tracing::{info, instrument, trace, warn};

use crate::{
    prover::params::NonNativeParams,
    types::{layer::ProofLayer, ProverType},
    util::{
        default_kzg_params_dir, default_non_native_params_dir, kzg_params_path,
        non_native_params_path as nn_params_path, read_env_or_default, read_json, read_kzg_params,
        CACHE_PATH_EVM, CACHE_PATH_PI, CACHE_PATH_PROOFS, CACHE_PATH_SNARKS, CACHE_PATH_TASKS,
        DEFAULT_DEGREE_LAYER0, ENV_DEGREE_LAYER0, JSON_EXT,
    },
    ProverError,
};

/// Configuration for a generic prover.
#[derive(Default, Debug)]
pub struct ProverConfig<Type> {
    /// Polynomial degree used by proof generation layer.
    pub degrees: HashMap<ProofLayer, u32>,
    /// KZG setup parameters by proof layer.
    pub kzg_params: HashMap<ProofLayer, ParamsKZG<Bn256>>,
    /// Config parameters for non-native field arithmetics by proof layer.
    pub nn_params: HashMap<ProofLayer, NonNativeParams>,
    /// Proving keys by proof layer.
    pub pks: HashMap<ProofLayer, ProvingKey<G1Affine>>,
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
    pub fn with_nn_params(mut self, layer: ProofLayer, params: NonNativeParams) -> Self {
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

/// Convenience type.
type KzgParamsAndPk<'a> = (&'a ParamsKZG<Bn256>, &'a ProvingKey<G1Affine>);

impl<Type: ProverType> ProverConfig<Type> {
    /// Setup the prover config by reading relevant config files from storage.
    #[instrument(name = "ProverConfig::setup", skip(self))]
    pub fn setup(mut self) -> Result<Self, ProverError> {
        info!(name = "setup prover config", prover_type = ?Type::NAME.to_string());

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
        trace!(name = "config directories", non_native_params = ?nn_params_dir, kzg_params = ?kzg_params_dir, caching = ?self.cache_dir);
        if self.cache_dir.is_none() {
            warn!(name = "setup prover without caching");
        }

        // Read and store non-native field arithmetic config params for each layer.
        for layer in proof_layers {
            // Layer0 (SuperCircuit) does not have non-native field arithmetics.
            if layer != ProofLayer::Layer0 {
                let params_path = nn_params_path(nn_params_dir.as_path(), layer);
                trace!(name = "read config for non-native field arithmetics", ?layer, path = ?params_path);
                let params = read_json::<NonNativeParams>(params_path.as_path())?;
                self.degrees.insert(layer, params.degree);
                self.nn_params.insert(layer, params);
            }

            if layer == ProofLayer::Layer0 {
                trace!(name = "read environment variable", ?layer, key = ?ENV_DEGREE_LAYER0, default = ?DEFAULT_DEGREE_LAYER0);
                let layer0_degree = read_env_or_default(ENV_DEGREE_LAYER0, DEFAULT_DEGREE_LAYER0);
                trace!(name = "configured degree", ?layer, degree = ?layer0_degree);
                self.degrees.insert(ProofLayer::Layer0, layer0_degree);
            }
        }

        // Read and store KZG setup params for each layer.
        for (&layer, &degree) in self.degrees.iter() {
            let params_path = kzg_params_path(kzg_params_dir.as_path(), degree);
            trace!(
                name = "read KZG setup parameters",
                ?layer,
                ?degree,
                path = ?params_path,
            );
            let params = read_kzg_params(params_path.as_path())?;
            self.kzg_params.insert(layer, params);
        }

        // Setup the cache directory's structure.
        if let Some(ref cache_dir) = self.cache_dir {
            create_dir_all(cache_dir.join(CACHE_PATH_TASKS))?;
            create_dir_all(cache_dir.join(CACHE_PATH_SNARKS))?;
            create_dir_all(cache_dir.join(CACHE_PATH_PROOFS))?;
            create_dir_all(cache_dir.join(CACHE_PATH_PI))?;
            create_dir_all(cache_dir.join(CACHE_PATH_EVM))?;
        }

        // Update directories in self.
        self.nn_params_dir.replace(nn_params_dir);
        self.kzg_params_dir.replace(kzg_params_dir);

        info!(name = "setup prover config OK", prover_type = ?Type::NAME.to_string());

        Ok(self)
    }

    /// Returns the proving key for the proof layer.
    pub fn gen_proving_key<C: Circuit<Fr>>(
        &mut self,
        layer: ProofLayer,
        circuit: &C,
    ) -> Result<KzgParamsAndPk, ProverError> {
        if self.pks.contains_key(&layer) {
            return Ok((&self.kzg_params[&layer], &self.pks[&layer]));
        }

        // Generate proving key for the circuit and insert into the cached map.
        let kzg_params = self.kzg_params(layer)?;
        let pk = keygen_pk2(kzg_params, circuit)
            .map_err(|e| ProverError::Keygen(Type::NAME.to_string(), layer, e))?;
        self.pks.insert(layer, pk);

        Ok((&self.kzg_params[&layer], &self.pks[&layer]))
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

    /// Returns the path to cache the generated SNARK.
    pub fn path_snark(&self, id: &str, layer: ProofLayer) -> Option<PathBuf> {
        self.cache_dir
            .as_ref()
            .map(|dir| dir.join(CACHE_PATH_SNARKS).join(format!("{layer:?}-{id}")))
    }
}

impl<Type: ProverType> ProverConfig<Type> {
    /// Returns the KZG setup parameters for the proof layer.
    pub fn kzg_params(&self, layer: ProofLayer) -> Result<&ParamsKZG<Bn256>, ProverError> {
        self.kzg_params
            .get(&layer)
            .ok_or(ProverError::MissingKzgParams(Type::NAME.into(), layer))
    }

    /// Returns the proving key for the proof layer.
    pub fn proving_key(&self, layer: ProofLayer) -> Result<&ProvingKey<G1Affine>, ProverError> {
        self.pks.get(&layer).ok_or(ProverError::MissingProvingKey(
            Type::NAME.to_string(),
            layer,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::env::current_dir;

    use aggregator::MAX_AGG_SNARKS;

    use crate::{
        prover::ProverConfig,
        types::{ProverTypeBatch, ProverTypeChunk},
    };

    #[test]
    fn setup_prover() -> anyhow::Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .pretty()
            .init();

        let test_dir = current_dir()?.join("test_data");

        let _chunk_prover_config = ProverConfig::<ProverTypeChunk>::default()
            .with_nn_params_dir(test_dir.join(".configs"))
            .with_kzg_params_dir(test_dir.join(".params"))
            .with_cache_dir(test_dir.join(".cache"))
            .setup()?;

        let _batch_prover_config = ProverConfig::<ProverTypeBatch<MAX_AGG_SNARKS>>::default()
            .with_nn_params_dir(test_dir.join(".configs"))
            .with_kzg_params_dir(test_dir.join(".params"))
            .setup()?;

        Ok(())
    }
}
