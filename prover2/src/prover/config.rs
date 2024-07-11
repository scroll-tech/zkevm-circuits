use std::{
    collections::BTreeMap, env::current_dir, fs::File, io::BufReader, marker::PhantomData,
    path::PathBuf,
};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::ProvingKey,
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};

use crate::{
    types::ProverType,
    util::{kzg_params_path, non_native_params_path},
    Params, ProofLayer, ProverError,
};

/// Configuration for a generic prover.
#[derive(Default)]
pub struct ProverConfig<Type> {
    /// KZG setup parameters by proof layer.
    pub kzg_params: BTreeMap<ProofLayer, ParamsKZG<Bn256>>,
    /// Config parameters for non-native field arithmetics by proof layer.
    pub non_native_params: BTreeMap<ProofLayer, Params>,
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
    pub fn with_params(mut self, layer: ProofLayer, params: Params) -> Self {
        self.non_native_params.insert(layer, params);
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
    pub fn load(mut self) -> Result<Self, ProverError> {
        // The proof layers that this prover needs to generate proofs for.
        let proof_layers = Type::layers();

        // Use the configured directories or fallback to current working directory.
        let non_native_params_dir = self.non_native_params_dir.clone().unwrap_or(current_dir()?);
        let kzg_params_dir = self.kzg_params_dir.clone().unwrap_or(current_dir()?);

        // Read and store non-native field arithmetic config params for each layer.
        for layer in proof_layers {
            let params_file = File::open(non_native_params_path(
                non_native_params_dir.as_path(),
                layer,
            ))?;
            let params = serde_json::from_reader(params_file)?;
            self.non_native_params.insert(layer, params);
        }

        // Read and store KZG setup params for each layer.
        for (&layer, non_native_params) in self.non_native_params.iter() {
            let params_file = File::open(kzg_params_path(
                kzg_params_dir.as_path(),
                non_native_params.degree,
            ))?;
            let params = ParamsKZG::<Bn256>::read_custom(
                &mut BufReader::new(params_file),
                SerdeFormat::RawBytesUnchecked,
            )?;
            self.kzg_params.insert(layer, params);
        }

        Ok(self)
    }
}
