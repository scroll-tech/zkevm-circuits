use std::{
    env::current_dir,
    path::{Path, PathBuf},
};

use crate::{ProofLayer, ProverError};

mod fs;
pub use fs::{read_json, read_kzg_params};

mod env;
pub use env::read_env_or_default;

/// The config parameters for non native field arithmetics are in a *.config file.
pub const NON_NATIVE_PARAMS_EXT: &str = ".config";

/// The config parameters for non native field arithmetics are by default in this directory.
pub const NON_NATIVE_PARAMS_DIR: &str = ".config";

/// The KZG setup parameters are by default in this directory.
pub const KZG_PARAMS_DIR: &str = ".params";

/// The default directory used for cached data.
pub const CACHE_PATH: &str = ".cache";

/// The directory within cache to store proving tasks in JSON format.
pub const CACHE_PATH_TASKS: &str = "tasks";

/// The directory within cache to store proof outputs.
pub const CACHE_PATH_PROOFS: &str = "proofs";

/// The directory within cache to store public input data.
pub const CACHE_PATH_PI: &str = "pi";

/// The directory within cache to store Verifier contract code.
pub const CACHE_PATH_EVM: &str = "evm";

/// The environment variable to be set to configure custom degree for the super circuit (layer0).
pub const ENV_DEGREE_LAYER0: &str = "SUPER_CIRCUIT_DEGREE";

/// The default degree for the super circuit (layer0).
pub const DEFAULT_DEGREE_LAYER0: u32 = 20;

/// The path to the config parameters for a given proof layer.
///
/// <DIR>/{layer}.config
pub fn non_native_params_path(dir: &Path, layer: ProofLayer) -> PathBuf {
    dir.join(format!("{}{NON_NATIVE_PARAMS_EXT}", layer.to_string()))
}

/// The path to the KZG params by degree.
///
/// <DIR>/params{degree}
pub fn kzg_params_path(dir: &Path, degree: u32) -> PathBuf {
    dir.join(format!("params{degree}"))
}

/// Wrapper functionality for current working directory.
pub fn pwd() -> Result<PathBuf, ProverError> {
    Ok(current_dir()?)
}

/// The default path to find non-native field arithmetic config params.
///
/// <PWD>/.config
pub fn default_non_native_params_dir() -> Result<PathBuf, ProverError> {
    Ok(pwd()?.join(NON_NATIVE_PARAMS_DIR))
}

/// The default path to find KZG setup parameters.
///
/// <PWD>/.params
pub fn default_kzg_params_dir() -> Result<PathBuf, ProverError> {
    Ok(pwd()?.join(KZG_PARAMS_DIR))
}

/// The default path to the cache directory.
///
/// <PWD>/.cache
pub fn default_cache_dir() -> Result<PathBuf, ProverError> {
    Ok(pwd()?.join(CACHE_PATH))
}
