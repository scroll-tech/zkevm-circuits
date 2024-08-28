use std::{
    env::current_dir,
    path::{Path, PathBuf},
};

use crate::{types::layer::ProofLayer, ProverError};

/// Test data directory.
pub const TEST_DATA_DIR: &str = "test_data";

/// The extension used for JSON files.
pub const JSON_EXT: &str = ".json";

/// The config parameters for non native field arithmetics are in a *.config file.
pub const NON_NATIVE_PARAMS_EXT: &str = ".config";

/// The config parameters for non native field arithmetics are by default in this directory.
pub const NON_NATIVE_PARAMS_DIR: &str = ".configs";

/// The KZG setup parameters are by default in this directory.
pub const KZG_PARAMS_DIR: &str = ".params";

/// The directory within cache to store proving tasks in JSON format.
pub const CACHE_PATH_TASKS: &str = "tasks";

/// The directory within cache to store SNARKs generated at intermediate proving layers.
pub const CACHE_PATH_SNARKS: &str = "snarks";

/// The directory within cache to store proof outputs.
pub const CACHE_PATH_PROOFS: &str = "proofs";

/// The directory within cache to store public input data.
pub const CACHE_PATH_PI: &str = "pi";

/// The directory within cache to store Verifier contract code.
pub const CACHE_PATH_EVM: &str = "evm";

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
    Ok(pwd()?.join(TEST_DATA_DIR).join(NON_NATIVE_PARAMS_DIR))
}

/// The default path to find KZG setup parameters.
///
/// <PWD>/.params
pub fn default_kzg_params_dir() -> Result<PathBuf, ProverError> {
    Ok(pwd()?.join(TEST_DATA_DIR).join(KZG_PARAMS_DIR))
}
