use std::path::{Path, PathBuf};

use crate::ProofLayer;

/// The config parameters for non native field arithmetics is a *.config file.
const NON_NATIVE_PARAMS_EXT: &str = ".config";

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
