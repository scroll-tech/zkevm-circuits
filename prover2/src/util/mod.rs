use git_version::git_version;
use once_cell::sync::Lazy;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

mod dir;
pub use dir::{
    default_kzg_params_dir, default_non_native_params_dir, kzg_params_path, non_native_params_path,
    CACHE_PATH_EVM, CACHE_PATH_PI, CACHE_PATH_PROOFS, CACHE_PATH_SNARKS, CACHE_PATH_TASKS,
    JSON_EXT,
};

mod env;
pub use env::read_env_or_default;

mod io;
pub use io::{read_json, read_kzg_params, write, write_json};

mod serde;
pub use serde::{deserialize_be, serialize_be};

/// The environment variable to be set to configure custom degree for the super circuit (layer0).
pub const ENV_DEGREE_LAYER0: &str = "SUPER_CIRCUIT_DEGREE";

/// The default degree for the super circuit (layer0).
pub const DEFAULT_DEGREE_LAYER0: u32 = 20;

/// Git version (git describe) of the source code.
pub static GIT_VERSION: Lazy<&str> = Lazy::new(|| {
    git_version!(args = ["--abbrev=8", "--always"])
        .split('-')
        .last()
        .expect("git describe should not fail")
});

/// Seed and return a random number generator.
pub fn gen_rng() -> impl Rng + Send {
    let seed = [0u8; 16];
    XorShiftRng::from_seed(seed)
}
