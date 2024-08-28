use std::{env::var, str::FromStr};

use crate::{
    ProverError,
    ProverError::{EnvVar, Parse},
};

/// Wrapper to read variable from the environment.
pub fn read_env(key: &str) -> Result<String, ProverError> {
    var(key).map_err(|source| EnvVar {
        source,
        key: key.into(),
    })
}

/// Read variable from the environment and parse to a generic type.
pub fn read_env_as<T: FromStr>(key: &str) -> Result<T, ProverError>
where
    T::Err: std::error::Error,
{
    let src = read_env(key)?;

    src.parse::<T>().map_err(|e| Parse {
        src,
        err: e.to_string(),
    })
}

/// Read variable from the environment if set, otherwise return the provided default value.
pub fn read_env_or_default<T: FromStr>(key: &str, default: T) -> T
where
    T::Err: std::error::Error,
{
    read_env_as::<T>(key).unwrap_or(default)
}
