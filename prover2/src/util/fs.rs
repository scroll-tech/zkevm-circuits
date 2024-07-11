use std::{
    fs::{self, File},
    io::BufReader,
    path::Path,
};

use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG, SerdeFormat};
use serde::de::DeserializeOwned;

use crate::{
    ProverError,
    ProverError::{IoReadWrite, ReadWriteJson},
};

/// Wrapper functionality for opening a file.
pub fn open(path: &Path) -> Result<File, ProverError> {
    File::open(path).map_err(|source| IoReadWrite {
        source,
        path: path.into(),
    })
}

/// Wrapper functionality for reading bytes from a file.
pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>, ProverError> {
    let path = path.as_ref();
    fs::read(path).map_err(|source| IoReadWrite {
        source,
        path: path.into(),
    })
}

/// Wrapper functionality for reading a JSON file.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, ProverError> {
    let bytes = read(path)?;
    serde_json::from_slice(&bytes).map_err(|source| ReadWriteJson {
        source,
        path: path.into(),
    })
}

/// Read KZG setup parameters that are in a custom serde format.
pub fn read_kzg_params(path: &Path) -> Result<ParamsKZG<Bn256>, ProverError> {
    let f = open(path)?;
    Ok(ParamsKZG::<Bn256>::read_custom(
        &mut BufReader::new(f),
        SerdeFormat::RawBytesUnchecked,
    )?)
}
