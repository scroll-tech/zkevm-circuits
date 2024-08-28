use std::{
    fs::{self, File},
    io::BufReader,
    path::Path,
};

use halo2_proofs::{halo2curves::bn256::Bn256, poly::kzg::commitment::ParamsKZG, SerdeFormat};
use serde::{de::DeserializeOwned, Serialize};

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

/// Wrapper functionality to write bytes to a file.
pub fn write(path: impl AsRef<Path>, data: &[u8]) -> Result<(), ProverError> {
    let path = path.as_ref();
    fs::write(path, data).map_err(|source| IoReadWrite {
        source,
        path: path.into(),
    })
}

/// Wrapper functionality to create a file and write to it.
pub fn create_and_write(path: &Path, data: &[u8]) -> Result<(), ProverError> {
    File::create(path)?;
    write(path, data)
}

/// Wrapper functionality for reading a JSON file.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, ProverError> {
    let bytes = read(path)?;
    serde_json::from_slice(&bytes).map_err(|source| ReadWriteJson {
        source,
        path: path.into(),
    })
}

pub fn write_json<T: Serialize>(path: &Path, data: &T) -> Result<(), ProverError> {
    let bytes = serde_json::to_vec(data)?;
    create_and_write(path, &bytes)
}

/// Read KZG setup parameters that are in a custom serde format.
pub fn read_kzg_params(path: &Path) -> Result<ParamsKZG<Bn256>, ProverError> {
    let f = open(path)?;
    Ok(ParamsKZG::<Bn256>::read_custom(
        &mut BufReader::new(f),
        SerdeFormat::RawBytesUnchecked,
    )?)
}
