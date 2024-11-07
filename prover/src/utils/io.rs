use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
};

use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{Circuit, VerifyingKey},
    SerdeFormat,
};
use serde::{
    de::{Deserialize, DeserializeOwned},
    Serialize,
};
use snark_verifier::util::arithmetic::PrimeField;

use crate::ProverError;

pub fn serialize_fr(f: &Fr) -> Vec<u8> {
    f.to_bytes().to_vec()
}

pub fn deserialize_fr(buf: Vec<u8>) -> Fr {
    Fr::from_repr(buf.try_into().unwrap()).unwrap()
}
pub fn serialize_fr_vec(v: &[Fr]) -> Vec<Vec<u8>> {
    v.iter().map(serialize_fr).collect()
}
pub fn deserialize_fr_vec(l2_buf: Vec<Vec<u8>>) -> Vec<Fr> {
    l2_buf.into_iter().map(deserialize_fr).collect()
}

pub fn serialize_fr_matrix(m: &[Vec<Fr>]) -> Vec<Vec<Vec<u8>>> {
    m.iter().map(|v| serialize_fr_vec(v.as_slice())).collect()
}

pub fn deserialize_fr_matrix(l3_buf: Vec<Vec<Vec<u8>>>) -> Vec<Vec<Fr>> {
    l3_buf.into_iter().map(deserialize_fr_vec).collect()
}

pub fn serialize_instance(instance: &[Vec<Fr>]) -> Vec<u8> {
    let instances_for_serde = serialize_fr_matrix(instance);

    serde_json::to_vec(&instances_for_serde).unwrap()
}

pub fn write_file(folder: &mut PathBuf, filename: &str, buf: &[u8]) {
    folder.push(filename);
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();

    fd.write_all(buf).unwrap();
}

pub fn serialize_vk(vk: &VerifyingKey<G1Affine>) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    vk.write(&mut result, SerdeFormat::Processed).unwrap();
    result
}

pub fn deserialize_vk<C: Circuit<Fr, Params = ()>>(raw_vk: &[u8]) -> VerifyingKey<G1Affine> {
    VerifyingKey::<G1Affine>::read::<_, C>(&mut Cursor::new(raw_vk), SerdeFormat::Processed, ())
        .unwrap_or_else(|_| panic!("failed to deserialize vk with len {}", raw_vk.len()))
}

/// Read bytes from a file.
pub fn read<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, ProverError> {
    let path = path.as_ref();
    fs::read(path).map_err(|source| ProverError::IoReadWrite {
        source,
        path: path.into(),
    })
}

/// Wrapper to read JSON file.
pub fn read_json<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> Result<T, ProverError> {
    let path = path.as_ref();
    let bytes = read(path)?;
    serde_json::from_slice(&bytes).map_err(|source| ProverError::JsonReadWrite {
        source,
        path: path.to_path_buf(),
    })
}

/// Wrapper to read JSON that might be deeply nested.
pub fn read_json_deep<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> Result<T, ProverError> {
    let fd = fs::File::open(path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(fd);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
    Ok(Deserialize::deserialize(deserializer)?)
}

/// Try to read bytes from a file.
///
/// Returns an optional value, which is `None` in case of an i/o error encountered.
pub fn try_read<P: AsRef<Path>>(path: P) -> Option<Vec<u8>> {
    self::read(path).ok()
}

/// Read bytes from a file.
///
/// Panics if any i/o error encountered.
pub fn force_read<P: AsRef<Path> + std::fmt::Debug>(path: P) -> Vec<u8> {
    self::read(path.as_ref()).unwrap_or_else(|_| panic!("no file found! path={path:?}"))
}

/// Wrapper functionality to write bytes to a file.
pub fn write<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<(), ProverError> {
    let path = path.as_ref();
    fs::write(path, data).map_err(|source| ProverError::IoReadWrite {
        source,
        path: path.into(),
    })
}

/// Serialize the provided type to JSON format and write to the given path.
pub fn write_json<P: AsRef<Path>, T: Serialize>(path: P, value: &T) -> Result<(), ProverError> {
    let mut writer = fs::File::create(path)?;
    Ok(serde_json::to_writer(&mut writer, value)?)
}
