use anyhow;
use halo2_proofs::{
    halo2curves::bn256::{Fr, G1Affine},
    plonk::{Circuit, VerifyingKey},
    SerdeFormat,
};
use snark_verifier::util::arithmetic::PrimeField;
use snark_verifier_sdk::Snark;
use std::{
    fs::File,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

pub fn from_json_file<'de, P: serde::Deserialize<'de>>(file_path: &str) -> anyhow::Result<P> {
    if !Path::new(&file_path).exists() {
        anyhow::bail!("File {file_path} doesn't exist");
    }

    let fd = File::open(file_path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(fd);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);

    Ok(serde::Deserialize::deserialize(deserializer)?)
}

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

pub fn read_all(filename: &str) -> Vec<u8> {
    let mut buf = vec![];
    let mut fd = std::fs::File::open(filename).unwrap();
    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn read_file(folder: &mut PathBuf, filename: &str) -> Vec<u8> {
    let mut buf = vec![];

    folder.push(filename);
    let mut fd = std::fs::File::open(folder.as_path()).unwrap();
    folder.pop();

    fd.read_to_end(&mut buf).unwrap();
    buf
}

pub fn try_to_read(dir: &str, filename: &str) -> Option<Vec<u8>> {
    let mut path = PathBuf::from(dir);
    path.push(filename);

    if path.exists() {
        Some(read_all(&path.to_string_lossy()))
    } else {
        None
    }
}

pub fn force_to_read(dir: &str, filename: &str) -> Vec<u8> {
    try_to_read(dir, filename).unwrap_or_else(|| panic!("File {filename} must exist in {dir}"))
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

pub fn deserialize_vk<C: Circuit<Fr>>(raw_vk: &[u8]) -> VerifyingKey<G1Affine> {
    VerifyingKey::<G1Affine>::read::<_, C>(&mut Cursor::new(raw_vk), SerdeFormat::Processed)
        .unwrap()
}

pub fn write_snark(file_path: &str, snark: &Snark) {
    log::debug!("write_snark to {file_path}");
    let mut fd = std::fs::File::create(file_path).unwrap();
    serde_json::to_writer(&mut fd, snark).unwrap();
    log::debug!("write_snark to {file_path} done");
}

pub fn load_snark(file_path: &str) -> anyhow::Result<Option<Snark>> {
    if !Path::new(file_path).exists() {
        return Ok(None);
    }

    let fd = File::open(file_path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(fd);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
    let snark = serde::Deserialize::deserialize(deserializer)?;
    Ok(Some(snark))
}

pub fn load_instances(buf: &[u8]) -> Vec<Vec<Vec<Fr>>> {
    let instances: Vec<Vec<Vec<Vec<u8>>>> = serde_json::from_reader(buf).unwrap();
    instances
        .into_iter()
        .map(|l1| {
            l1.into_iter()
                .map(|l2| {
                    l2.into_iter()
                        .map(|buf| Fr::from_bytes(&buf.try_into().unwrap()).unwrap())
                        .collect()
                })
                .collect()
        })
        .collect()
}

#[ignore]
#[test]
fn test_block_trace_convert() {
    let trace_v1: eth_types::l2_types::BlockTrace =
        from_json_file("src/testdata/trace_v1_5224657.json").expect("should load");
    let trace_v2: eth_types::l2_types::BlockTraceV2 = trace_v1.into();
    let mut fd = std::fs::File::create("src/testdata/trace_v2_5224657.json").unwrap();
    serde_json::to_writer_pretty(&mut fd, &trace_v2).unwrap();
    // then we can use this command to compare the traces:
    // vimdiff <(jq -S "del(.executionResults)|del(.txStorageTraces)" src/testdata/trace_v1_5224657.json) <(jq -S . src/testdata/trace_v2_5224657.json)
}
