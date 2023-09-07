use anyhow;
use halo2_proofs::{
    halo2curves::bn256::{Fq, Fr, G1Affine},
    plonk::{Circuit, VerifyingKey},
    SerdeFormat,
};
use num_bigint::BigUint;
use snark_verifier::util::arithmetic::PrimeField;
use snark_verifier_sdk::Snark;
use std::{
    fs::File,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

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

pub fn serialize_fr_tensor(t: &[Vec<Vec<Fr>>]) -> Vec<Vec<Vec<Vec<u8>>>> {
    t.iter()
        .map(|m| serialize_fr_matrix(m.as_slice()))
        .collect()
}

pub fn deserialize_fr_tensor(l4_buf: Vec<Vec<Vec<Vec<u8>>>>) -> Vec<Vec<Vec<Fr>>> {
    l4_buf.into_iter().map(deserialize_fr_matrix).collect()
}

pub fn serialize_instance(instance: &[Vec<Fr>]) -> Vec<u8> {
    let instances_for_serde = serialize_fr_matrix(instance);

    serde_json::to_vec(&instances_for_serde).unwrap()
}

pub fn load_instance(buf: &[u8]) -> Vec<Vec<Vec<Fr>>> {
    let instances: Vec<Vec<Vec<Vec<u8>>>> = serde_json::from_reader(buf).unwrap();
    deserialize_fr_tensor(instances)
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

pub fn write_verify_circuit_vk(folder: &mut PathBuf, verify_circuit_vk: &[u8]) {
    folder.push("verify_circuit.vkey");
    let mut fd = std::fs::File::create(folder.as_path()).unwrap();
    folder.pop();
    fd.write_all(verify_circuit_vk).unwrap()
}

pub fn field_to_bn(f: &Fq) -> BigUint {
    BigUint::from_bytes_le(&f.to_bytes())
}

pub fn serialize_commitments(buf: &[Vec<G1Affine>]) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    let mut fd = Cursor::new(&mut result);
    let to_bytes_be = |x: &BigUint| {
        let mut buf = x.to_bytes_le();
        buf.resize(32, 0u8);
        buf.reverse();
        buf
    };
    for v in buf {
        for commitment in v {
            let x = field_to_bn(&commitment.x);
            let y = field_to_bn(&commitment.y);
            let be = to_bytes_be(&x)
                .into_iter()
                .chain(to_bytes_be(&y).into_iter())
                .collect::<Vec<_>>();
            fd.write_all(&be).unwrap()
        }
    }
    result
}

pub fn serialize_verify_circuit_final_pair(pair: &(G1Affine, G1Affine, Vec<Fr>)) -> Vec<u8> {
    let mut result = Vec::<u8>::new();
    let mut fd = Cursor::new(&mut result);
    fd.write_all(&pair.0.x.to_bytes()).unwrap();
    fd.write_all(&pair.0.y.to_bytes()).unwrap();
    fd.write_all(&pair.1.x.to_bytes()).unwrap();
    fd.write_all(&pair.1.y.to_bytes()).unwrap();
    pair.2.iter().for_each(|scalar| {
        fd.write_all(&scalar.to_bytes()).unwrap();
    });
    result
}

pub fn write_snark(file_path: &str, snark: &Snark) {
    let mut fd = std::fs::File::create(file_path).unwrap();
    serde_json::to_writer(&mut fd, snark).unwrap()
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

pub fn load_instances_flat(buf: &[u8]) -> Vec<Vec<Vec<Fr>>> {
    let mut ret = vec![];
    let cursor = &mut std::io::Cursor::new(buf);
    let mut scalar_bytes = <Fr as PrimeField>::Repr::default();

    while cursor.read_exact(scalar_bytes.as_mut()).is_ok() {
        ret.push(Fr::from_bytes(&scalar_bytes).unwrap());
    }

    vec![vec![ret]]
}
