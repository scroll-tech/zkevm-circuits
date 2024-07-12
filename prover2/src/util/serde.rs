use halo2_proofs::halo2curves::bn256::Fr;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::ScalarField;

/// Serialize a field element [`Fr`] to big-endian bytes.
pub fn serialize_be(field: &Fr) -> Vec<u8> {
    field.to_bytes().into_iter().rev().collect()
}

/// Deserialize a field element [`Fr`] from big-endian bytes.
pub fn deserialize_be(be_bytes: &[u8]) -> Fr {
    let mut le_bytes = [0u8; 32];
    le_bytes.copy_from_slice(be_bytes);
    le_bytes.reverse();
    Fr::from_bytes_le(&le_bytes)
}
