use crate::{barycentric::interpolate, ChunkHash};
use eth_types::U256;
use ethers_core::utils::keccak256;
use halo2_proofs::halo2curves::bls12_381::Scalar;

pub const BLOB_WIDTH: usize = 4096;
pub const BYTES_PER_BLOB_ELEMENT: usize = 32;
pub const LOG_BLOG_WIDTH: usize = 12;

#[derive(Clone, Debug, Default)]
pub struct Blob(Vec<Vec<u8>>);

impl Blob {
    pub fn new(chunk_hashes: &[ChunkHash]) -> Self {
        Self(
            chunk_hashes
                .iter()
                .filter(|chunk_hash| !chunk_hash.is_padding)
                .map(|chunk_hash| chunk_hash.tx_bytes.clone())
                .collect(),
        )
    }

    pub fn coefficients(&self) -> [U256; BLOB_WIDTH] {
        let mut le_bytes = [[0; BYTES_PER_BLOB_ELEMENT]; BLOB_WIDTH];
        for (i, byte) in self.bytes().enumerate() {
            le_bytes[i / 31][i % 31] = byte;
        }
        le_bytes.map(|bytes| U256::from_little_endian(&bytes))
    }

    pub fn challenge_point(&self) -> U256 {
        let chunk_tx_bytes_hashes = self.0.iter().flat_map(keccak256);

        let input: Vec<_> = keccak256(self.metadata_bytes().collect::<Vec<_>>())
            .into_iter()
            .chain(chunk_tx_bytes_hashes)
            .collect();

        keccak256(input).into()
    }

    fn metadata_bytes(&self) -> impl Iterator<Item = u8> + '_ {
        let n_chunks = self.0.len();
        let chunk_lengths = self.0.iter().map(Vec::len);
        std::iter::empty()
            .chain(u16::try_from(n_chunks).unwrap().to_be_bytes())
            .chain(chunk_lengths.flat_map(|x| u32::try_from(x).unwrap().to_be_bytes()))
    }

    fn bytes(&self) -> impl Iterator<Item = u8> + '_ {
        self.metadata_bytes()
            .chain(self.0.iter().flat_map(|x| x.iter().copied()))
    }
}

#[derive(Clone, Debug)]
pub struct BlobAssignments {
    pub challenge_digest: U256,
    pub evaluation: U256,
    pub coefficients: [U256; BLOB_WIDTH],
}

impl From<&Blob> for BlobAssignments {
    fn from(blob: &Blob) -> Self {
        let coefficients = blob.coefficients();
        let coefficients_scalar = coefficients.map(|coeff| Scalar::from_raw(coeff.0));
        let challenge_digest = blob.challenge_point();

        Self {
            challenge_digest,
            evaluation: U256::from_little_endian(
                &interpolate(Scalar::from_raw(challenge_digest.0), coefficients_scalar).to_bytes(),
            ),
            coefficients,
        }
    }
}

impl Default for BlobAssignments {
    fn default() -> Self {
        Self {
            challenge_digest: U256::default(),
            evaluation: U256::default(),
            coefficients: [U256::default(); BLOB_WIDTH],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::barycentric::ROOTS_OF_UNITY;
    use reth_primitives::{
        constants::eip4844::MAINNET_KZG_TRUSTED_SETUP,
        kzg::{Blob as RethBlob, KzgProof},
    };

    #[test]
    fn empty_chunks_random_point() {
        let empty_blob = Blob::default();
        assert_eq!(empty_blob.challenge_point(), U256::from(keccak256([0u8])),)
    }

    #[test]
    fn zero_blob() {
        let blob = Blob::default();

        let z = Scalar::from_raw(blob.challenge_point().0);
        let y = interpolate(
            z,
            blob.coefficients().map(|coeff| Scalar::from_raw(coeff.0)),
        );

        assert_eq!(
            z,
            from_str("4848d14b5080aacc030c6a2178eda978125553b177d80992ff96a9e164bcc989")
        );
        assert_eq!(y, Scalar::zero());
    }

    #[test]
    fn generic_blob() {
        let blob = Blob(vec![
            vec![30; 56],
            vec![200; 100],
            vec![0; 340],
            vec![10; 23],
            vec![14; 23],
            vec![255; 23],
        ]);

        let z = Scalar::from_raw(blob.challenge_point().0);
        let y = interpolate(
            z,
            blob.coefficients().map(|coeff| Scalar::from_raw(coeff.0)),
        );

        assert_eq!(
            z,
            from_str("17feb47df94b20c6da69f871c980459a7a834adad6a564304a0e8cd8a09bcb27")
        );
        assert_eq!(
            y,
            from_str("061f4f5d9005302ca556a0847d27f456cad82c6883a588fde6d48088fb4ec6a7")
        );
    }

    #[test]
    fn interpolate_matches_reth_implementation() {
        let blob = Blob(vec![
            vec![30; 56],
            vec![200; 100],
            vec![0; 340],
            vec![10; 23],
        ]);

        for z in 0..10 {
            let z = Scalar::from(u64::try_from(13241234 + z).unwrap());
            assert_eq!(
                reth_point_evaluation(z, blob.coefficients().map(|c| Scalar::from_raw(c.0))),
                interpolate(z, blob.coefficients().map(|c| Scalar::from_raw(c.0)))
            );
        }
    }

    fn reth_point_evaluation(z: Scalar, coefficients: [Scalar; BLOB_WIDTH]) -> Scalar {
        let blob = RethBlob::from_bytes(
            &coefficients
                .into_iter()
                .flat_map(to_be_bytes)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let (_proof, y) =
            KzgProof::compute_kzg_proof(&blob, &to_be_bytes(z).into(), &MAINNET_KZG_TRUSTED_SETUP)
                .unwrap();
        from_canonical_be_bytes(*y)
    }

    #[test]
    fn reth_kzg_implementation() {
        // check that we are calling the reth implementation correctly
        for z in 0..10 {
            let z = Scalar::from(u64::try_from(z).unwrap());
            assert_eq!(reth_point_evaluation(z, *ROOTS_OF_UNITY), z)
        }
    }

    fn to_be_bytes(x: Scalar) -> [u8; 32] {
        let mut bytes = x.to_bytes();
        bytes.reverse();
        bytes
    }

    fn from_canonical_be_bytes(bytes: [u8; 32]) -> Scalar {
        let mut bytes = bytes;
        bytes.reverse();
        Scalar::from_bytes(&bytes).expect("non-canonical bytes")
    }

    fn from_str(x: &str) -> Scalar {
        let mut bytes: [u8; 32] = hex::decode(x)
            .expect("bad hex string")
            .try_into()
            .expect("need 32 bytes");
        bytes.reverse();
        Scalar::from_bytes(&bytes).expect("non-canonical representation")
    }

    #[test]
    fn test_be_bytes() {
        let mut be_bytes_one = [0; 32];
        be_bytes_one[31] = 1;
        assert_eq!(to_be_bytes(Scalar::one()), be_bytes_one);
    }
}
