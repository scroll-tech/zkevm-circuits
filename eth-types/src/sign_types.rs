//! secp256k1 signature types and helper functions.

use crate::{ToBigEndian, Word};
use ethers_core::types::Bytes;
use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    halo2curves::{
        group::{
            ff::{Field as GroupField, PrimeField},
            Curve,
        },
        secp256k1::{self, Secp256k1Affine},
        Coordinates,
    },
};
use lazy_static::lazy_static;
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};
use subtle::CtOption;

/// Do a secp256k1 signature with a given randomness value.
pub fn sign(
    randomness: secp256k1::Fq,
    sk: secp256k1::Fq,
    msg_hash: secp256k1::Fq,
) -> (secp256k1::Fq, secp256k1::Fq) {
    let randomness_inv =
        Option::<secp256k1::Fq>::from(randomness.invert()).expect("cannot invert randomness");
    let generator = Secp256k1Affine::generator();
    let sig_point = generator * randomness;
    let x = *Option::<Coordinates<_>>::from(sig_point.to_affine().coordinates())
        .expect("point is the identity")
        .x();

    let x_repr = &mut vec![0u8; 32];
    x_repr.copy_from_slice(x.to_bytes().as_slice());

    let mut x_bytes = [0u8; 64];
    x_bytes[..32].copy_from_slice(&x_repr[..]);

    let sig_r = secp256k1::Fq::from_bytes_wide(&x_bytes); // get x cordinate (E::Base) on E::Scalar
    let sig_s = randomness_inv * (msg_hash + sig_r * sk);
    (sig_r, sig_s)
}

/// Signature data required by the SignVerify Chip as input to verify a
/// signature.
#[derive(Clone, Debug)]
pub struct SignData {
    /// Secp256k1 signature point
    pub signature: (secp256k1::Fq, secp256k1::Fq),
    /// Secp256k1 public key
    pub pk: Secp256k1Affine,
    /// Message being hashed before signing.
    pub msg: Bytes,
    /// Hash of the message that is being signed
    pub msg_hash: secp256k1::Fq,
}

lazy_static! {
    static ref SIGN_DATA_DEFAULT: SignData = {
        let generator = Secp256k1Affine::generator();
        let sk = secp256k1::Fq::one();
        let pk = generator * sk;
        let pk = pk.to_affine();
        let msg = b"1";
        // let msg = TransactionRequest::new()
        //     .nonce(0)
        //     .gas(0)
        //     .gas_price(U256::zero())
        //     .to(Address::zero())
        //     .value(U256::zero())
        //     .data(Bytes::default())
        //     .chain_id(1)
        //     .rlp().to_vec();
        let msg_hash: [u8; 32] = Keccak256::digest(msg)
            .as_slice()
            .to_vec()
            .try_into()
            .expect("hash length isn't 32 bytes");
        let msg_hash = secp256k1::Fq::from_bytes(&msg_hash).unwrap();
        let randomness = secp256k1::Fq::one();
        let (sig_r, sig_s) = sign(randomness, sk, msg_hash);

        SignData {
            signature: (sig_r, sig_s),
            pk,
            msg: msg.into(),
            msg_hash,
        }
    };
}

impl Default for SignData {
    fn default() -> Self {
        // Hardcoded valid signature corresponding to a hardcoded private key and
        // message hash generated from "nothing up my sleeve" values to make the
        // ECDSA chip pass the constraints, to be use for padding signature
        // verifications (where the constraints pass, but we don't care about the
        // message hash and public key).
        SIGN_DATA_DEFAULT.clone()
    }
}

/// Convert a `BigUint` into 32 bytes in little endian.
pub fn biguint_to_32bytes_le(v: BigUint) -> [u8; 32] {
    let mut res = [0u8; 32];
    let v_le = v.to_bytes_le();
    res[..v_le.len()].copy_from_slice(&v_le);
    res
}

/// Recover the public key from a secp256k1 signature and the message hash.
pub fn recover_pk(
    v: u8,
    r: &Word,
    s: &Word,
    msg_hash: &[u8; 32],
) -> Result<Secp256k1Affine, libsecp256k1::Error> {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r.to_be_bytes());
    sig_bytes[32..].copy_from_slice(&s.to_be_bytes());
    let signature = libsecp256k1::Signature::parse_standard(&sig_bytes)?;
    let msg_hash = libsecp256k1::Message::parse_slice(msg_hash.as_slice())?;
    let recovery_id = libsecp256k1::RecoveryId::parse(v)?;
    let pk = libsecp256k1::recover(&msg_hash, &signature, &recovery_id)?;
    let pk_be = pk.serialize();
    let pk_le = pk_bytes_swap_endianness(&pk_be[1..]);
    let x = ct_option_ok_or(
        secp256k1::Fp::from_bytes(pk_le[..32].try_into().unwrap()),
        libsecp256k1::Error::InvalidPublicKey,
    )?;
    let y = ct_option_ok_or(
        secp256k1::Fp::from_bytes(pk_le[32..].try_into().unwrap()),
        libsecp256k1::Error::InvalidPublicKey,
    )?;
    ct_option_ok_or(
        Secp256k1Affine::from_xy(x, y),
        libsecp256k1::Error::InvalidPublicKey,
    )
}

lazy_static! {
    /// Secp256k1 Curve Scalar.  Referece: Section 2.4.1 (parameter `n`) in "SEC 2: Recommended
    /// Elliptic Curve Domain Parameters" document at http://www.secg.org/sec2-v2.pdf
    pub static ref SECP256K1_Q: BigUint = BigUint::from_bytes_le(&(secp256k1::Fq::zero() - secp256k1::Fq::one()).to_repr()) + 1u64;
}

/// Helper function to convert a `CtOption` into an `Result`.  Similar to
/// `Option::ok_or`.
pub fn ct_option_ok_or<T, E>(v: CtOption<T>, err: E) -> Result<T, E> {
    Option::<T>::from(v).ok_or(err)
}

/// Return a copy of the serialized public key with swapped Endianness.
pub fn pk_bytes_swap_endianness<T: Clone>(pk: &[T]) -> [T; 64] {
    assert_eq!(pk.len(), 64);
    let mut pk_swap = <&[T; 64]>::try_from(pk)
        .map(|r| r.clone())
        .expect("pk.len() != 64");
    pk_swap[..32].reverse();
    pk_swap[32..].reverse();
    pk_swap
}

/// Return the secp256k1 public key (x, y) coordinates in little endian bytes.
pub fn pk_bytes_le(pk: &Secp256k1Affine) -> [u8; 64] {
    let pk_coord = Option::<Coordinates<_>>::from(pk.coordinates()).expect("point is the identity");
    let mut pk_le = [0u8; 64];
    pk_le[..32].copy_from_slice(&pk_coord.x().to_bytes());
    pk_le[32..].copy_from_slice(&pk_coord.y().to_bytes());
    pk_le
}
