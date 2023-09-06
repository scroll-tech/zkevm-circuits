//! secp256k1 signature types and helper functions.

use crate::{
    address,
    geth_types::{Transaction, TxType},
    word, ToBigEndian, Word, H256,
};
use ethers_core::{
    k256::ecdsa::SigningKey,
    types::{Address, Bytes, Signature, TransactionRequest, U256},
    utils::keccak256,
};
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
use subtle::CtOption;

/// Do a secp256k1 signature with a given randomness value.
pub fn sign(
    randomness: secp256k1::Fq,
    sk: secp256k1::Fq,
    msg_hash: secp256k1::Fq,
) -> (secp256k1::Fq, secp256k1::Fq, u8) {
    let randomness_inv =
        Option::<secp256k1::Fq>::from(randomness.invert()).expect("cannot invert randomness");
    let generator = Secp256k1Affine::generator();
    let sig_point = generator * randomness;
    let sig_v: bool = sig_point.to_affine().y.is_odd().into();

    let x = *Option::<Coordinates<_>>::from(sig_point.to_affine().coordinates())
        .expect("point is the identity")
        .x();

    let mut x_bytes = [0u8; 64];
    x_bytes[..32].copy_from_slice(&x.to_bytes());

    let sig_r = secp256k1::Fq::from_bytes_wide(&x_bytes); // get x cordinate (E::Base) on E::Scalar

    let sig_s = randomness_inv * (msg_hash + sig_r * sk);
    (sig_r, sig_s, u8::from(sig_v))
}

/// Signature data required by the SignVerify Chip as input to verify a
/// signature.
#[derive(Clone, Debug)]
pub struct SignData {
    /// Secp256k1 signature point (r, s, v)
    /// v must be 0 or 1
    pub signature: (secp256k1::Fq, secp256k1::Fq, u8),
    /// Secp256k1 public key
    pub pk: Secp256k1Affine,
    /// Message being hashed before signing.
    pub msg: Bytes,
    /// Hash of the message that is being signed
    pub msg_hash: secp256k1::Fq,
}

/// Generate a dummy pre-eip155 tx in which
/// (nonce=0, gas=0, gas_price=0, to=0, value=0, data="")
/// using the dummy private key = 1
pub fn get_dummy_tx() -> (TransactionRequest, Signature) {
    let mut sk_be_scalar = [0u8; 32];
    sk_be_scalar[31] = 1_u8;

    let sk = SigningKey::from_bytes(&sk_be_scalar).expect("sign key = 1");
    let wallet = ethers_signers::Wallet::from(sk);

    let tx = TransactionRequest::new()
        .nonce(0)
        .gas(0)
        .gas_price(U256::zero())
        .to(Address::zero())
        .value(U256::zero())
        .data(Bytes::default());
    let sighash: H256 = keccak256(tx.rlp_unsigned()).into();

    let sig = wallet.sign_hash(sighash);
    assert_eq!(sig.v, 28);
    assert_eq!(
        sig.r,
        word!("4faabf49beea23083894651a6f34baaf3dc29b396fb5baf8b8454773f328df61")
    );
    assert_eq!(
        sig.s,
        word!("0x75ae2dd5e4e688c9dbc6db7e75bafcb04ea141ca20332be9809a444d541272c1")
    );

    (tx, sig)
}

impl SignData {
    /// Recover address of the signature
    pub fn get_addr(&self) -> Address {
        let pk_le = pk_bytes_le(&self.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        let pk_hash = keccak256(pk_be);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&pk_hash[12..]);
        Address::from_slice(&addr_bytes)
    }
}

lazy_static! {
    /// This is the sign data of default padding tx
    static ref SIGN_DATA_DEFAULT: SignData = {
        let (tx_req, sig) = get_dummy_tx();
        let tx = Transaction {
            tx_type: TxType::PreEip155,
            rlp_unsigned_bytes: tx_req.rlp_unsigned().to_vec(),
            rlp_bytes: tx_req.rlp_signed(&sig).to_vec(),
            v: sig.v,
            r: sig.r,
            s: sig.s,
            // other fields are irrelevant to get the sign_data()
            ..Default::default()
        };

        let sign_data = tx.sign_data().unwrap();
        assert_eq!(sign_data.get_addr(), address!("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"));

        sign_data
    };
}

impl Default for SignData {
    // Hardcoded valid signature corresponding to a hardcoded private key and
    // message hash generated from "nothing up my sleeve" values to make the
    // ECDSA chip pass the constraints, to be use for padding signature
    // verifications (where the constraints pass, but we don't care about the
    // message hash and public key).
    fn default() -> Self {
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
