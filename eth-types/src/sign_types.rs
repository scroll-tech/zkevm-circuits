//! secp256k1 signature types and helper functions.

use crate::{
    address,
    geth_types::{Transaction, TxType},
    word, Error, Word, H256,
};
use ethers_core::{
    k256::{
        ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey},
        elliptic_curve::{consts::U32, sec1::ToEncodedPoint},
        PublicKey as K256PublicKey,
    },
    types::{Address, Bytes, Signature, TransactionRequest, U256},
    utils::keccak256,
};
use halo2curves::{
    ff::FromUniformBytes,
    //group::{ff::PrimeField, prime::PrimeCurveAffine, Curve},
    group::{ff::PrimeField, prime::PrimeCurveAffine, Curve},

    // secp256k1 curve
    secp256k1::{Fp as Fp_K1, Fq as Fq_K1, Secp256k1Affine},
    // p256 curve
    secp256r1::{Fp as Fp_R1, Fq as Fq_R1, Secp256r1Affine},
    Coordinates,
    CurveAffine,
    CurveAffineExt,
};
use num_bigint::BigUint;
use sha3::digest::generic_array::GenericArray;
use std::sync::LazyLock;
use subtle::CtOption;

/// Do a secp256k1 or secp256r1 signature with a given randomness value.
/// FromUniformBytes<64> refers to https://github.com/scroll-tech/halo2curves/blob/v0.1.0/src/secp256k1/fq.rs#L287
/// and https://github.com/scroll-tech/halo2curves/blob/v0.1.0/src/secp256r1/fq.rs#L283
pub fn sign<
    Fp: PrimeField<Repr = [u8; 32]>,
    Fq: PrimeField + FromUniformBytes<64>,
    Affine: CurveAffine<ScalarExt = Fq, Base = Fp> + std::ops::Mul<Fq> + CurveAffineExt,
>(
    randomness: Fq,
    sk: Fq,
    msg_hash: Fq,
) -> (Fq, Fq, u8) {
    let randomness_inv = Option::<Fq>::from(randomness.invert()).expect("cannot invert randomness");
    let generator = Affine::generator();
    let sig_point = generator * randomness;
    let sig_v: bool = sig_point.to_affine().into_coordinates().1.is_odd().into();

    let x = *Option::<Coordinates<_>>::from(sig_point.to_affine().coordinates())
        .expect("point is the identity")
        .x();

    let mut x_bytes = [0u8; 64];
    x_bytes[..32].copy_from_slice(&x.to_repr());

    // get x cordinate (E::Base) on E::Scalar
    let sig_r = Fq::from_uniform_bytes(&x_bytes);

    let sig_s = randomness_inv * (msg_hash + sig_r * sk);

    (sig_r, sig_s, u8::from(sig_v))
}

/// Do a secp256k1 or secp256r1 signature verification with a given pub key.
/// Refers to https://github.com/scroll-tech/halo2curves/blob/v0.1.0/src/secp256k1/curve.rs
/// and https://github.com/scroll-tech/halo2curves/blob/v0.1.0/src/secp256r1/curve.rs
pub fn verify<
    Fp: PrimeField<Repr = [u8; 32]>,
    Fq: PrimeField + FromUniformBytes<64>,
    Affine: CurveAffine<ScalarExt = Fq, Base = Fp> + std::ops::Mul<Fq> + CurveAffineExt,
>(
    pub_key: Affine,
    r: Fq,
    s: Fq,
    msg_hash: Fq,
    // if pubkey is provided rather than from recovered , v is not necessary.
    _v: Option<bool>,
) -> bool {
    // Verify
    let s_inv = s.invert().unwrap();
    let u_1 = msg_hash * s_inv;
    let u_2 = r * s_inv;

    let g = Affine::generator();
    let u1_affine = g * u_1;

    let u2_affine = pub_key * u_2;

    let r_point = (u1_affine + u2_affine).to_affine().coordinates().unwrap();
    let x_candidate = r_point.x();
    let r_candidate = mod_n(*x_candidate);

    // v is used to recovery y, not use it for now.
    r == r_candidate
}

// convert Fp to Fq
fn mod_n<Fp: PrimeField<Repr = [u8; 32]>, Fq: PrimeField + FromUniformBytes<64>>(x: Fp) -> Fq {
    let mut x_repr = [0u8; 32];
    x_repr.copy_from_slice(x.to_repr().as_ref());
    let mut x_bytes = [0u8; 64];
    x_bytes[..32].copy_from_slice(&x_repr[..]);
    Fq::from_uniform_bytes(&x_bytes)
}

/// Signature data required by the SignVerify Chip as input to verify a
/// signature.
#[derive(Clone, Debug)]
pub struct SignData<Fq: PrimeField, Affine: CurveAffine> {
    /// Secp256k1 signature point (r, s, v)
    /// v must be 0 or 1
    pub signature: (Fq, Fq, u8),
    /// Secp256k1 or Secp256r1 public key
    ///
    pub pk: Affine,
    /// Message being hashed before signing.
    /// for Secp256r1(p256)verify precompile, msg bytes is unknown, only with msg_hash.
    pub msg: Bytes,
    /// Hash of the message that is being signed
    pub msg_hash: Fq,
}

/// Generate a dummy pre-eip155 tx in which
/// (nonce=0, gas=0, gas_price=0, to=0, value=0, data="")
/// using the dummy private key = 1
pub fn get_dummy_tx() -> (TransactionRequest, Signature) {
    let mut sk_be_scalar = [0u8; 32];
    sk_be_scalar[31] = 1_u8;

    let sk = SigningKey::from_bytes((&sk_be_scalar).into()).expect("sign key = 1");
    let wallet = ethers_signers::Wallet::from(sk);

    let tx = TransactionRequest::new()
        .nonce(0)
        .gas(0)
        .gas_price(U256::zero())
        .to(Address::zero())
        .value(U256::zero())
        .data(Bytes::default());
    let sighash: H256 = keccak256(tx.rlp_unsigned()).into();

    let sig = wallet
        .sign_hash(sighash)
        .expect("sign dummy tx using dummy sk");
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

impl SignData<Fq_K1, Secp256k1Affine> {
    /// Recover address of the signature
    pub fn get_addr(&self) -> Address {
        if self.pk.is_identity().into() {
            return Address::zero();
        }
        let pk_hash = keccak256(pk_bytes_swap_endianness(&pk_bytes_le(&self.pk)));
        Address::from_slice(&pk_hash[12..])
    }
}

impl SignData<Fq_R1, Secp256r1Affine> {
    /// Recover address of the signature
    pub fn get_addr(&self) -> Address {
        if self.pk.is_identity().into() {
            return Address::zero();
        }
        let pk_hash = keccak256(pk_bytes_swap_endianness(&pk_bytes_le_generic(&self.pk)));
        Address::from_slice(&pk_hash[12..])
    }
}

static SIGN_DATA_DEFAULT: LazyLock<SignData<Fq_K1, Secp256k1Affine>> = LazyLock::new(|| {
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
    assert_eq!(
        sign_data.get_addr(),
        address!("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")
    );

    sign_data
});

static SIGN_DATA_DEFAULT_R1: LazyLock<SignData<Fq_R1, Secp256r1Affine>> = LazyLock::new(|| {
    let sk = Fq_R1::one().double();
    let pk = Secp256r1Affine::generator() * sk;
    let pk = pk.to_affine();

    let msg = [0u8; 32];
    //let msg_hash = Fq_R1::one();

    let msg_hash = keccak256(msg);
    let msg_hash_fq = Fq_R1::from_bytes(&msg_hash).unwrap();

    let signature = sign::<Fp_R1, Fq_R1, Secp256r1Affine>(Fq_R1::one(), sk, msg_hash_fq);

    SignData {
        signature,
        pk,
        msg: msg.into(),
        //msg_hash,
        msg_hash: msg_hash_fq,
    }
});

// Default for secp256k1
impl Default for SignData<Fq_K1, Secp256k1Affine> {
    // Hardcoded valid signature corresponding to a hardcoded private key and
    // message hash generated from "nothing up my sleeve" values to make the
    // ECDSA chip pass the constraints, to be use for padding signature
    // verifications (where the constraints pass, but we don't care about the
    // message hash and public key).
    fn default() -> Self {
        SIGN_DATA_DEFAULT.clone()
    }
}

// Default for secp256r1
impl Default for SignData<Fq_R1, Secp256r1Affine> {
    // Hardcoded valid signature corresponding to a hardcoded private key and
    // message hash generated from "nothing up my sleeve" values to make the
    // ECDSA chip pass the constraints, to be use for padding signature
    // verifications (where the constraints pass, but we don't care about the
    // message hash and public key).
    fn default() -> Self {
        SIGN_DATA_DEFAULT_R1.clone()
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
pub fn recover_pk2(
    v: u8,
    r: &Word,
    s: &Word,
    msg_hash: &[u8; 32],
) -> Result<Secp256k1Affine, Error> {
    debug_assert!(v == 0 || v == 1, "recovery ID (v) is boolean");
    let mut recoverable_sig = {
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        r.to_big_endian(&mut r_bytes);
        s.to_big_endian(&mut s_bytes);
        let gar: &GenericArray<u8, U32> = GenericArray::from_slice(&r_bytes);
        let gas: &GenericArray<u8, U32> = GenericArray::from_slice(&s_bytes);
        K256Signature::from_scalars(*gar, *gas).map_err(|_| Error::Signature)?
    };
    let mut v = v;
    if let Some(sig_normalized) = recoverable_sig.normalize_s() {
        recoverable_sig = sig_normalized;
        v ^= 1;
    };
    let recovery_id = RecoveryId::from_byte(v).expect("normalized recovery id always valid");
    let verify_key =
        VerifyingKey::recover_from_prehash(msg_hash.as_ref(), &recoverable_sig, recovery_id)
            .map_err(|_| Error::Signature)?;
    let public_key = K256PublicKey::from(&verify_key);
    let public_key = public_key.to_encoded_point(/* compress = */ false);
    let public_key = public_key.as_bytes();
    debug_assert_eq!(public_key[0], 0x04);
    let pk_le = pk_bytes_swap_endianness(&public_key[1..]);
    let x = ct_option_ok_or(
        Fp_K1::from_bytes(pk_le[..32].try_into().unwrap()),
        Error::Signature,
    )?;
    let y = ct_option_ok_or(
        Fp_K1::from_bytes(pk_le[32..].try_into().unwrap()),
        Error::Signature,
    )?;
    ct_option_ok_or(Secp256k1Affine::from_xy(x, y), Error::Signature)
}

/// Secp256k1 Curve Scalar.  Reference: Section 2.4.1 (parameter `n`) in "SEC 2: Recommended
/// Elliptic Curve Domain Parameters" document at http://www.secg.org/sec2-v2.pdf
pub static SECP256K1_Q: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::from_bytes_le(&(Fq_K1::zero() - Fq_K1::one()).to_repr()) + 1u64);

/// Helper function to convert a `CtOption` into an `Result`.  Similar to
/// `Option::ok_or`.
pub fn ct_option_ok_or<T, E>(v: CtOption<T>, err: E) -> Result<T, E> {
    Option::<T>::from(v).ok_or(err)
}

/// Return a copy of the serialized public key with swapped Endianness.
pub fn pk_bytes_swap_endianness<T: Clone>(pk: &[T]) -> [T; 64] {
    assert_eq!(pk.len(), 64);
    let mut pk_swap = <&[T; 64]>::try_from(pk).cloned().expect("pk.len() != 64");
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

/// Return both secp256k1 and secp256r1 public key (x, y) coordinates in little endian bytes.
pub fn pk_bytes_le_generic<
    Fp: PrimeField<Repr = [u8; 32]>, // + GroupEncoding<Repr = [u8; 32]>, // 32 bytes for secp256k1 and secp256r1 curve
    Affine: CurveAffine<Base = Fp>,
>(
    pk: &Affine,
) -> [u8; 64] {
    let pk_coord = Option::<Coordinates<_>>::from(pk.coordinates()).expect("point is the identity");
    let mut pk_le = [0u8; 64];
    pk_le[..32].copy_from_slice(&pk_coord.x().to_repr());
    pk_le[32..].copy_from_slice(&pk_coord.y().to_repr());
    pk_le
}

/// this helper should can be removed now.
pub fn pk_bytes_le_p256(pk: &Secp256r1Affine) -> [u8; 64] {
    let pk_coord = Option::<Coordinates<_>>::from(pk.coordinates()).expect("point is the identity");
    let mut pk_le = [0u8; 64];
    pk_le[..32].copy_from_slice(&pk_coord.x().to_bytes());
    pk_le[32..].copy_from_slice(&pk_coord.y().to_bytes());
    pk_le
}
