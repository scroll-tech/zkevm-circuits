//! utils for build state trie

use eth_types::{Address, Bytes, Word, H256, U256, U64};
use std::{
    convert::TryFrom,
    io::{Error, ErrorKind, Read},
};

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::halo2curves::group::ff::PrimeField;
use mpt_circuits::hash::Hashable;

use lazy_static::lazy_static;

lazy_static! {
    pub(crate) static ref HASH_SCHEME_DONE: bool = {
        zktrie::init_hash_scheme(hash_scheme);
        true
    };
}

static FILED_ERROR_READ: &str = "invalid input field";
static FILED_ERROR_OUT: &str = "output field fail";

extern "C" fn hash_scheme(a: *const u8, b: *const u8, out: *mut u8) -> *const i8 {
    use std::slice;
    let a: [u8; 32] =
        TryFrom::try_from(unsafe { slice::from_raw_parts(a, 32) }).expect("length specified");
    let b: [u8; 32] =
        TryFrom::try_from(unsafe { slice::from_raw_parts(b, 32) }).expect("length specified");
    let out = unsafe { slice::from_raw_parts_mut(out, 32) };

    let fa = Fr::from_bytes(&a);
    let fa = if fa.is_some().into() {
        fa.unwrap()
    } else {
        return FILED_ERROR_READ.as_ptr().cast();
    };
    let fb = Fr::from_bytes(&b);
    let fb = if fb.is_some().into() {
        fb.unwrap()
    } else {
        return FILED_ERROR_READ.as_ptr().cast();
    };

    let h = Fr::hash([fa, fb]);
    let repr_h = h.to_repr();
    if repr_h.len() == 32 {
        out.copy_from_slice(repr_h.as_ref());
        std::ptr::null()
    } else {
        FILED_ERROR_OUT.as_ptr().cast()
    }
}

const NODE_TYPE_MIDDLE: u8 = 0;
const NODE_TYPE_LEAF: u8 = 1;
const NODE_TYPE_EMPTY: u8 = 2;

#[derive(Debug, Default, Copy, Clone)]
pub(crate) struct AccountData {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256,
    pub storage_root: H256,
}

pub(crate) fn extend_address_to_h256(src: &Address) -> [u8; 32] {
    let mut bts: Vec<u8> = src.as_bytes().into();
    bts.resize(32, 0);
    bts.as_slice().try_into().expect("32 bytes")
}

pub(crate) trait CanRead: Sized {
    fn try_parse(rd: impl Read) -> Result<Self, Error>;
    fn parse_leaf(data: &[u8]) -> Result<Self, Error> {
        // notice the first 33 bytes has been read external
        Self::try_parse(&data[33..])
    }
}

impl CanRead for AccountData {
    fn try_parse(mut rd: impl Read) -> Result<Self, Error> {
        let mut uint_buf = [0; 4];
        rd.read_exact(&mut uint_buf)?;
        // check it is 0x04040000
        if uint_buf != [4, 4, 0, 0] {
            return Err(Error::new(ErrorKind::Other, "unexpected flags"));
        }

        let mut byte32_buf = [0; 32];
        rd.read_exact(&mut byte32_buf)?; //nonce
        let nonce = U64::from_big_endian(&byte32_buf[24..]);
        rd.read_exact(&mut byte32_buf)?; //balance
        let balance = U256::from_big_endian(&byte32_buf);
        rd.read_exact(&mut byte32_buf)?; //codehash
        let code_hash = H256::from(&byte32_buf);
        rd.read_exact(&mut byte32_buf)?; //storage root, not need yet
        let storage_root = H256::from(&byte32_buf);

        Ok(AccountData {
            nonce: nonce.as_u64(),
            balance,
            code_hash,
            storage_root,
        })
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct StorageData(Word);

impl AsRef<Word> for StorageData {
    fn as_ref(&self) -> &Word {
        &self.0
    }
}

impl CanRead for StorageData {
    fn try_parse(mut rd: impl Read) -> Result<Self, Error> {
        let mut uint_buf = [0; 4];
        rd.read_exact(&mut uint_buf)?;
        // check it is 0x01010000
        if uint_buf != [1, 1, 0, 0] {
            return Err(Error::new(ErrorKind::Other, "unexpected flags"));
        }
        let mut byte32_buf = [0; 32];
        rd.read_exact(&mut byte32_buf)?;
        Ok(StorageData(Word::from(byte32_buf)))
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct TrieProof<T> {
    pub data: T,
    pub key: Option<H256>,
    // the path from top to bottom, in (left child, right child) form
    pub path: Vec<(U256, U256)>,
}

pub(crate) type AccountProof = TrieProof<AccountData>;
pub(crate) type StorageProof = TrieProof<StorageData>;

pub(crate) struct BytesArray<T>(pub T);

impl<'d, T, BYTES> TryFrom<BytesArray<BYTES>> for TrieProof<T>
where
    T: CanRead + Default,
    BYTES: Iterator<Item = &'d [u8]>,
{
    type Error = Error;

    fn try_from(src: BytesArray<BYTES>) -> Result<Self, Self::Error> {
        let mut path: Vec<(U256, U256)> = Vec::new();
        for data in src.0 {
            let mut rd = data;
            let mut prefix = [0; 1];
            rd.read_exact(&mut prefix)?;
            match prefix[0] {
                NODE_TYPE_LEAF => {
                    let mut byte32_buf = [0; 32];
                    rd.read_exact(&mut byte32_buf)?;
                    let key = H256::from(byte32_buf);
                    let data = T::parse_leaf(data)?;
                    return Ok(Self {
                        key: Some(key),
                        data,
                        path,
                    });
                }
                NODE_TYPE_EMPTY => {
                    return Ok(Self {
                        path,
                        ..Default::default()
                    });
                }
                NODE_TYPE_MIDDLE => {
                    let mut buf: [u8; 32] = [0; 32];
                    rd.read_exact(&mut buf)?;
                    let left = U256::from_big_endian(&buf);
                    rd.read_exact(&mut buf)?;
                    let right = U256::from_big_endian(&buf);
                    path.push((left, right));
                }
                _ => (),
            }
        }

        Err(Error::new(ErrorKind::UnexpectedEof, "no leaf key found"))
    }
}

impl<T: CanRead + Default> TryFrom<&[Bytes]> for TrieProof<T> {
    type Error = Error;
    fn try_from(src: &[Bytes]) -> Result<Self, Self::Error> {
        Self::try_from(BytesArray(src.iter().map(Bytes::as_ref)))
    }
}

pub(crate) fn verify_proof_leaf<T: Default>(inp: TrieProof<T>, key_buf: &[u8; 32]) -> TrieProof<T> {
    let first_16bytes: [u8; 16] = key_buf[..16].try_into().expect("expect first 16 bytes");
    let last_16bytes: [u8; 16] = key_buf[16..].try_into().expect("expect last 16 bytes");

    let bt_high = Fr::from_u128(u128::from_be_bytes(first_16bytes));
    let bt_low = Fr::from_u128(u128::from_be_bytes(last_16bytes));

    if let Some(key) = inp.key {
        let rev_key_bytes: Vec<u8> = key.to_fixed_bytes().into_iter().rev().collect();
        let key_fr = Fr::from_bytes(&rev_key_bytes.try_into().unwrap()).unwrap();

        let secure_hash = Fr::hash([bt_high, bt_low]);

        if key_fr == secure_hash {
            inp
        } else {
            Default::default()
        }
    } else {
        inp
    }
}
