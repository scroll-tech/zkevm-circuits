//! utils for build state trie

use eth_types::{
    state_db, Address, Bytes, Word, H256, KECCAK_CODE_HASH_EMPTY, POSEIDON_CODE_HASH_EMPTY, U256,
    U64,
};
use std::{
    convert::TryFrom,
    io::{Error, ErrorKind, Read},
    sync::Once,
};

use halo2curves::{bn256::Fr, group::ff::PrimeField};
use poseidon_base::hash::Hashable;

/// Init hash scheme
pub fn init_hash_scheme() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        zktrie::init_hash_scheme_simple(poseidon_hash_scheme);
    });
}

fn poseidon_hash_scheme(a: &[u8; 32], b: &[u8; 32], domain: &[u8; 32]) -> Option<[u8; 32]> {
    let fa = Fr::from_bytes(a);
    let fa = if fa.is_some().into() {
        fa.unwrap()
    } else {
        return None;
    };
    let fb = Fr::from_bytes(b);
    let fb = if fb.is_some().into() {
        fb.unwrap()
    } else {
        return None;
    };
    let fdomain = Fr::from_bytes(domain);
    let fdomain = if fdomain.is_some().into() {
        fdomain.unwrap()
    } else {
        return None;
    };
    Some(Fr::hash_with_domain([fa, fb], fdomain).to_repr())
}

pub(crate) const NODE_TYPE_MIDDLE_0: u8 = 6;
pub(crate) const NODE_TYPE_MIDDLE_1: u8 = 7;
pub(crate) const NODE_TYPE_MIDDLE_2: u8 = 8;
pub(crate) const NODE_TYPE_MIDDLE_3: u8 = 9;
pub(crate) const NODE_TYPE_LEAF: u8 = 4;
pub(crate) const NODE_TYPE_EMPTY: u8 = 5;
/// Secure hash domain
pub const SECURE_HASH_DOMAIN: u64 = 512;

/// AccountData
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct AccountData {
    /// nonce
    pub nonce: u64,
    /// balance
    pub balance: U256,
    /// keccak code hash
    pub keccak_code_hash: H256,
    /// poseidon code hash
    pub poseidon_code_hash: H256,
    /// code size
    pub code_size: u64,
    /// storage root
    pub storage_root: H256,
}

impl AccountData {
    /// is empty account
    pub fn is_empty(&self) -> bool {
        //let is_poseidon_code_hash_zero = self.poseidon_code_hash.is_zero();
        //let is_keccak_code_hash_zero = self.keccak_code_hash.is_zero();
        let is_poseidon_code_hash_empty = self.poseidon_code_hash == *POSEIDON_CODE_HASH_EMPTY;
        let is_keccak_code_hash_empty = self.keccak_code_hash == *KECCAK_CODE_HASH_EMPTY;
        let is_code_size_empty = self.code_size == 0;
        debug_assert_eq!(is_poseidon_code_hash_empty, is_keccak_code_hash_empty);
        debug_assert_eq!(is_poseidon_code_hash_empty, is_code_size_empty, "{self:?}");
        let is_nonce_empty = self.nonce == 0;
        let is_balance_empty = self.balance.is_zero();
        is_poseidon_code_hash_empty && is_nonce_empty && is_balance_empty
    }
}

impl From<zktrie::AccountData> for AccountData {
    fn from(acc_fields: zktrie::AccountData) -> Self {
        let field0 = acc_fields[0];

        let code_size = U64::from_big_endian(&field0[16..24]);
        let nonce = U64::from_big_endian(&field0[24..]);
        let balance = U256::from_big_endian(&acc_fields[1]);
        let storage_root = H256::from(&acc_fields[2]);
        let keccak_code_hash = H256::from(&acc_fields[3]);
        let poseidon_code_hash = H256::from(&acc_fields[4]);

        Self {
            nonce: nonce.as_u64(),
            balance,
            keccak_code_hash,
            poseidon_code_hash,
            code_size: code_size.as_u64(),
            storage_root,
        }
    }
}

impl From<&AccountData> for state_db::Account {
    fn from(acc_data: &AccountData) -> Self {
        if acc_data.keccak_code_hash.is_zero() {
            state_db::Account::zero()
        } else {
            Self {
                nonce: acc_data.nonce.into(),
                balance: acc_data.balance,
                code_hash: acc_data.poseidon_code_hash,
                keccak_code_hash: acc_data.keccak_code_hash,
                code_size: acc_data.code_size.into(),
                storage: Default::default(),
            }
        }
    }
}

impl From<AccountData> for zktrie::AccountData {
    fn from(acc: AccountData) -> Self {
        let mut nonce_codesize = [0u8; 32];
        let u64factor = U256::from(0x10000000000000000u128);
        (U256::from(acc.code_size) * u64factor + U256::from(acc.nonce))
            .to_big_endian(nonce_codesize.as_mut_slice());
        let mut balance = [0u8; 32];
        acc.balance.to_big_endian(balance.as_mut_slice());
        let mut poseidon_code_hash = [0u8; 32];
        U256::from(acc.poseidon_code_hash.0).to_big_endian(poseidon_code_hash.as_mut_slice());
        let mut code_hash = [0u8; 32];
        U256::from(acc.keccak_code_hash.0).to_big_endian(code_hash.as_mut_slice());

        [
            nonce_codesize,
            balance,
            acc.storage_root.0,
            code_hash,
            poseidon_code_hash,
        ]
    }
}

/// Extend address to H256
pub fn extend_address_to_h256(src: &Address) -> [u8; 32] {
    let mut bts: Vec<u8> = src.as_bytes().into();
    bts.resize(32, 0);
    bts.as_slice().try_into().expect("32 bytes")
}

/// The trait to parse proof
pub trait CanRead: Sized {
    /// Try parse
    fn try_parse(rd: impl Read) -> Result<Self, Error>;
    /// Parse leaf
    fn parse_leaf(data: &[u8]) -> Result<Self, Error> {
        // notice the first 33 bytes has been read external
        Self::try_parse(&data[33..])
    }
}

impl CanRead for AccountData {
    fn try_parse(mut rd: impl Read) -> Result<Self, Error> {
        let mut uint_buf = [0; 4];
        rd.read_exact(&mut uint_buf)?;
        // check it is 0x05080000
        if uint_buf != [5, 8, 0, 0] {
            log::error!("invalid AccountData flag {:?}", uint_buf);
            return Err(Error::new(ErrorKind::Other, "unexpected flags"));
        }

        let mut read_buf = [0; zktrie::ACCOUNTFIELDS].map(|_| [0u8; zktrie::FIELDSIZE]);
        for field_buf in read_buf.iter_mut() {
            rd.read_exact(field_buf.as_mut_slice())?;
        }
        Ok(read_buf.into())
    }
}

/// Storage data
#[derive(Debug, Default, Clone)]
pub struct StorageData(Word);

impl AsRef<Word> for StorageData {
    fn as_ref(&self) -> &Word {
        &self.0
    }
}

impl From<StorageData> for Word {
    fn from(data: StorageData) -> Self {
        data.0
    }
}

impl From<zktrie::StoreData> for StorageData {
    fn from(store_field: zktrie::StoreData) -> Self {
        Self(Word::from(store_field))
    }
}

impl CanRead for StorageData {
    fn try_parse(mut rd: impl Read) -> Result<Self, Error> {
        let mut uint_buf = [0; 4];
        rd.read_exact(&mut uint_buf)?;
        // check it is 0x01010000
        if uint_buf != [1, 1, 0, 0] {
            log::error!("invalid StorageData flag {:?}", uint_buf);
            return Err(Error::new(ErrorKind::Other, "unexpected flags"));
        }
        let mut byte32_buf = [0; 32];
        rd.read_exact(&mut byte32_buf)?;
        Ok(StorageData(Word::from(byte32_buf)))
    }
}

/// Trie proof
#[derive(Debug, Default, Clone)]
pub struct TrieProof<T> {
    /// Data
    pub data: T,
    /// Key
    pub key: Option<H256>,
    /// Key stype
    pub key_type: Option<u64>,
    /// the path from top to bottom, in (left child, right child) form
    pub path: Vec<(U256, U256)>,
    /// the path type from top to bottom
    pub path_type: Vec<u64>,
}

/// Account Proof
pub type AccountProof = TrieProof<AccountData>;
/// Storage Proof
pub type StorageProof = TrieProof<StorageData>;

/// Helper for dealing with bytes array
pub struct BytesArray<T>(pub T);

impl<'d, T, BYTES> TryFrom<BytesArray<BYTES>> for TrieProof<T>
where
    T: CanRead + Default,
    BYTES: Iterator<Item = &'d [u8]>,
{
    type Error = Error;

    fn try_from(src: BytesArray<BYTES>) -> Result<Self, Self::Error> {
        let mut path: Vec<(U256, U256)> = Vec::new();
        let mut path_type: Vec<u64> = Vec::new();
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
                        key_type: Some(prefix[0] as u64),
                        data,
                        path,
                        path_type,
                    });
                }
                NODE_TYPE_EMPTY => {
                    return Ok(Self {
                        path,
                        path_type,
                        key_type: Some(prefix[0] as u64),
                        ..Default::default()
                    });
                }
                NODE_TYPE_MIDDLE_0 | NODE_TYPE_MIDDLE_1 | NODE_TYPE_MIDDLE_2
                | NODE_TYPE_MIDDLE_3 => {
                    let mut buf: [u8; 32] = [0; 32];
                    rd.read_exact(&mut buf)?;
                    let left = U256::from_big_endian(&buf);
                    rd.read_exact(&mut buf)?;
                    let right = U256::from_big_endian(&buf);
                    path.push((left, right));
                    path_type.push(prefix[0] as u64);
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

        let secure_hash = Fr::hash_with_domain([bt_high, bt_low], Fr::from(SECURE_HASH_DOMAIN));

        if key_fr == secure_hash {
            inp
        } else {
            Default::default()
        }
    } else {
        inp
    }
}
