//! utils for build state trie

use eth_types::{Word, Address, Bytes, H256, U256, U64};
use num_bigint::BigUint;
use std::{
    convert::TryFrom,
    io::{Error, ErrorKind, Read},
};


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
struct StorageData(Word);

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

type AccountProof = TrieProof<AccountData>;
type StorageProof = TrieProof<StorageData>;

pub(crate) struct BytesArray<T> (pub T);

impl<'d, T, BYTES> TryFrom<BytesArray<BYTES>> for TrieProof<T> 
where
    T : CanRead + Default,
    BYTES: Iterator<Item= &'d [u8]>,
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


impl<T : CanRead + Default> TryFrom<&[Bytes]> for TrieProof<T> 
{
    type Error = Error;
    fn try_from(src: &[Bytes]) -> Result<Self, Self::Error> {
        Self::try_from(BytesArray(src.iter().map(Bytes::as_ref)))
    }
}

pub(crate) fn verify_proof_leaf<T: Default>(
    inp: TrieProof<T>,
    key_buf: &[u8; 32],
) -> TrieProof<T> {
    use halo2_proofs::halo2curves::bn256::Fr;
    use halo2_proofs::arithmetic::FieldExt;
    use mpt_circuits::hash::Hashable;

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


/*
pub fn build_statedb_and_codedb(blocks: &[BlockTrace]) -> Result<(StateDB, CodeDB), anyhow::Error> {
    let mut sdb = StateDB::new();
    let mut cdb =
        CodeDB::new_with_code_hasher(Box::new(PoseidonCodeHash::new(POSEIDONHASH_BYTES_IN_FIELD)));

    // step1: insert proof into statedb
    for block in blocks.iter().rev() {
        let storage_trace = &block.storage_trace;
        if let Some(acc_proofs) = &storage_trace.proofs {
            for (addr, acc) in acc_proofs.iter() {
                let acc_proof: mpt::AccountProof = acc.as_slice().try_into()?;
                let acc = verify_proof_leaf(acc_proof, &mpt::extend_address_to_h256(addr));
                if acc.key.is_some() {
                    // a valid leaf
                    let (_, acc_mut) = sdb.get_account_mut(addr);
                    acc_mut.nonce = acc.data.nonce.into();
                    acc_mut.code_hash = acc.data.code_hash;
                    acc_mut.balance = acc.data.balance;
                } else {
                    // it is essential to set it as default (i.e. not existed account data)
                    sdb.set_account(
                        addr,
                        Account {
                            nonce: Default::default(),
                            balance: Default::default(),
                            storage: HashMap::new(),
                            code_hash: Default::default(),
                        },
                    );
                }
            }
        }

        for (addr, s_map) in storage_trace.storage_proofs.iter() {
            let (found, acc) = sdb.get_account_mut(addr);
            if !found {
                log::error!("missed address in proof field show in storage: {:?}", addr);
                continue;
            }

            for (k, val) in s_map {
                let mut k_buf: [u8; 32] = [0; 32];
                k.to_big_endian(&mut k_buf[..]);
                let val_proof: mpt::StorageProof = val.as_slice().try_into()?;
                let val = verify_proof_leaf(val_proof, &k_buf);

                if val.key.is_some() {
                    // a valid leaf
                    acc.storage.insert(*k, *val.data.as_ref());
                //                log::info!("set storage {:?} {:?} {:?}", addr, k, val.data);
                } else {
                    // add 0
                    acc.storage.insert(*k, Default::default());
                    //                log::info!("set empty storage {:?} {:?}", addr, k);
                }
            }
        }

        // step2: insert code into codedb
        // notice empty codehash always kept as keccak256(nil)
        cdb.insert(Vec::new());

        for execution_result in &block.execution_results {
            if let Some(bytecode) = &execution_result.byte_code {
                if execution_result.account_created.is_none() {
                    cdb.0.insert(
                        execution_result
                            .code_hash
                            .ok_or_else(|| anyhow!("empty code hash in result"))?,
                        decode_bytecode(bytecode)?.to_vec(),
                    );
                }
            }

            for step in execution_result.exec_steps.iter().rev() {
                if let Some(data) = &step.extra_data {
                    match step.op {
                        OpcodeId::CALL
                        | OpcodeId::CALLCODE
                        | OpcodeId::DELEGATECALL
                        | OpcodeId::STATICCALL => {
                            let callee_code = data.get_code_at(1);
                            trace_code(&mut cdb, step, &sdb, callee_code, 1);
                        }
                        OpcodeId::CREATE | OpcodeId::CREATE2 => {
                            // notice we do not need to insert code for CREATE,
                            // bustmapping do this job
                        }
                        OpcodeId::EXTCODESIZE | OpcodeId::EXTCODECOPY => {
                            let code = data.get_code_at(0);
                            trace_code(&mut cdb, step, &sdb, code, 0);
                        }

                        _ => {}
                    }
                }
            }
        }
    }

    // A temporary fix: zkgeth do not trace 0 address if it is only refered as coinbase
    // (For it is not the "real" coinbase address in PoA) but would still refer it for
    // other reasons (like being transferred or called), in the other way, busmapping
    // seems always refer it as coinbase (?)
    // here we just add it as unexisted account and consider fix it in zkgeth later (always
    // record 0 addr inside storageTrace field)
    let (zero_coinbase_exist, _) = sdb.get_account(&Default::default());
    if !zero_coinbase_exist {
        sdb.set_account(
            &Default::default(),
            Account {
                nonce: Default::default(),
                balance: Default::default(),
                storage: HashMap::new(),
                code_hash: Default::default(),
            },
        );
    }

    Ok((sdb, cdb))
}
 */