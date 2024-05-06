//! witness generator
use eth_types::{Address, Hash, ToWord, Word, H256, U256};
use halo2_proofs::halo2curves::group::ff::PrimeField;
use mpt_circuits::{
    serde::{
        AccountData as SMTAccount, Hash as SMTHash, HexBytes, SMTNode, SMTPath, SMTTrace, StateData,
    },
    MPTProofType,
};
use mpt_zktrie::{
    extend_address_to_h256, state::StorageData, AccountData, BytesArray, CanRead, TrieProof,
    ZkTrie, ZkTrieNode, ZktrieState, SECURE_HASH_DOMAIN,
};
use std::collections::HashMap;

use num_bigint::BigUint;
use std::{
    fmt,
    io::{Error as IoError, Read},
};

fn to_smt_account(acc: AccountData) -> SMTAccount {
    let mut balance: [u8; 32] = [0; 32];
    acc.balance.to_big_endian(balance.as_mut_slice());
    let balance = BigUint::from_bytes_be(balance.as_slice());
    let code_hash = BigUint::from_bytes_be(acc.keccak_code_hash.as_bytes());
    let poseidon_code_hash = BigUint::from_bytes_be(acc.poseidon_code_hash.as_bytes());
    let code_size = acc.code_size;

    SMTAccount {
        nonce: acc.nonce,
        balance,
        code_hash,
        poseidon_code_hash,
        code_size,
    }
}

/// witness generator for producing SMTTrace
pub struct WitnessGenerator {
    trie: ZkTrie,
    storages_cache: HashMap<Address, ZkTrie>,
}

impl From<&ZktrieState> for WitnessGenerator {
    fn from(state: &ZktrieState) -> Self {
        Self {
            trie: state.zk_db.borrow_mut().new_trie(&state.trie_root).unwrap(),
            storages_cache: HashMap::new(),
        }
    }
}

impl WitnessGenerator {
    /// dump inner data for debugging
    pub fn dump<'a>(&self, addrs: impl Iterator<Item = &'a Address>) {
        for addr in addrs {
            let acc = self
                .trie
                .get_account(addr.as_bytes())
                .map(AccountData::from);
            log::info!("account data {:#x}: {:#?}", addr, acc);
        }
    }
    /// get account proof
    pub fn account_proof(&self, address: Address) -> Vec<Vec<u8>> {
        self.trie.prove(address.as_bytes()).unwrap()
    }
    /// get storage proof
    pub fn storage_proof(&self, address: Address, key: Word) -> Vec<Vec<u8>> {
        let key = {
            let mut word_buf = [0u8; 32];
            key.to_big_endian(word_buf.as_mut_slice());
            HexBytes(word_buf)
        };

        self.storages_cache
            .get(&address)
            .map(Clone::clone)
            .or_else(|| {
                self.trie
                    .get_account(address.as_bytes())
                    .map(AccountData::from)
                    .and_then(|account| self.trie.get_db().new_trie(&account.storage_root.0))
            })
            .and_then(|trie| trie.prove(key.as_ref()).ok())
            .unwrap_or_default()
    }
    fn fetch_storage_cache(&mut self, address: Address) -> Option<&mut ZkTrie> {
        let cache_entry = self.storages_cache.entry(address);
        match cache_entry {
            std::collections::hash_map::Entry::Vacant(entry) => {
                let account = self.trie.get_account(address.as_bytes());
                account
                    .map(AccountData::from)
                    .and_then(|acc_data| {
                        // all trie share the same underlay db, so we can create new trie here
                        let zk_db = self.trie.get_db();
                        zk_db.new_trie(&acc_data.storage_root.0)
                    })
                    .map(|trie| entry.insert(trie))
            }
            std::collections::hash_map::Entry::Occupied(entry) => Some(entry.into_mut()),
        }
    }

    fn trace_storage_update(
        &mut self,
        address: Address,
        key: Word,
        new_value: Word,
        old_value: Word,
    ) -> SMTTrace {
        let (storage_key, key) = {
            let mut word_buf = [0u8; 32];
            key.to_big_endian(word_buf.as_mut_slice());
            (hash_zktrie_key(&word_buf), HexBytes(word_buf))
        };

        let trie = if let Some(trie) = self.fetch_storage_cache(address) {
            trie
        } else {
            // Handle corner case where the account doesn't exist at all. In this case we produce an
            // non-existing account proof, but with the state_key field set.
            if new_value.is_zero() {
                let mut trace = self.trace_account_update(address, |_| None);
                trace.state_key = Some(key);
                return trace;
            }
            panic!("invalid trace_storage_update addr {address:?} key {key:?} new_value {new_value:?} old_value {old_value:?}");
        };

        let store_after = {
            let mut word_buf = [0u8; 32];
            new_value.to_big_endian(word_buf.as_mut_slice());
            StateData {
                key,
                value: HexBytes(word_buf),
            }
        };
        let storage_before_proofs = trie.prove(key.as_ref()).unwrap();
        let storage_before = decode_proof_for_mpt_path(storage_key, storage_before_proofs);

        let store_before = {
            let mut word_buf = [0u8; 32];
            old_value.to_big_endian(word_buf.as_mut_slice());
            // sanity check
            let old_value_in_trie = storage_before
                .as_ref()
                .ok()
                .and_then(|(_, nd)| nd.as_ref())
                .and_then(|nd| nd.as_storage())
                .unwrap_or_default();
            assert_eq!(hex::encode(word_buf), hex::encode(old_value_in_trie),
                "for (address {address:?} key {key:?}): old value in proof != old value in partial trie",
            );
            StateData {
                key,
                value: HexBytes(word_buf),
            }
        };

        if !new_value.is_zero() {
            trie.update_store(key.as_ref(), &store_after.value.0)
                .unwrap();
        } else if !old_value.is_zero() {
            trie.delete(key.as_ref());
            if trie.get_store(key.as_ref()).is_some() {
                log::error!("fail to delete key {} in {:?}", key.hex(), address);
            }
        } // notice if the value is both zero we never touch the trie layer

        let storage_root_after = H256(trie.root());
        let storage_after_proofs = trie.prove(key.as_ref()).unwrap();
        let storage_after = decode_proof_for_mpt_path(storage_key, storage_after_proofs);

        // sanity check
        assert_eq!(
            smt_hash_from_bytes(storage_root_after.as_bytes()),
            storage_after
                .as_ref()
                .map(|(p, _)| p.root)
                .unwrap_or(HexBytes([0; 32]))
        );

        let mut out = self.trace_account_update(address, |acc| {
            if let Some(acc) = acc {
                // sanity check
                assert_eq!(
                    smt_hash_from_bytes(acc.storage_root.as_bytes()),
                    storage_before
                        .as_ref()
                        .map(|(p, _)| p.root)
                        .unwrap_or(HexBytes([0; 32]))
                );
                let mut acc = *acc;
                acc.storage_root = storage_root_after;
                Some(acc)
            } else {
                // sanity check
                assert!(old_value.is_zero() && new_value.is_zero());
                None
            }
        });

        out.common_state_root = None; // clear common state root
        out.state_key = Some(smt_hash_from_u256(&storage_key));

        out.state_path = [
            storage_before.map(|(p, _)| p).ok(),
            storage_after.map(|(p, _)| p).ok(),
        ];
        out.state_update = Some([Some(store_before), Some(store_after)]);
        out
    }

    fn trace_account_update<U>(&mut self, address: Address, update_account_data: U) -> SMTTrace
    where
        U: FnOnce(Option<&AccountData>) -> Option<AccountData>,
    {
        let proofs = match self.trie.prove(address.as_bytes()) {
            Ok(proofs) => proofs,
            Err(e) => {
                panic!("cannot prove, addr {address:?}, err{e:?}");
            }
        };

        let address_key = hash_zktrie_key(&extend_address_to_h256(&address));

        let (account_path_before, account_data_before) =
            decode_proof_for_mpt_path(address_key, proofs).expect("unless the db is totally empty");
        let account_data_before = account_data_before
            .and_then(|nd| nd.as_account())
            .map(AccountData::from);

        let account_data_after = update_account_data(account_data_before.as_ref());

        if let Some(account_data_after) = account_data_after {
            let mut nonce_codesize = [0u8; 32];
            let u64factor = U256::from(0x10000000000000000u128);
            (U256::from(account_data_after.code_size) * u64factor
                + U256::from(account_data_after.nonce))
            .to_big_endian(nonce_codesize.as_mut_slice());
            let mut balance = [0u8; 32];
            account_data_after
                .balance
                .to_big_endian(balance.as_mut_slice());
            let mut poseidon_code_hash = [0u8; 32];
            U256::from(account_data_after.poseidon_code_hash.0)
                .to_big_endian(poseidon_code_hash.as_mut_slice());
            let mut code_hash = [0u8; 32];
            U256::from(account_data_after.keccak_code_hash.0)
                .to_big_endian(code_hash.as_mut_slice());

            let acc_data = [
                nonce_codesize,
                balance,
                account_data_after.storage_root.0,
                code_hash,
                poseidon_code_hash,
            ];
            let rs = self.trie.update_account(address.as_bytes(), &acc_data);
            if rs.is_err() {
                log::warn!("invalid update {:?}", rs);
            }

            // self.accounts_cache.insert(address, account_data_after);
            // if account_data_before.is_none() {
            //     self.storages.insert(address, ZkTrie::new());
            // }
        } else if account_data_before.is_some() {
            log::warn!("trace update try delete account {address:?} trie while we have no SELFDESTRUCT yet");
            self.trie.delete(address.as_bytes());
            // self.accounts_cache.remove(&address);
        } // no touch for non-exist proof

        let proofs = self.trie.prove(address.as_bytes()).unwrap();
        let (account_path_after, _) = decode_proof_for_mpt_path(address_key, proofs).unwrap();

        SMTTrace {
            address: HexBytes(address.0),
            account_path: [account_path_before, account_path_after],
            account_update: [
                account_data_before.map(to_smt_account),
                account_data_after.map(to_smt_account),
            ],
            account_key: smt_hash_from_u256(&address_key),
            state_path: [None, None],
            common_state_root: account_data_before
                .map(|data| smt_hash_from_bytes(data.storage_root.as_bytes()))
                .or(Some(HexBytes([0; 32]))),
            state_key: None,
            state_update: None,
        }
    }

    /// check current root
    pub fn root(&self) -> Hash {
        H256::from(self.trie.root())
    }

    /// use one entry in mpt table to build the corresponding mpt operation (via
    /// SMTTrace)
    pub fn handle_new_state(
        &mut self,
        proof_type: MPTProofType,
        address: Address,
        new_val: Word,
        old_val: Word,
        key: Option<Word>,
    ) -> SMTTrace {
        if let Some(key) = key {
            self.trace_storage_update(address, key, new_val, old_val)
        } else {
            self.trace_account_update(address, |acc_before: Option<&AccountData>| {
                let mut acc_data = acc_before.copied().unwrap_or_default();
                match proof_type {
                    MPTProofType::NonceChanged => {
                        assert!(old_val <= u64::MAX.into());
                        // TODO: fix (hypothetical) inconsistency where CREATE gadget allows nonce
                        // to be 1 << 64, but mpt circuit does not support this.
                        assert!(new_val <= Word::from(u64::MAX) + Word::one());
                        assert_eq!(old_val.as_u64(), acc_data.nonce);
                        acc_data.nonce = new_val.as_u64();
                    }
                    MPTProofType::BalanceChanged => {
                        assert_eq!(old_val, acc_data.balance);
                        acc_data.balance = new_val;
                    }
                    MPTProofType::CodeHashExists => {
                        let mut code_hash = [0u8; 32];
                        old_val.to_big_endian(code_hash.as_mut_slice());
                        debug_assert_eq!(H256::from(code_hash), acc_data.keccak_code_hash);
                        new_val.to_big_endian(code_hash.as_mut_slice());
                        acc_data.keccak_code_hash = H256::from(code_hash);
                    }
                    MPTProofType::PoseidonCodeHashExists => {
                        let mut code_hash = [0u8; 32];
                        old_val.to_big_endian(code_hash.as_mut_slice());
                        debug_assert_eq!(H256::from(code_hash), acc_data.poseidon_code_hash);
                        new_val.to_big_endian(code_hash.as_mut_slice());
                        acc_data.poseidon_code_hash = H256::from(code_hash);
                    }
                    MPTProofType::CodeSizeExists => {
                        assert!(old_val < u64::MAX.into());
                        assert!(new_val < u64::MAX.into());
                        // code size can only change from 0
                        debug_assert_eq!(old_val.as_u64(), acc_data.code_size);
                        debug_assert!(
                            old_val.as_u64() == 0u64 || old_val.as_u64() == new_val.as_u64(),
                            "old {old_val:?} new {new_val:?}",
                        );
                        acc_data.code_size = new_val.as_u64();
                    }
                    MPTProofType::AccountDoesNotExist => {
                        // for proof NotExist, the account_before must be empty
                        assert!(acc_before.is_none());
                        assert!(
                            acc_data.balance.is_zero(),
                            "not-exist proof on existed account balance: {address}"
                        );
                        assert_eq!(
                            0, acc_data.nonce,
                            "not-exist proof on existed account nonce: {address}"
                        );
                        assert!(
                            acc_data.storage_root.is_zero(),
                            "not-exist proof on existed account storage: {address}"
                        );
                        return None;
                    }
                    _ => unreachable!("invalid proof type: {:?}", proof_type),
                }
                if acc_data == AccountData::default() {
                    None
                } else {
                    Some(acc_data)
                }
            })
        }
    }
}

fn smt_hash_from_u256(i: &U256) -> SMTHash {
    let mut out: [u8; 32] = [0; 32];
    i.to_little_endian(&mut out);
    HexBytes(out)
}

fn smt_hash_from_bytes(bt: &[u8]) -> SMTHash {
    let mut out: Vec<_> = bt.iter().copied().rev().collect();
    out.resize(32, 0);
    HexBytes(out.try_into().expect("extract size has been set"))
}

fn hash_zktrie_key(key_buf: &[u8; 32]) -> Word {
    use halo2_proofs::halo2curves::bn256::Fr;
    use hash_circuit::hash::Hashable;

    let first_16bytes: [u8; 16] = key_buf[..16].try_into().expect("expect first 16 bytes");
    let last_16bytes: [u8; 16] = key_buf[16..].try_into().expect("expect last 16 bytes");

    let bt_high = Fr::from_u128(u128::from_be_bytes(first_16bytes));
    let bt_low = Fr::from_u128(u128::from_be_bytes(last_16bytes));

    let hash = Fr::hash_with_domain([bt_high, bt_low], Fr::from(SECURE_HASH_DOMAIN));

    U256::from_little_endian(hash.to_repr().as_ref())
}

#[derive(Default)]
struct LeafNode(Option<ZkTrieNode>);

impl fmt::Debug for LeafNode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({:?})", self.0.as_ref().and_then(|n| n.value_hash()),)
    }
}

impl CanRead for LeafNode {
    fn try_parse(mut _rd: impl Read) -> Result<Self, IoError> {
        panic!("this entry is not used")
    }
    fn parse_leaf(data: &[u8]) -> Result<Self, IoError> {
        let node = ZkTrieNode::parse(data).ok();
        // sanity check
        if let Some(node_r) = node.as_ref() {
            assert!(node_r.is_tip(), "the bytes we have parsed must be a leaf");
        }
        Ok(Self(node))
    }
}

fn decode_proof_for_mpt_path(
    mut key: Word,
    proofs: Vec<Vec<u8>>,
) -> Result<(SMTPath, Option<ZkTrieNode>), IoError> {
    let root = if let Some(arr) = proofs.first() {
        let n = ZkTrieNode::parse(arr.as_slice()).expect("wrong proof bytes");
        smt_hash_from_bytes(n.node_hash().as_slice())
    } else {
        HexBytes::<32>([0; 32])
    };

    let expected_key = key;
    let proof_bytes = proofs.iter().map(Vec::as_slice);
    let trie_proof = TrieProof::<LeafNode>::try_from(BytesArray(proof_bytes))?;

    // convert path part
    let mut path_bit_now = BigUint::from(1_u32);
    let mut path_part: BigUint = Default::default();
    let mut path = Vec::new();

    for ((left, right), &node_type) in trie_proof.path.iter().zip(&trie_proof.path_type) {
        let is_bit_one = key.bit(0);
        path.push(if is_bit_one {
            SMTNode {
                node_type,
                value: smt_hash_from_u256(right),
                sibling: smt_hash_from_u256(left),
            }
        } else {
            SMTNode {
                node_type,
                value: smt_hash_from_u256(left),
                sibling: smt_hash_from_u256(right),
            }
        });
        key >>= 1;
        if is_bit_one {
            path_part += &path_bit_now
        };
        path_bit_now *= 2_u32;
    }

    let node = trie_proof.data.0;
    let leaf = trie_proof.key.as_ref().map(|h| SMTNode {
        node_type: trie_proof.key_type.expect("key type should has been set"),
        value: smt_hash_from_bytes(
            &node
                .as_ref()
                .and_then(ZkTrieNode::value_hash)
                .expect("the node must exit and has value hash if we has parsed the node hash"),
        ),
        sibling: smt_hash_from_bytes(h.as_bytes()),
    });

    let node = if trie_proof.key.as_ref().map(ToWord::to_word) == Some(expected_key) {
        node
    } else {
        None
    };

    Ok((
        SMTPath {
            root,
            leaf,
            path,
            path_part,
        },
        node,
    ))
}

use eth_types::Bytes;
use serde::Deserialize;

type AccountTrieProofs = HashMap<Address, Vec<Bytes>>;
type StorageTrieProofs = HashMap<Address, HashMap<Word, Vec<Bytes>>>;

type AccountDatas = HashMap<Address, AccountData>;
type StorageDatas = HashMap<(Address, Word), StorageData>;

#[derive(Deserialize, Default, Debug, Clone)]
struct StorageTrace {
    #[serde(rename = "rootBefore")]
    pub root_before: Hash,
    #[serde(rename = "rootAfter")]
    pub root_after: Hash,
    pub proofs: Option<AccountTrieProofs>,
    #[serde(rename = "storageProofs", default)]
    pub storage_proofs: StorageTrieProofs,
}

#[derive(Deserialize, Default, Debug, Clone)]
struct BlockTrace {
    #[serde(rename = "storageTrace")]
    pub storage_trace: StorageTrace,
}

fn smt_bytes_to_hash(bt: &[u8]) -> [u8; 32] {
    let mut out: Vec<_> = bt.iter().copied().rev().collect();
    out.resize(32, 0);
    out.try_into().expect("extract size has been set")
}

#[test]
fn witgen_init_writer() {
    let (state, _, _) = build_state_from_string(EXAMPLE_TRACE);
    let w = WitnessGenerator::from(&state);

    let root_init = w.root();

    log::info!("root: {root_init:?}");

    assert_eq!(
        format!("{root_init:?}"),
        "0x24c368802ea77a0d8d49d8ccce69cdb7aead98533c77aebbd7605358a592f3aa"
    );
}

#[test]
fn witgen_update_one() {
    use eth_types::U256;
    let (state, accounts, storages) = build_state_from_string(EXAMPLE_TRACE);
    let mut w = WitnessGenerator::from(&state);

    let target_addr = Address::from_slice(
        hex::decode("1C5A77d9FA7eF466951B2F01F724BCa3A5820b63")
            .unwrap()
            .as_slice(),
    );

    let start_state = accounts.get(&target_addr);
    assert!(start_state.is_some(), "we picked an existed account");
    let start_state = start_state.unwrap();

    let trace = w.handle_new_state(
        MPTProofType::BalanceChanged,
        target_addr,
        start_state.balance + U256::from(1_u64),
        start_state.balance,
        None,
    );

    let new_root = w.root();

    let new_acc_root = smt_bytes_to_hash(trace.account_path[1].root.as_ref());
    assert_eq!(new_root.0, new_acc_root);

    log::info!("ret {:?}", trace);

    // create storage slot
    w.handle_new_state(
        MPTProofType::StorageChanged,
        target_addr,
        U256::from(1u32),
        U256::default(),
        Some(U256::zero()),
    );

    let target_addr = Address::from_slice(
        hex::decode("66613A02924ca4171675f3793b4eB3908A480D55")
            .unwrap()
            .as_slice(),
    );

    // check value of storage slot 0 is 10
    assert_eq!(
        Some(U256::from(10u32)),
        storages
            .get(&(target_addr, U256::zero()))
            .map(AsRef::as_ref)
            .copied()
    );

    let trace = w.handle_new_state(
        MPTProofType::StorageChanged,
        target_addr,
        U256::from(11u32),
        U256::from(10u32),
        Some(U256::zero()),
    );

    let new_root = w.root();

    let new_acc_root = smt_bytes_to_hash(trace.account_path[1].root.as_ref());
    assert_eq!(new_root.0, new_acc_root);

    log::info!("ret {:?}", trace);
}

fn build_state_from_string(sample_str: &str) -> (ZktrieState, AccountDatas, StorageDatas) {
    let trace: StorageTrace = serde_json::from_str(sample_str).unwrap();

    let account_traces = trace.proofs.iter().flat_map(|kv_map| {
        kv_map
            .iter()
            .map(|(k, bts)| (k, bts.iter().map(Bytes::as_ref)))
    });

    let storage_traces = trace.storage_proofs.iter().flat_map(|(k, kv_map)| {
        kv_map
            .iter()
            .map(move |(sk, bts)| (k, sk, bts.iter().map(Bytes::as_ref)))
    });

    let account_datas = ZktrieState::parse_account_from_proofs(account_traces.clone())
        .map(|r| r.unwrap())
        .collect::<AccountDatas>();

    let storage_datas = ZktrieState::parse_storage_from_proofs(storage_traces.clone())
        .map(|r| r.unwrap())
        .collect::<StorageDatas>();

    (
        ZktrieState::from_trace_with_additional(
            trace.root_before,
            account_traces,
            storage_traces,
            std::iter::empty(),
        )
        .unwrap(),
        account_datas,
        storage_datas,
    )
}

const EXAMPLE_TRACE: &str = r#"
    {
        "proofs": {
            "0x1C5A77d9FA7eF466951B2F01F724BCa3A5820b63": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x0927fb0f5d23170a387eba5ab2e6d4353fd2ec8ab81022f981548d9acdc07c637a2048ec88c007fbe8be0b597adcb2ce40b5f4581e0cc058d67e8e12528d3e6917",
                "0x0921b2b32fa1ee730a507859d58adc1e3f03eac97c1c38ffd8bd1e5e940233fa1301e6296bc35577d87cbfd3bc018c967217ed782d80e3ac023a5f9266f48e3e0a",
                "0x09257a991b89aa51317b15269eb70790e0803ee6e0d5538b8a47160d7da2a9a0e52e9f943364bcb33bf65e07fc546385a3ad38275445465fd06d258d45da867911",
                "0x082bfe09e985d916d891cefd063e0a4e85cb623b2822d9991960e5976252e0e97f2bf9bb78779eabc2ae7590830e67f163171f978ae7116107d2d092b6d6137599",
                "0x0627fe0e20e21d984acac7defe4fbc7decc711efb1190c2abe0c6205e3701945d7231809d3f2acabf42f8d33b76be108af5914ca497c4ec7d82c8fe9fba181778b",
                "0x041822829dca763241624d1f8dd4cf59018fc5f69931d579f8e8a4c3addd6633e605080000000000000000000000000000000000000000000000000000000000000000002d007fffffffffffffffffffffffffffffffffffffffffc078f7390f013506e29d0000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864201c5a77d9fa7ef466951b2f01f724bca3a5820b63000000000000000000000000",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ],
            "0x5300000000000000000000000000000000000000": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x0927fb0f5d23170a387eba5ab2e6d4353fd2ec8ab81022f981548d9acdc07c637a2048ec88c007fbe8be0b597adcb2ce40b5f4581e0cc058d67e8e12528d3e6917",
                "0x0921b2b32fa1ee730a507859d58adc1e3f03eac97c1c38ffd8bd1e5e940233fa1301e6296bc35577d87cbfd3bc018c967217ed782d80e3ac023a5f9266f48e3e0a",
                "0x09257a991b89aa51317b15269eb70790e0803ee6e0d5538b8a47160d7da2a9a0e52e9f943364bcb33bf65e07fc546385a3ad38275445465fd06d258d45da867911",
                "0x07000000000000000000000000000000000000000000000000000000000000000003b55c8d0d38991f88a85866f2761582f6406e64948c312400a939c2e91f9add",
                "0x05",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ],
            "0x5300000000000000000000000000000000000002": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x091b204534c37ac203794c08e52119dc660abcc864cdb6f2075322915e31b65e551773f6dc1cefdc735b427c9caf30e5a56967fd8e5acc572e67b8e182a741e88e",
                "0x092c931a2e09736360d6db7cc0ba65f0da7023755cc347e4cd06876942f178357429a62ba9ff4ad321a1efc63248664c87e0d0f77669fbe9d33826201d28310f57",
                "0x0810a513bd289b88f45942986cce068223def56384d1b943f9448ed65dfc86c76d301dc3e787d41a3db0710353073f18eaebab31ac37d69e25983caf72f6c08178",
                "0x04139a6815e4d1fb05c969e6a8036aa5cc06b88751d713326d681bd90448ea64c905080000000000000000000000000000000000000000000000000874000000000000000000000000000000000000000000000000000000000000000000000000000000002c3c54d9c8b2d411ccd6458eaea5c644392b097de2ee416f5c923f3b01c7b8b80fabb5b0f58ec2922e2969f4dadb6d1395b49ecd40feff93e01212ae848355d410e77cae1c507f967948c6cd114e74ed65f662e365c7d6993e97f78ce898252800",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ],
            "0x5300000000000000000000000000000000000005": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x091b204534c37ac203794c08e52119dc660abcc864cdb6f2075322915e31b65e551773f6dc1cefdc735b427c9caf30e5a56967fd8e5acc572e67b8e182a741e88e",
                "0x092c931a2e09736360d6db7cc0ba65f0da7023755cc347e4cd06876942f178357429a62ba9ff4ad321a1efc63248664c87e0d0f77669fbe9d33826201d28310f57",
                "0x0810a513bd289b88f45942986cce068223def56384d1b943f9448ed65dfc86c76d301dc3e787d41a3db0710353073f18eaebab31ac37d69e25983caf72f6c08178",
                "0x0700000000000000000000000000000000000000000000000000000000000000002f50fafb9ade43f0863208e700a30a6c38b0f61c71d6b5a8d63b26cea263c304",
                "0x0811a6bc666ad72d376eb65e0a1b89284eadab8c2540f1897a540b06a62d32e608096c33b369382285822d8f0acf8097ca6f095334750a42f869e513c8ec3779a7",
                "0x08261d70525dea5d9a404e59443e7288da6b5e8eb67220ee02b1690708cb211b600000000000000000000000000000000000000000000000000000000000000000",
                "0x0700000000000000000000000000000000000000000000000000000000000000000d5dad10d619a4035d148cbee268b10fdb63e8a690796394c44718c38e542ffa",
                "0x070000000000000000000000000000000000000000000000000000000000000000078947de592c917b37a2fef56798b4c0f6dc88ff90e73c335d0124cc8b2868f2",
                "0x062909a1a348c8f4ba007916d070ebd79bb41550449bb369d43c0fd2349e2e5ca92c2cc500f3d3a26e685bbb70f7a6e10f9df1be5962ae38a04361b8ebf4e7d2a1",
                "0x04287b801ba8950befe82147f88e71eff6b85eb921845d754c9c2a165a4ec8679105080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000944b701a819ff30000000000000000000000000000000000000000000000000000000000000000c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864205300000000000000000000000000000000000005000000000000000000000000",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ],
            "0x66613A02924ca4171675f3793b4eB3908A480D55": [
                "0x0917e72849d9c0d67bb31746101cf4895de34892b24d1486daa024a660abc37d860ddffa0c24af819b6e3c1a8b94699fedcdc77656184edc5a39eb81ca0bed790a",
                "0x0927fb0f5d23170a387eba5ab2e6d4353fd2ec8ab81022f981548d9acdc07c637a2048ec88c007fbe8be0b597adcb2ce40b5f4581e0cc058d67e8e12528d3e6917",
                "0x0921b2b32fa1ee730a507859d58adc1e3f03eac97c1c38ffd8bd1e5e940233fa1301e6296bc35577d87cbfd3bc018c967217ed782d80e3ac023a5f9266f48e3e0a",
                "0x0715c17bf538c62ca0e099396928857a0be6d6dca109eba6c338d62c199410a9bf2fe42431a564bcfd3b464819934c1dca3aa031fd49ed4c7c9724e991dc38ed15",
                "0x08205a520af27de994c9eeef1ab0a6145e1f0f90e59aefdb73a3674484bc6a8d3f2671e331081527a983a7610159b13af138a164596c8280d1553b6578f7759e88",
                "0x04072e5dd3f196958c52140078f2407e11cf80f414c2a3ae3f3bd641c92f7d693a050800000000000000000000000000000000000000000000000000e4000000000000000100000000000000000000000000000000000000000000000000000000000000000d24d8b8043e372c52c8e686ff0998ec5f85e26a5f882c5b9026925a1d23f4fc1f5b06141eb3afb77b6dc6873756a9fdc88f90c2b1937e4b523358664a3f894108cc5fe38e7c93fa53a7f1da1e46529e3e1aff66ef93e078a014794238d5fe332066613a02924ca4171675f3793b4eb3908a480d55000000000000000000000000",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
            ]
            },
        "rootAfter": "0x2a68d57b081310708d5ea3debf78ff0ede609cff7e4e622025379212044b554c",
        "rootBefore": "0x24c368802ea77a0d8d49d8ccce69cdb7aead98533c77aebbd7605358a592f3aa",
        "storageProofs": {
            "0x5300000000000000000000000000000000000000": {
                "0x0000000000000000000000000000000000000000000000000000000000000000": [
                "0x05",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ]
            },
            "0x5300000000000000000000000000000000000002": {
                "0x0000000000000000000000000000000000000000000000000000000000000001": [
                "0x080a639a06ff193b9ab132db86545f81c4539ced774b7c66a710799c0e74aebe0d19c4b6fecc8df35dbeb90e48cc838e8df15c05c37230403e144af7dfd0ad7e6e",
                "0x081c8562edca41192eb53d47f84e6e3e75ef936a5db0204312f1fcc5a6cc8dfd52219f351123d5de3428077892a32046effcf21ea6464f7e154b56171facc664e8",
                "0x08247eaef322d76a2cc5bc3def50b5499b636270811928cf94a9553136d8a12e182c60e31a75eefcdc66dad994396a7e42327a2fd04d5f2628a7efd06bfe288b1b",
                "0x082699b6a24c3e9f728bbf81d8b478a89532f62d7dd90b661a5f593b78c506178c0000000000000000000000000000000000000000000000000000000000000000",
                "0x0700000000000000000000000000000000000000000000000000000000000000002dee0af1874f4020b28b87f4ee0b83e70f37ec0a8431a05e839af1beb84b1c74",
                "0x082b5774df25a3fbd3e4fb8afb512ccdf26f1bee61f068f843ab3de6ca05d1b5d90000000000000000000000000000000000000000000000000000000000000000",
                "0x0700000000000000000000000000000000000000000000000000000000000000002a58476ab614c08bcc7ec1b76a32c1e042ba9c0e7375230151dd8e15e5763cd9",
                "0x082d1480889354a6403a0f8c383b4b3bbbe6c0c04b91ca1cad3889067296301aca0000000000000000000000000000000000000000000000000000000000000000",
                "0x0802437779d2f9307c1740a480612491d5fa678120af3feb0a05a2b1a49f7e31aa0000000000000000000000000000000000000000000000000000000000000000",
                "0x07000000000000000000000000000000000000000000000000000000000000000025779e74373d78c2cb4ba4f274db6c97339d159c64c78ec58acab0dd015aa3dc",
                "0x06117d34d74a18b069a21756f797f9f540dde234c57d1934c46572c46d445ed3331be984c8f0565383e1b3c8716daf78661d65a4707650973cef954e35ab4d09a1",
                "0x0426049ba6de63003492eb078a01a8aa4f4a0e67f28f0955c2eba9101d5d2eea50010100000000000000000000000000000000000000000000000000000000000000000064200000000000000000000000000000000000000000000000000000000000000001",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ],
                "0x0000000000000000000000000000000000000000000000000000000000000002": [
                "0x080a639a06ff193b9ab132db86545f81c4539ced774b7c66a710799c0e74aebe0d19c4b6fecc8df35dbeb90e48cc838e8df15c05c37230403e144af7dfd0ad7e6e",
                "0x081c8562edca41192eb53d47f84e6e3e75ef936a5db0204312f1fcc5a6cc8dfd52219f351123d5de3428077892a32046effcf21ea6464f7e154b56171facc664e8",
                "0x08247eaef322d76a2cc5bc3def50b5499b636270811928cf94a9553136d8a12e182c60e31a75eefcdc66dad994396a7e42327a2fd04d5f2628a7efd06bfe288b1b",
                "0x04020953ad52de135367a1ba2629636216ed5174cce5629d11b5d97fe733f07dcc0101000000000000000000000000000000000000000000000000000000000000000017d4200000000000000000000000000000000000000000000000000000000000000002",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ],
                "0x0000000000000000000000000000000000000000000000000000000000000003": [
                "0x080a639a06ff193b9ab132db86545f81c4539ced774b7c66a710799c0e74aebe0d19c4b6fecc8df35dbeb90e48cc838e8df15c05c37230403e144af7dfd0ad7e6e",
                "0x0406c50541f08911ad149aa545dd3d606f86ee63c751a795c7d57f0d3f85e6bdeb01010000000000000000000000000000000000000000000000000000000000004a42fc80200000000000000000000000000000000000000000000000000000000000000003",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ]
            },
            "0x66613A02924ca4171675f3793b4eB3908A480D55": {
                "0x0000000000000000000000000000000000000000000000000000000000000000": [
                "0x041d3c5f8c36e5da873d45bfa1d2399a572ac77493ec089cbf88a37b9e9442842201010000000000000000000000000000000000000000000000000000000000000000000a200000000000000000000000000000000000000000000000000000000000000000",
                "0x5448495320495320534f4d45204d4147494320425954455320464f5220534d54206d3172525867503278704449"
                ]
            }
        }
    }
    "#;

#[test]
fn deserialize_example() {
    use mpt_zktrie::{AccountProof, StorageProof};
    let s_trace: StorageTrace = serde_json::from_str(EXAMPLE_TRACE).unwrap();
    let proofs = s_trace.proofs.as_ref().unwrap();
    for (_, proof) in proofs.iter() {
        let proof: AccountProof = proof.as_slice().try_into().unwrap();
        log::info!("proof: {:?}", proof);
    }

    for (_, s_map) in s_trace.storage_proofs.iter() {
        for (k, val) in s_map {
            let val_proof: StorageProof = val.as_slice().try_into().unwrap();
            log::info!("k: {}, v: {:?}", k, val_proof);
        }
    }
}
