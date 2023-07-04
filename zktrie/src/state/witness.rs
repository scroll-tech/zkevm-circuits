//! witness generator
use super::{
    builder::{extend_address_to_h256, AccountData, BytesArray, CanRead, TrieProof},
    MPTProofType, ZktrieState,
};
use bus_mapping::{state_db::CodeDB, util::KECCAK_CODE_HASH_ZERO};
use eth_types::{Address, Hash, Word, H256, U256};
use halo2_proofs::halo2curves::group::ff::PrimeField;
use mpt_circuits::serde::{
    AccountData as SMTAccount, Hash as SMTHash, HexBytes, SMTNode, SMTPath, SMTTrace, StateData,
};
use std::collections::HashMap;
use zktrie::{Hash as ZkTrieHash, ZkTrie, ZkTrieNode};

use num_bigint::BigUint;
use std::io::{Error as IoError, Read};

impl From<AccountData> for SMTAccount {
    fn from(acc: AccountData) -> Self {
        let mut balance: [u8; 32] = [0; 32];
        acc.balance.to_big_endian(balance.as_mut_slice());
        let balance = BigUint::from_bytes_be(balance.as_slice());
        let code_hash = BigUint::from_bytes_be(acc.keccak_code_hash.as_bytes());
        let poseidon_code_hash = BigUint::from_bytes_be(acc.poseidon_code_hash.as_bytes());
        let code_size = acc.code_size;

        Self {
            nonce: acc.nonce,
            balance,
            code_hash,
            poseidon_code_hash,
            code_size,
        }
    }
}

/// witness generator for producing SMTTrace
pub struct WitnessGenerator {
    trie: ZkTrie,
    accounts: HashMap<Address, AccountData>,
    storages: HashMap<Address, ZkTrie>,
}

impl From<&ZktrieState> for WitnessGenerator {
    fn from(state: &ZktrieState) -> Self {
        let sdb = &state.sdb;

        let trie = state.zk_db.borrow_mut().new_trie(&state.trie_root).unwrap();

        let accounts: HashMap<_, _> = state
            .accounts
            .iter()
            .map(|(addr, storage_root)| {
                let (existed, acc_data) = sdb.get_account(addr);
                assert!(
                    existed,
                    "expected to be consistented between records in sdb and account root"
                );
                (*addr, acc_data, storage_root)
            })
            // filter out the account data which is empty can provide update applying some
            // convenient
            .filter(|(_, acc_data, _)| !acc_data.is_empty())
            .map(|(addr, acc_data, storage_root)| {
                (
                    addr,
                    AccountData {
                        nonce: acc_data.nonce.as_u64(),
                        balance: acc_data.balance,
                        poseidon_code_hash: acc_data.code_hash,
                        keccak_code_hash: acc_data.keccak_code_hash,
                        code_size: acc_data.code_size.as_u64(),
                        storage_root: H256::from(storage_root),
                    },
                )
            })
            .collect();

        let storages: HashMap<_, _> = state
            .accounts
            .iter()
            .map(|(addr, storage_root)| (*addr, state.zk_db.borrow_mut().new_trie(storage_root)))
            // if an account has no storage slot being touched in execution, they do not need
            // storage trie and would be filter out here
            .filter(|(_, storage_root)| storage_root.is_some())
            .map(|(addr, storage_root)| (addr, storage_root.expect("None has been filtered")))
            .collect();

        Self {
            trie,
            accounts,
            storages,
        }
    }
}

impl WitnessGenerator {
    /// dump inner data for debugging
    pub fn dump(&self) {
        log::info!("account data {:#?}", self.accounts);
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

        // Handle corner case where the account doesn't exist at all. In this case we produce an
        // non-existing account proof, but with the state_key field set.
        if new_value.is_zero() && !self.accounts.contains_key(&address) {
            let mut trace = self.trace_account_update(address, |_| None);
            trace.state_key = Some(key);
            return trace;
        }

        self.storages.entry(address).or_insert_with(|| {
            ZktrieState::default()
                .zk_db
                .borrow_mut()
                .new_trie(&ZkTrieHash::default())
                .unwrap()
        });

        let trie = self.storages.get_mut(&address).unwrap();

        let store_before = {
            let mut word_buf = [0u8; 32];
            old_value.to_big_endian(word_buf.as_mut_slice());
            // sanity check
            let old_value_in_statedb = trie.get_store(key.as_ref()).unwrap_or_default();
            if word_buf != old_value_in_statedb {
                log::error!(
                    "old value in proof {:?} != old value in partial db {:?}",
                    hex::encode(word_buf),
                    hex::encode(old_value_in_statedb)
                );
                log::error!(
                    "address {:?} key {:?} new_value {:?} old_value {:?}",
                    address,
                    key,
                    new_value,
                    old_value
                );
            }
            assert_eq!(word_buf, old_value_in_statedb);
            StateData {
                key,
                value: HexBytes(word_buf),
            }
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
        let storage_before_path = decode_proof_for_mpt_path(storage_key, storage_before_proofs);
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
        let storage_after_path = decode_proof_for_mpt_path(storage_key, storage_after_proofs);

        // sanity check
        assert_eq!(
            smt_hash_from_bytes(storage_root_after.as_bytes()),
            storage_after_path
                .as_ref()
                .map(|p| p.root)
                .unwrap_or(HexBytes([0; 32]))
        );

        let mut out = self.trace_account_update(address, |acc| {
            if let Some(acc) = acc {
                // sanity check
                assert_eq!(
                    smt_hash_from_bytes(acc.storage_root.as_bytes()),
                    storage_before_path
                        .as_ref()
                        .map(|p| p.root)
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

        out.state_path = [storage_before_path.ok(), storage_after_path.ok()];
        out.state_update = Some([Some(store_before), Some(store_after)]);
        out
    }

    fn trace_account_update<U>(&mut self, address: Address, update_account_data: U) -> SMTTrace
    where
        U: FnOnce(Option<&AccountData>) -> Option<AccountData>,
    {
        let account_data_before = self.accounts.get(&address).copied();

        let proofs = self.trie.prove(address.as_bytes()).unwrap();
        let address_key = hash_zktrie_key(&extend_address_to_h256(&address));

        let account_path_before = decode_proof_for_mpt_path(address_key, proofs).unwrap();

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

            self.accounts.insert(address, account_data_after);
            // if account_data_before.is_none() {
            //     self.storages.insert(address, ZkTrie::new());
            // }
        } else if account_data_before.is_some() {
            log::warn!("trace update try delete account {address:?} trie while we have no SELFDESTRUCT yet");
            self.trie.delete(address.as_bytes());
            self.accounts.remove(&address);
        } // no touch for non-exist proof

        let proofs = self.trie.prove(address.as_bytes()).unwrap();
        let account_path_after = decode_proof_for_mpt_path(address_key, proofs).unwrap();

        SMTTrace {
            address: HexBytes(address.0),
            account_path: [account_path_before, account_path_after],
            account_update: [
                account_data_before.map(Into::into),
                account_data_after.map(Into::into),
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
                        if H256::from(code_hash) != acc_data.poseidon_code_hash {
                            if H256::from(code_hash).is_zero()
                                && acc_data.keccak_code_hash == *KECCAK_CODE_HASH_ZERO
                            {
                                log::trace!("codehash 0->keccak(nil)");
                            } else {
                                debug_assert_eq!(H256::from(code_hash), acc_data.keccak_code_hash);
                            }
                        }
                        new_val.to_big_endian(code_hash.as_mut_slice());
                        acc_data.keccak_code_hash = H256::from(code_hash);
                    }
                    MPTProofType::PoseidonCodeHashExists => {
                        let mut code_hash = [0u8; 32];
                        old_val.to_big_endian(code_hash.as_mut_slice());
                        if H256::from(code_hash) != acc_data.poseidon_code_hash {
                            if H256::from(code_hash).is_zero()
                                && acc_data.poseidon_code_hash == CodeDB::empty_code_hash()
                            {
                                log::trace!("codehash 0->poseidon(nil)");
                            } else {
                                debug_assert_eq!(
                                    H256::from(code_hash),
                                    acc_data.poseidon_code_hash
                                );
                            }
                        }
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
    use halo2_proofs::{arithmetic::FieldExt, halo2curves::bn256::Fr};
    use hash_circuit::hash::Hashable;

    let first_16bytes: [u8; 16] = key_buf[..16].try_into().expect("expect first 16 bytes");
    let last_16bytes: [u8; 16] = key_buf[16..].try_into().expect("expect last 16 bytes");

    let bt_high = Fr::from_u128(u128::from_be_bytes(first_16bytes));
    let bt_low = Fr::from_u128(u128::from_be_bytes(last_16bytes));

    let hash = Fr::hash([bt_high, bt_low]);

    U256::from_little_endian(hash.to_repr().as_ref())
}

#[derive(Debug, Default, Clone)]
struct LeafNodeHash(H256);

impl CanRead for LeafNodeHash {
    fn try_parse(mut _rd: impl Read) -> Result<Self, IoError> {
        panic!("this entry is not used")
    }
    fn parse_leaf(data: &[u8]) -> Result<Self, IoError> {
        let node = ZkTrieNode::parse(data);
        Ok(Self(
            node.value_hash()
                .expect("leaf should has value hash")
                .into(),
        ))
    }
}

impl AsRef<[u8]> for LeafNodeHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

fn decode_proof_for_mpt_path(mut key: Word, proofs: Vec<Vec<u8>>) -> Result<SMTPath, IoError> {
    let root = if let Some(arr) = proofs.first() {
        let n = ZkTrieNode::parse(arr.as_slice());
        smt_hash_from_bytes(n.node_hash().as_slice())
    } else {
        HexBytes::<32>([0; 32])
    };

    let proof_bytes = proofs.iter().map(Vec::as_slice);
    let trie_proof = TrieProof::<LeafNodeHash>::try_from(BytesArray(proof_bytes))?;

    // convert path part
    let mut path_bit_now = BigUint::from(1_u32);
    let mut path_part: BigUint = Default::default();
    let mut path = Vec::new();

    for (left, right) in trie_proof.path.iter() {
        let is_bit_one = key.bit(0);
        path.push(if is_bit_one {
            SMTNode {
                value: smt_hash_from_u256(right),
                sibling: smt_hash_from_u256(left),
            }
        } else {
            SMTNode {
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

    let leaf = trie_proof.key.as_ref().map(|h| SMTNode {
        value: smt_hash_from_bytes(trie_proof.data.as_ref()),
        sibling: smt_hash_from_bytes(h.as_bytes()),
    });

    Ok(SMTPath {
        root,
        leaf,
        path,
        path_part,
    })
}
