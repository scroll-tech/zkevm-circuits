use crate::evm_circuit::util::rlc;
use crate::evm_circuit::witness::Rw;
use crate::table::{AccountFieldTag, ProofType};
use eth_types::{Address, Field, ToLittleEndian, ToScalar, Word, U256};
use halo2_proofs::circuit::Value;
use itertools::Itertools;
use mpt_zktrie::state::witness::WitnessGenerator;
use mpt_zktrie::{serde::SMTTrace, state, MPTProofType};
use std::collections::BTreeMap;

pub use state::ZktrieState;

/// An MPT update whose validity is proved by the MptCircuit
#[derive(Debug, Clone, Copy)]
pub struct MptUpdate {
    key: Key,
    old_value: Word,
    new_value: Word,
    old_root: Word,
    new_root: Word,
}

impl MptUpdate {
    fn proof_type(&self) -> ProofType {
        match self.key {
            Key::AccountStorage { .. } => {
                if self.old_value.is_zero() && self.new_value.is_zero() {
                    ProofType::StorageDoesNotExist
                } else {
                    ProofType::StorageChanged
                }
            }
            Key::Account { field_tag, .. } => field_tag.into(),
        }
    }
}

/// All the MPT updates in the MptCircuit, accessible by their key
#[derive(Default, Clone, Debug)]
pub struct MptUpdates {
    old_root: Word,
    new_root: Word,
    updates: BTreeMap<Key, MptUpdate>,
    pub(crate) smt_traces: Vec<SMTTrace>,
    pub(crate) proof_types: Vec<MPTProofType>,
}

/// The field element encoding of an MPT update, which is used by the MptTable
#[derive(Debug, Clone, Copy)]
pub struct MptUpdateRow<F>(pub(crate) [F; 7]);

impl MptUpdates {
    pub(crate) fn old_root(&self) -> Word {
        self.old_root
    }

    pub(crate) fn new_root(&self) -> Word {
        self.new_root
    }

    pub(crate) fn get(&self, row: &Rw) -> Option<MptUpdate> {
        key(row).map(|key| *self.updates.get(&key).expect("missing key in mpt updates"))
    }

    pub(crate) fn fill_state_roots(&mut self, init_trie: &ZktrieState) {
        let root_pair = (self.old_root, self.new_root);
        self.old_root = U256::from_big_endian(init_trie.root());
        log::trace!("fill_state_roots init {:?}", init_trie.root());

        let mut wit_gen = WitnessGenerator::from(init_trie);
        self.smt_traces = Vec::new();
        self.proof_types = Vec::new();

        for (key, update) in &mut self.updates {
            log::trace!("apply update {:?} {:?}", key, update);
            let proof_tip = state::as_proof_type(update.proof_type() as i32);
            let smt_trace = wit_gen.handle_new_state(
                proof_tip,
                match key {
                    Key::Account { address, .. } | Key::AccountStorage { address, .. } => *address,
                },
                update.new_value,
                update.old_value,
                match key {
                    Key::Account { .. } => None,
                    Key::AccountStorage { storage_key, .. } => Some(*storage_key),
                },
            );
            log::trace!(
                "fill_state_roots {:?}->{:?}",
                smt_trace.account_path[0].root,
                smt_trace.account_path[1].root
            );
            update.old_root = U256::from_little_endian(smt_trace.account_path[0].root.as_ref());
            update.new_root = U256::from_little_endian(smt_trace.account_path[1].root.as_ref());
            self.new_root = update.new_root;
            self.smt_traces.push(smt_trace);
            self.proof_types.push(proof_tip);
        }
        log::debug!(
            "mpt update roots (after zktrie) {:?} {:?}",
            self.old_root,
            self.new_root
        );
        let root_pair2 = (self.old_root, self.new_root);
        if root_pair2 != root_pair {
            log::error!("roots non consistent {:?} vs {:?}", root_pair, root_pair2);
        }
    }

    pub(crate) fn from_rws_with_mock_state_roots(
        rows: &[Rw],
        old_root: U256,
        new_root: U256,
    ) -> Self {
        log::debug!("mpt update roots (mocking) {:?} {:?}", old_root, new_root);
        let rows_len = rows.len();
        let updates: BTreeMap<_, _> = rows
            .iter()
            .group_by(|row| key(row))
            .into_iter()
            .filter_map(|(key, rows)| key.map(|key| (key, rows)))
            .enumerate()
            .map(|(i, (key, mut rows))| {
                let first = rows.next().unwrap();
                let last = rows.last().unwrap_or(first);
                let key_exists = key;
                let key = key.set_non_exists(value_prev(first), value(last));
                (
                    key_exists,
                    MptUpdate {
                        key,
                        old_root: Word::from(i as u64) + old_root,
                        new_root: if i + 1 == rows_len {
                            new_root
                        } else {
                            Word::from(i as u64 + 1) + old_root
                        },
                        old_value: value_prev(first),
                        new_value: value(last),
                    },
                )
            })
            .collect();
        MptUpdates {
            updates,
            old_root,
            new_root,
            ..Default::default()
        }
    }

    pub(crate) fn table_assignments<F: Field>(
        &self,
        randomness: Value<F>,
    ) -> Vec<MptUpdateRow<Value<F>>> {
        self.updates
            .values()
            .map(|update| {
                let (new_root, old_root) = randomness
                    .map(|randomness| update.root_assignments(randomness))
                    .unzip();
                let (new_value, old_value) = randomness
                    .map(|randomness| update.value_assignments(randomness))
                    .unzip();
                MptUpdateRow([
                    Value::known(update.key.address()),
                    randomness.map(|randomness| update.key.storage_key(randomness)),
                    Value::known(F::from(update.proof_type() as u64)),
                    new_root,
                    old_root,
                    new_value,
                    old_value,
                ])
            })
            .collect()
    }
}

impl MptUpdate {
    pub(crate) fn value_assignments<F: Field>(&self, word_randomness: F) -> (F, F) {
        let assign = |x: Word| match self.key {
            Key::Account {
                field_tag: AccountFieldTag::Nonce | AccountFieldTag::NonExisting,
                ..
            } => x.to_scalar().unwrap(),
            _ => rlc::value(&x.to_le_bytes(), word_randomness),
        };

        (assign(self.new_value), assign(self.old_value))
    }

    pub(crate) fn root_assignments<F: Field>(&self, word_randomness: F) -> (F, F) {
        (
            rlc::value(&self.new_root.to_le_bytes(), word_randomness),
            rlc::value(&self.old_root.to_le_bytes(), word_randomness),
        )
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug, Copy, PartialOrd, Ord)]
enum Key {
    AccountStorage {
        tx_id: usize,
        address: Address,
        storage_key: Word,
        exists: bool,
    },
    Account {
        address: Address,
        field_tag: AccountFieldTag,
    },
}

impl Key {
    // If the transition is Storage 0 -> 0, set the key as non-existing storage.
    // If the transition is CodeHash 0 -> 0, set the key as non-existing account.
    // Otherwise return the key unmodified.
    fn set_non_exists(self, value_prev: Word, value: Word) -> Self {
        if value_prev.is_zero() && value.is_zero() {
            match self {
                Key::Account { address, field_tag } => {
                    if matches!(field_tag, AccountFieldTag::CodeHash) {
                        Key::Account {
                            address,
                            field_tag: AccountFieldTag::NonExisting,
                        }
                    } else {
                        self
                    }
                }
                Key::AccountStorage {
                    tx_id,
                    address,
                    storage_key,
                    ..
                } => Key::AccountStorage {
                    tx_id,
                    address,
                    storage_key,
                    exists: false,
                },
            }
        } else {
            self
        }
    }
    fn address<F: Field>(&self) -> F {
        match self {
            Self::Account { address, .. } | Self::AccountStorage { address, .. } => {
                address.to_scalar().unwrap()
            }
        }
    }
    fn storage_key<F: Field>(&self, randomness: F) -> F {
        match self {
            Self::Account { .. } => F::zero(),
            Self::AccountStorage { storage_key, .. } => {
                rlc::value(&storage_key.to_le_bytes(), randomness)
            }
        }
    }
}

impl<F> MptUpdateRow<F> {
    /// The individual values of the row, in the column order used by the
    /// MptTable
    pub fn values(&self) -> impl Iterator<Item = &F> {
        self.0.iter()
    }
}

fn key(row: &Rw) -> Option<Key> {
    match row {
        Rw::Account {
            account_address,
            field_tag,
            ..
        } => Some(Key::Account {
            address: *account_address,
            field_tag: *field_tag,
        }),
        Rw::AccountStorage {
            tx_id,
            account_address,
            storage_key,
            ..
        } => Some(Key::AccountStorage {
            tx_id: *tx_id,
            address: *account_address,
            storage_key: *storage_key,
            exists: true,
        }),
        _ => None,
    }
}

fn value(row: &Rw) -> Word {
    match row {
        Rw::Account { value, .. } => *value,
        Rw::AccountStorage { value, .. } => *value,
        _ => unreachable!(),
    }
}

fn value_prev(row: &Rw) -> Word {
    match row {
        Rw::Account { value_prev, .. } => *value_prev,
        Rw::AccountStorage { value_prev, .. } => *value_prev,
        _ => unreachable!(),
    }
}
