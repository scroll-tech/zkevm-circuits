use crate::{
    evm_circuit::{util::rlc, witness::Rw},
    table::AccountFieldTag,
    util::Field,
};
use eth_types::{Address, ToLittleEndian, ToScalar, Word, U256};
use halo2_proofs::circuit::Value;
use itertools::Itertools;
use mpt_circuits::{serde::SMTTrace, MPTProofType};
use mpt_zktrie::{state, state::builder::init_hash_scheme};
use serde::{Deserialize, Serialize};
pub use state::ZktrieState;
use std::collections::BTreeMap;

#[cfg(test)]
mod test;
mod witness;
use witness::WitnessGenerator;

/// Used to store withdraw proof
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawProof {
    /// state root after a block
    pub state_root: U256,
    /// account proof for withdraw bridge contract
    pub account_proof: Vec<Vec<u8>>,
    /// storage proof for withdraw bridge contract, withdraw root storage key
    pub storage_proof: Vec<Vec<u8>>,
}

/// An MPT update whose validity is proved by the MptCircuit
#[derive(Debug, Clone, PartialEq)]
pub struct MptUpdate {
    key: Key,
    old_value: Word,
    new_value: Word,
    old_root: Word,
    new_root: Word,
    // for debugging
    #[cfg(debug_assertions)]
    original_rws: Vec<Rw>,
}

impl MptUpdate {
    fn from_rows(
        key: Key,
        rows: Vec<Rw>,
        offset: usize,
        total_lens: usize,
        old_root: Word,
        new_root: Word,
    ) -> (Key, Self) {
        let first = &rows[0];
        let last = rows.iter().last().unwrap_or(first);
        let key_exists = key;
        let key = key.set_non_exists(value_prev(first), value(last));
        (
            key_exists,
            MptUpdate {
                key,
                old_root: Word::from(offset as u64) + old_root,
                new_root: if offset + 1 == total_lens {
                    new_root
                } else {
                    Word::from(offset as u64 + 1) + old_root
                },
                old_value: value_prev(first),
                new_value: value(last),
                #[cfg(debug_assertions)]
                original_rws: rows,
            },
        )
    }
}

// just for convenience
impl Default for MptUpdate {
    fn default() -> Self {
        Self {
            key: Key::Account {
                address: Address::zero(),
                field_tag: AccountFieldTag::Nonce,
            },
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            #[cfg(debug_assertions)]
            original_rws: Vec::new(),
        }
    }
}

/// All the MPT updates in the MptCircuit, accessible by their key
#[derive(Default, Clone, Debug)]
pub struct MptUpdates {
    old_root: Word,
    new_root: Word,
    updates: BTreeMap<Key, MptUpdate>,
    /// TODO: is here the best place for this?
    /// Withdraw proof after this block
    pub withdraw_proof: WithdrawProof,
    /// The detailed mpt witness
    pub smt_traces: Vec<SMTTrace>,
    pub(crate) proof_types: Vec<MPTProofType>,
}

/// The field element encoding of an MPT update, which is used by the MptTable
#[derive(Debug, Clone, Copy)]
pub struct MptUpdateRow<F>(pub(crate) [F; 7]);

impl MptUpdates {
    pub(crate) fn len(&self) -> usize {
        self.updates.len()
    }

    pub(crate) fn old_root(&self) -> Word {
        self.old_root
    }

    pub(crate) fn new_root(&self) -> Word {
        self.new_root
    }

    pub(crate) fn get(&self, row: &Rw) -> Option<MptUpdate> {
        key(row).map(|key| {
            self.updates
                .get(&key)
                .expect("missing key in mpt updates")
                .clone()
        })
    }

    /// initialize a mock witness generator that is consistent with the old values of self.updates
    pub(crate) fn mock_fill_state_roots(&mut self) {
        init_hash_scheme();
        let temp_trie = ZktrieState::default();
        let mut wit_gen = WitnessGenerator::from(&temp_trie);
        let mut storage_touched = std::collections::HashSet::<(&Address, &Word)>::new();
        for (key, update) in &mut self.updates {
            // we should only handle the storage key occur for the first time
            if let Key::AccountStorage {
                storage_key,
                address,
                ..
            } = key
            {
                if !storage_touched.insert((address, storage_key)) {
                    continue;
                }
            }
            let key = key.set_non_exists(Word::zero(), update.old_value);
            wit_gen.handle_new_state(
                update.proof_type(),
                match key {
                    Key::Account { address, .. } | Key::AccountStorage { address, .. } => address,
                },
                update.old_value,
                Word::zero(),
                match key {
                    Key::Account { .. } => None,
                    Key::AccountStorage { storage_key, .. } => Some(storage_key),
                },
            );
        }
        self.old_root = U256::from_big_endian(wit_gen.root().as_bytes());
        self.fill_state_roots_from_generator(wit_gen);
        log::debug!("mocking fill_state_roots done");
        self.pretty_print();
    }

    pub(crate) fn fill_state_roots(&mut self, init_trie: &ZktrieState) {
        let root_pair = (self.old_root, self.new_root);
        self.old_root = U256::from_big_endian(init_trie.root());
        log::trace!("fill_state_roots init {:?}", init_trie.root());

        let wit_gen = WitnessGenerator::from(init_trie);
        let wit_gen = self.fill_state_roots_from_generator(wit_gen);

        let root_pair2 = (self.old_root, self.new_root);
        if root_pair2 != root_pair {
            log::error!(
                "roots non consistent ({:#x},{:#x}) vs ({:#x},{:#x})",
                root_pair.0,
                root_pair.1,
                root_pair2.0,
                root_pair2.1
            );
            wit_gen.dump(
                self.updates
                    .iter()
                    .group_by(|(k, _)| match k {
                        Key::Account { address, .. } | Key::AccountStorage { address, .. } => {
                            address
                        }
                    })
                    .into_iter()
                    .map(|(addr, _)| addr),
            );
        } else {
            log::debug!("roots consistent ({:#x},{:#x})", root_pair.0, root_pair.1);
        }

        let gen_withdraw_proof = false;
        if gen_withdraw_proof {
            // generate withdraw proof
            let address = *bus_mapping::l2_predeployed::message_queue::ADDRESS;
            let key = bus_mapping::l2_predeployed::message_queue::WITHDRAW_TRIE_ROOT_SLOT;
            let account_proof = wit_gen.account_proof(address);
            let storage_proof = wit_gen.storage_proof(address, key);
            // TODO: add withdraw_root to WithdrawProof?
            let withdraw_proof = WithdrawProof {
                state_root: self.new_root,
                account_proof,
                storage_proof,
            };
            log::debug!("withdraw proof {withdraw_proof:?}");
            self.withdraw_proof = withdraw_proof;
        }
        log::debug!("fill_state_roots done");
        self.pretty_print();
    }

    fn fill_state_roots_from_generator(
        &mut self,
        mut wit_gen: WitnessGenerator,
    ) -> WitnessGenerator {
        self.smt_traces = Vec::new();
        self.proof_types = Vec::new();

        for (key, update) in &mut self.updates {
            log::trace!("apply update {:?} {:#?}", key, update);
            let key = key.set_non_exists(update.old_value, update.new_value);
            let proof_tip = update.proof_type();
            let smt_trace = wit_gen.handle_new_state(
                proof_tip,
                match key {
                    Key::Account { address, .. } | Key::AccountStorage { address, .. } => address,
                },
                update.new_value,
                update.old_value,
                match key {
                    Key::Account { .. } => None,
                    Key::AccountStorage { storage_key, .. } => Some(storage_key),
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
            "mpt update roots (after zktrie) {:#x} {:#x}",
            self.old_root,
            self.new_root
        );

        wit_gen
    }

    pub(crate) fn mock_from(rows: &[Rw]) -> Self {
        Self::from_rws_with_mock_state_roots(rows, 0xcafeu64.into(), 0xdeadbeefu64.into())
    }

    pub(crate) fn from_unsorted_rws_with_mock_state_roots(
        rows: &[Rw],
        old_root: U256,
        new_root: U256,
    ) -> Self {
        log::debug!("mpt update roots (mocking) {:?} {:?}", old_root, new_root);
        let rows_len = rows.len();
        let mut updates: BTreeMap<_, Vec<_>> = BTreeMap::new(); // TODO: preallocate
        for (key, row) in rows.iter().filter_map(|row| key(row).map(|key| (key, row))) {
            updates.entry(key).or_default().push(*row); // TODO: preallocate
        }
        let updates: BTreeMap<_, _> = updates
            .into_iter()
            .enumerate()
            .map(|(i, (key, rows))| {
                MptUpdate::from_rows(key, rows, i, rows_len, old_root, new_root)
            })
            .collect();
        let mpt_updates = MptUpdates {
            old_root,
            new_root,
            updates,
            ..Default::default()
        };
        // FIXME: we can remove this assert after the code runs a while and everything is ok?
        #[cfg(debug_assertions)]
        {
            let mut rows = rows.to_vec();
            rows.sort_by_key(Rw::as_key);
            let old_updates = Self::from_rws_with_mock_state_roots(&rows, old_root, new_root);
            assert_eq!(old_updates.updates, mpt_updates.updates);
        }
        mpt_updates
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
            .map(|(i, (key, rows))| {
                let rows: Vec<Rw> = rows.copied().collect_vec();
                MptUpdate::from_rows(key, rows, i, rows_len, old_root, new_root)
            })
            .collect();
        MptUpdates {
            old_root,
            new_root,
            updates,
            ..Default::default()
        }
    }

    pub(crate) fn table_assignments<F: Field>(
        &self,
        randomness: Value<F>,
    ) -> Vec<MptUpdateRow<Value<F>>> {
        self.updates
            .values()
            .map(|update| update.table_assignments(randomness))
            .collect()
    }

    fn insert(&mut self, update: MptUpdate) {
        self.updates.insert(update.key, update);
    }

    pub(crate) fn pretty_print(&self) {
        for (idx, update) in self.updates.values().enumerate() {
            log::trace!("mpt_update {idx} {update:?}");
        }
    }
}

impl MptUpdate {
    pub(crate) fn values(&self) -> (Word, Word) {
        (self.new_value, self.old_value)
    }

    pub(crate) fn value_assignments<F: Field>(&self, word_randomness: F) -> (F, F) {
        let assign = |x: Word| match self.key {
            Key::Account {
                field_tag: AccountFieldTag::CodeHash,
                ..
            } => {
                if cfg!(feature = "poseidon-codehash") {
                    x.to_scalar().unwrap()
                } else {
                    rlc::value(&x.to_le_bytes(), word_randomness)
                }
            }
            Key::Account {
                field_tag:
                    AccountFieldTag::Nonce | AccountFieldTag::NonExisting | AccountFieldTag::CodeSize,
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

    pub(crate) fn table_assignments<F: Field>(
        &self,
        randomness: Value<F>,
    ) -> MptUpdateRow<Value<F>> {
        let (new_root, old_root) = randomness
            .map(|randomness| self.root_assignments(randomness))
            .unzip();
        let (new_value, old_value) = randomness
            .map(|randomness| self.value_assignments(randomness))
            .unzip();
        MptUpdateRow([
            Value::known(self.key.address()),
            randomness.map(|randomness| self.key.storage_key(randomness)),
            Value::known(F::from(self.proof_type() as u64)),
            new_root,
            old_root,
            new_value,
            old_value,
        ])
    }
    fn proof_type(&self) -> MPTProofType {
        match self.key {
            Key::AccountStorage { .. } => {
                if self.old_value.is_zero() && self.new_value.is_zero() {
                    MPTProofType::StorageDoesNotExist
                } else {
                    MPTProofType::StorageChanged
                }
            }
            Key::Account { field_tag, .. } => {
                if matches!(field_tag, AccountFieldTag::CodeHash)
                    && self.old_value.is_zero()
                    && self.new_value.is_zero()
                {
                    MPTProofType::AccountDoesNotExist
                } else {
                    field_tag.into()
                }
            }
        }
    }
}

#[derive(Eq, PartialEq, Hash, Clone, Debug, Copy, PartialOrd, Ord)]
enum Key {
    Account {
        address: Address,
        field_tag: AccountFieldTag,
    },
    AccountStorage {
        tx_id: usize,
        address: Address,
        storage_key: Word,
        exists: bool,
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

impl<F: Field> MptUpdateRow<Value<F>> {
    /// Corresponds to the padding row the mpt circuit uses to fill its columns.
    pub fn padding() -> Self {
        let mut values = [F::zero(); 7];
        values[2] = F::from(MPTProofType::AccountDoesNotExist as u64);
        Self(values.map(Value::known))
    }

    /// The individual values of the row, in the column order used by the
    /// MptTable
    pub fn values(&self) -> impl Iterator<Item = &Value<F>> {
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
