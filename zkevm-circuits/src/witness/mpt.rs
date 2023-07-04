use crate::{
    evm_circuit::{util::rlc, witness::Rw},
    table::AccountFieldTag,
};
use eth_types::{Address, Field, ToLittleEndian, ToScalar, Word, U256};
use halo2_proofs::circuit::Value;
use itertools::Itertools;
use mpt_zktrie::{
    mpt_circuits::{serde::SMTTrace, MPTProofType},
    state,
    state::witness::WitnessGenerator,
};
use std::collections::BTreeMap;

pub use state::ZktrieState;

/// An MPT update whose validity is proved by the MptCircuit
#[derive(Debug, Clone)]
pub struct MptUpdate {
    key: Key,
    old_value: Word,
    new_value: Word,
    old_root: Word,
    new_root: Word,
    // for debugging
    original_rws: Vec<Rw>,
}

impl MptUpdate {
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
        key(row).map(|key| {
            self.updates
                .get(&key)
                .expect("missing key in mpt updates")
                .clone()
        })
    }

    pub(crate) fn mock_fill_state_roots(&mut self) {
        // initialize a mock witness generator that is consistent with the old values of
        // self.updates
        let mut wit_gen = WitnessGenerator::from(&ZktrieState::default());
        for (key, update) in &mut self.updates {
            let key = key.set_non_exists(Word::zero(), update.old_value);
            self.old_root = U256::from_little_endian(
                wit_gen
                    .handle_new_state(
                        update.proof_type(),
                        match key {
                            Key::Account { address, .. } | Key::AccountStorage { address, .. } => {
                                address
                            }
                        },
                        update.old_value,
                        Word::zero(),
                        match key {
                            Key::Account { .. } => None,
                            Key::AccountStorage { storage_key, .. } => Some(storage_key),
                        },
                    )
                    .account_path[1]
                    .root
                    .as_ref(),
            );
        }
        self.fill_state_roots_from_generator(wit_gen);
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
            wit_gen.dump();
        }
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
                let first = &rows[0];
                let last = rows.iter().last().unwrap_or(first);
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
                        original_rws: rows,
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

    fn insert(&mut self, update: MptUpdate) {
        self.updates.insert(update.key, update);
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

#[cfg(test)]
mod test {
    use super::*;
    use mpt_zktrie::state::builder::HASH_SCHEME_DONE;

    #[test]
    fn invalid_state_from_reading_nonce() {
        assert!(*HASH_SCHEME_DONE,);

        let key = Key::Account {
            address: Address::zero(),
            field_tag: AccountFieldTag::Nonce,
        };
        let update = MptUpdate {
            key,
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::one(),
            original_rws: Default::default(),
        };

        let mut updates = MptUpdates::default();
        updates.updates.insert(key, update);

        updates.fill_state_roots(&ZktrieState::default());
    }

    #[test]
    fn invalid_state_from_reading_balance() {
        assert!(*HASH_SCHEME_DONE,);

        let key = Key::Account {
            address: Address::zero(),
            field_tag: AccountFieldTag::Balance,
        };
        let update = MptUpdate {
            key,
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::one(),
            original_rws: Default::default(),
        };

        let mut updates = MptUpdates::default();
        updates.updates.insert(key, update);

        updates.fill_state_roots(&ZktrieState::default());
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces[0]).unwrap()
        );
    }

    fn nonce_update(address: Address) -> MptUpdate {
        MptUpdate {
            key: Key::Account {
                address,
                field_tag: AccountFieldTag::Nonce,
            },
            old_value: Word::zero(),
            new_value: Word::one(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        }
    }

    #[test]
    fn nonce_update_existing() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 4..6u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        updates.insert(nonce_update(Address::repeat_byte(45)));
        let generator = updates
            .fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

        let mut updates = MptUpdates::default();
        let mut update = nonce_update(Address::repeat_byte(45));
        update.old_value = Word::one();
        update.new_value = Word::from(213);
        updates.insert(update);

        updates.fill_state_roots_from_generator(generator);
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn nonexisting_type_1() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 4..6u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        // The key of this address has the same first byte as the key of Address::zero();
        let mut address = Address::zero();
        address.0[1] = 202;

        updates.insert(MptUpdate {
            key: Key::Account {
                address,
                field_tag: AccountFieldTag::NonExisting,
            },
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots(&ZktrieState::default());
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn nonce_update_type_1() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 4..6u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        updates.insert(nonce_update(Address::zero()));

        // The key of this address has the same first byte as the key of Address::zero();
        let mut address = Address::zero();
        address.0[1] = 202;
        updates.insert(nonce_update(address));

        updates.fill_state_roots(&ZktrieState::default());
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn nonce_update_type_2() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        updates.insert(nonce_update(Address::zero()));

        // The key of this address has the same first byte as the key of Address::zero();
        let mut address = Address::zero();
        address.0[1] = 202;
        updates.insert(nonce_update(address));

        // This address is type 2 empty in the MPT containing the above two addresses.
        updates.insert(nonce_update(Address::repeat_byte(0x45)));

        updates.fill_state_roots(&ZktrieState::default());
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    fn balance_update(address: Address) -> MptUpdate {
        MptUpdate {
            key: Key::Account {
                address,
                field_tag: AccountFieldTag::Balance,
            },
            old_value: Word::zero(),
            new_value: Word::from(u64::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        }
    }

    #[test]
    fn balance_update_existing() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 4..6u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        updates.insert(balance_update(Address::repeat_byte(45)));
        let generator = updates
            .fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

        let mut updates = MptUpdates::default();
        let mut update = balance_update(Address::repeat_byte(45));
        update.old_value = Word::from(u64::MAX);
        update.new_value = Word::from(u64::MAX - (1 << 50));
        updates.insert(update);

        updates.fill_state_roots_from_generator(generator);
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn balance_update_type_1() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 4..6u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        updates.insert(nonce_update(Address::zero()));

        // The key of this address has the same first byte as the key of Address::zero();
        let mut address = Address::zero();
        address.0[1] = 202;
        updates.insert(balance_update(address));

        updates.fill_state_roots(&ZktrieState::default());
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn balance_update_type_2() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        updates.insert(nonce_update(Address::zero()));

        // The key of this address has the same first byte as the key of Address::zero();
        let mut address = Address::zero();
        address.0[1] = 202;
        updates.insert(nonce_update(address));

        // This address is type 2 empty in the MPT containing the above two addresses.
        updates.insert(balance_update(Address::repeat_byte(0x45)));

        updates.fill_state_roots(&ZktrieState::default());
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn update_code_size_existing() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 4..6u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::repeat_byte(45);
        updates.insert(nonce_update(address));

        let generator = updates
            .fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

        let mut updates = MptUpdates::default();
        let update = MptUpdate {
            key: Key::Account {
                address,
                field_tag: AccountFieldTag::CodeSize,
            },
            old_value: Word::zero(),
            new_value: Word::from(23412341231u64),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        };
        updates.insert(update);

        updates.fill_state_roots_from_generator(generator);
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn update_code_hash_existing() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 4..6u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::repeat_byte(45);
        updates.insert(nonce_update(address));

        let generator = updates
            .fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

        let mut updates = MptUpdates::default();
        let update = MptUpdate {
            key: Key::Account {
                address,
                field_tag: AccountFieldTag::CodeHash,
            },
            old_value: Word::zero(),
            new_value: Word::from(234123124231231u64),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        };
        updates.insert(update);

        updates.fill_state_roots_from_generator(generator);
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn update_keccak_code_hash_existing() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 4..6u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::repeat_byte(45);
        updates.insert(nonce_update(address));

        let generator = updates
            .fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

        let mut updates = MptUpdates::default();
        let update = MptUpdate {
            key: Key::Account {
                address,
                field_tag: AccountFieldTag::KeccakCodeHash,
            },
            old_value: Word::zero(),
            new_value: U256([u64::MAX; 4]),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        };
        updates.insert(update);

        updates.fill_state_roots_from_generator(generator);
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    // Every (existing, type 1, type 2) x (existing, type 1, type 2) combination is possible
    // except for type 1 -> type 2 and type 2 -> type 1
    #[test]
    fn update_storage_existing_to_existing() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..20u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        for i in 0..100 {
            updates.insert(MptUpdate {
                key: Key::AccountStorage {
                    address,
                    tx_id: 0,
                    exists: false, // true causes an unwraprror?  nope....
                    storage_key: Word::from(i),
                },
                old_value: Word::zero(),
                new_value: Word::from(u32::MAX),
                old_root: Word::zero(),
                new_root: Word::zero(),
                original_rws: Default::default(),
            });
        }
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::from(2431230),
            },
            old_value: Word::zero(),
            new_value: Word::from(u32::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::from(2431230),
            },
            old_value: Word::from(u32::MAX),
            new_value: Word::MAX - Word::from(u64::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn update_storage_type_1_to_type_1() {
        assert!(*HASH_SCHEME_DONE);
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::from(2431230),
            },
            old_value: Word::zero(),
            new_value: Word::from(u32::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::from(2431230),
            },
            old_value: Word::from(u32::MAX),
            new_value: Word::from(24),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::from(2431230),
            },
            old_value: Word::zero(),
            new_value: Word::from(u32::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::from(2431230),
            },
            old_value: Word::from(u32::MAX),
            new_value: Word::from(24),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn update_storage_type_2_to_type_2() {
        assert!(*HASH_SCHEME_DONE);
    }

    #[test]
    fn update_storage_type_1_to_existing() {
        assert!(*HASH_SCHEME_DONE);
    }

    #[test]
    fn update_storage_type_2_to_existing() {
        assert!(*HASH_SCHEME_DONE);
    }

    #[test]
    fn update_storage_existing_to_type_1() {
        assert!(*HASH_SCHEME_DONE);
    }

    #[test]
    fn update_storage_existing_to_type_2() {
        assert!(*HASH_SCHEME_DONE);
    }

    #[test]
    fn read_storage_type_1() {
        assert!(*HASH_SCHEME_DONE);
    }

    #[test]
    fn read_storage_type_2() {
        assert!(*HASH_SCHEME_DONE);
    }

    #[test]
    fn read_empty_storage_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        let update = MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::from(u64::MAX),
            },
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        };
        updates.insert(update);

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn write_empty_storage_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        let update = MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::MAX,
            },
            old_value: Word::zero(),
            new_value: Word::from(u32::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        };
        updates.insert(update);

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn read_singleton_storage_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::MAX - Word::from(43),
            },
            old_value: Word::zero(),
            new_value: Word::from(u32::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::MAX,
            },
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn write_singleton_storage_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::MAX - Word::from(43),
            },
            old_value: Word::zero(),
            new_value: Word::from(u32::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false, // true causes an unwraprror?  nope....
                storage_key: Word::MAX,
            },
            old_value: Word::zero(),
            new_value: Word::one(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn write_zero_to_singleton_storage_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false,
                storage_key: Word::MAX - Word::from(43),
            },
            old_value: Word::zero(),
            new_value: Word::from(u32::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: true,
                storage_key: Word::MAX - Word::from(43),
            },
            old_value: Word::from(u32::MAX),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn write_zero_to_doubleton_storage_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false,
                storage_key: Word::MAX - Word::from(43),
            },
            old_value: Word::zero(),
            new_value: Word::MAX - Word::from(43),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false,
                storage_key: Word::MAX - Word::from(12312),
            },
            old_value: Word::zero(),
            new_value: Word::from(u64::MAX),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: true,
                storage_key: Word::MAX - Word::from(43),
            },
            old_value: Word::MAX - Word::from(43),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn write_zero_to_storage_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        for i in 0..100u64 {
            updates.insert(MptUpdate {
                key: Key::AccountStorage {
                    address,
                    tx_id: 10,
                    exists: false, // true causes an unwraprror?  nope....
                    storage_key: Word::from(1000 * i),
                },
                old_value: Word::zero(),
                new_value: Word::from(u32::MAX),
                old_root: Word::zero(),
                new_root: Word::zero(),
                original_rws: Default::default(),
            });
        }
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: true,
                storage_key: Word::from(2000),
            },
            old_value: Word::from(u32::MAX),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn empty_storage_proof_empty_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: false,
                storage_key: Word::from(2000),
            },
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn empty_storage_proof_singleton_trie() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 10,
                exists: false,
                storage_key: Word::from(1000),
            },
            old_value: Word::zero(),
            new_value: Word::one(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: false,
                storage_key: Word::from(2000),
            },
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[test]
    fn empty_storage_proof_type_1() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 0..1u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(nonce_update(address));
        }

        let address = Address::zero();
        for i in 0..100u64 {
            updates.insert(MptUpdate {
                key: Key::AccountStorage {
                    address,
                    tx_id: 10,
                    exists: false, // true causes an unwraprror?  nope....
                    storage_key: Word::from(1000 * i),
                },
                old_value: Word::zero(),
                new_value: Word::from(u32::MAX),
                old_root: Word::zero(),
                new_root: Word::zero(),
                original_rws: Default::default(),
            });
        }
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: false,
                storage_key: Word::from(3),
            },
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[ignore = "TODO(mason): is it valid to put these storage writes on empty acc?"]
    #[test]
    fn empty_account_empty_storage_proof() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 1..20u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(MptUpdate {
                key: Key::AccountStorage {
                    address,
                    tx_id: 10,
                    exists: false,
                    storage_key: Word::from(3),
                },
                old_value: Word::zero(),
                new_value: Word::one(),
                old_root: Word::zero(),
                new_root: Word::zero(),
                original_rws: Default::default(),
            });
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: false,
                storage_key: Word::from(3),
            },
            old_value: Word::zero(),
            new_value: Word::zero(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }

    #[ignore = "TODO(mason): is it valid to put these storage writes on empty acc?"]
    #[test]
    fn empty_account_storage_write() {
        assert!(*HASH_SCHEME_DONE);

        let mut updates = MptUpdates::default();
        // Add precompile addresses in so MPT isn't too empty.
        for precompile in 1..20u8 {
            let mut address = Address::zero();
            address.0[1] = precompile;
            updates.insert(MptUpdate {
                key: Key::AccountStorage {
                    address,
                    tx_id: 10,
                    exists: false,
                    storage_key: Word::from(3),
                },
                old_value: Word::zero(),
                new_value: Word::one(),
                old_root: Word::zero(),
                new_root: Word::zero(),
                original_rws: Default::default(),
            });
        }

        let address = Address::zero();
        updates.insert(MptUpdate {
            key: Key::AccountStorage {
                address,
                tx_id: 11,
                exists: false,
                storage_key: Word::from(3),
            },
            old_value: Word::zero(),
            new_value: Word::one(),
            old_root: Word::zero(),
            new_root: Word::zero(),
            original_rws: Default::default(),
        });

        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
        println!(
            "{}",
            serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
        );
    }
}
