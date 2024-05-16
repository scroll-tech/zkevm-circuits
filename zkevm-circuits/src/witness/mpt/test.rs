use super::*;
use mpt_zktrie::state::builder::init_hash_scheme;

#[test]
fn invalid_state_from_reading_nonce() {
    init_hash_scheme();

    let key = Key::Account {
        address: Address::zero(),
        field_tag: AccountFieldTag::Nonce,
    };
    let update = MptUpdate {
        key,
        new_root: Word::one(),
        ..Default::default()
    };

    let mut updates = MptUpdates::default();
    updates.updates.insert(key, update);

    updates.fill_state_roots(&ZktrieState::default());
}

#[test]
fn invalid_state_from_reading_balance() {
    init_hash_scheme();

    let key = Key::Account {
        address: Address::zero(),
        field_tag: AccountFieldTag::Balance,
    };
    let update = MptUpdate {
        key,
        new_root: Word::one(),
        ..Default::default()
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
        new_value: Word::one(),
        ..Default::default()
    }
}

#[test]
fn nonce_update_existing() {
    init_hash_scheme();

    let mut updates = MptUpdates::default();
    // Add precompile addresses in so MPT isn't too empty.
    for precompile in 4..6u8 {
        let mut address = Address::zero();
        address.0[1] = precompile;
        updates.insert(nonce_update(address));
    }

    updates.insert(nonce_update(Address::repeat_byte(45)));
    let generator =
        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

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
    init_hash_scheme();

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
        ..Default::default()
    });

    updates.fill_state_roots(&ZktrieState::default());
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn nonce_update_type_1() {
    init_hash_scheme();

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
    init_hash_scheme();

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
        new_value: Word::from(u64::MAX),
        ..Default::default()
    }
}

#[test]
fn balance_update_existing() {
    init_hash_scheme();

    let mut updates = MptUpdates::default();
    // Add precompile addresses in so MPT isn't too empty.
    for precompile in 4..6u8 {
        let mut address = Address::zero();
        address.0[1] = precompile;
        updates.insert(nonce_update(address));
    }

    updates.insert(balance_update(Address::repeat_byte(45)));
    let generator =
        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

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
    init_hash_scheme();

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
    init_hash_scheme();

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
    init_hash_scheme();

    let mut updates = MptUpdates::default();
    // Add precompile addresses in so MPT isn't too empty.
    for precompile in 4..6u8 {
        let mut address = Address::zero();
        address.0[1] = precompile;
        updates.insert(nonce_update(address));
    }

    let address = Address::repeat_byte(45);
    updates.insert(nonce_update(address));

    let generator =
        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

    let mut updates = MptUpdates::default();
    let update = MptUpdate {
        key: Key::Account {
            address,
            field_tag: AccountFieldTag::CodeSize,
        },
        new_value: Word::from(23412341231u64),
        ..Default::default()
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
    init_hash_scheme();

    let mut updates = MptUpdates::default();
    // Add precompile addresses in so MPT isn't too empty.
    for precompile in 4..6u8 {
        let mut address = Address::zero();
        address.0[1] = precompile;
        updates.insert(nonce_update(address));
    }

    let address = Address::repeat_byte(45);
    updates.insert(nonce_update(address));

    let generator =
        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

    let mut updates = MptUpdates::default();
    let update = MptUpdate {
        key: Key::Account {
            address,
            field_tag: AccountFieldTag::CodeHash,
        },
        new_value: Word::from(234123124231231u64),
        ..Default::default()
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
    init_hash_scheme();

    let mut updates = MptUpdates::default();
    // Add precompile addresses in so MPT isn't too empty.
    for precompile in 4..6u8 {
        let mut address = Address::zero();
        address.0[1] = precompile;
        updates.insert(nonce_update(address));
    }

    let address = Address::repeat_byte(45);
    updates.insert(nonce_update(address));

    let generator =
        updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));

    let mut updates = MptUpdates::default();
    let update = MptUpdate {
        key: Key::Account {
            address,
            field_tag: AccountFieldTag::KeccakCodeHash,
        },
        new_value: U256([u64::MAX; 4]),
        ..Default::default()
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
    init_hash_scheme();

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
            new_value: Word::from(u32::MAX),
            ..Default::default()
        });
    }
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 10,
            exists: false, // true causes an unwraprror?  nope....
            storage_key: Word::from(2431230),
        },
        new_value: Word::from(u32::MAX),
        ..Default::default()
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
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn update_storage_type_1_to_type_1() {
    init_hash_scheme();
    init_hash_scheme();

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
        new_value: Word::from(u32::MAX),
        ..Default::default()
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
        ..Default::default()
    });
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 10,
            exists: false, // true causes an unwraprror?  nope....
            storage_key: Word::from(2431230),
        },
        new_value: Word::from(u32::MAX),
        ..Default::default()
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
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn update_storage_type_2_to_type_2() {
    init_hash_scheme();
}

#[test]
fn update_storage_type_1_to_existing() {
    init_hash_scheme();
}

#[test]
fn update_storage_type_2_to_existing() {
    init_hash_scheme();
}

#[test]
fn update_storage_existing_to_type_1() {
    init_hash_scheme();
}

#[test]
fn update_storage_existing_to_type_2() {
    init_hash_scheme();
}

#[test]
fn read_storage_type_1() {
    init_hash_scheme();
}

#[test]
fn read_storage_type_2() {
    init_hash_scheme();
}

#[test]
fn read_empty_storage_trie() {
    init_hash_scheme();

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
        ..Default::default()
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
    init_hash_scheme();

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
        new_value: Word::from(u32::MAX),
        ..Default::default()
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
    init_hash_scheme();

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
        new_value: Word::from(u32::MAX),
        ..Default::default()
    });
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 10,
            exists: false, // true causes an unwraprror?  nope....
            storage_key: Word::MAX,
        },
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn write_singleton_storage_trie() {
    init_hash_scheme();

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
        new_value: Word::from(u32::MAX),
        ..Default::default()
    });
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 10,
            exists: false, // true causes an unwraprror?  nope....
            storage_key: Word::MAX,
        },
        new_value: Word::one(),
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn write_zero_to_singleton_storage_trie() {
    init_hash_scheme();

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
        new_value: Word::from(u32::MAX),
        ..Default::default()
    });
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 10,
            exists: true,
            storage_key: Word::MAX - Word::from(43),
        },
        old_value: Word::from(u32::MAX),
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn write_zero_to_doubleton_storage_trie() {
    init_hash_scheme();

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
        new_value: Word::MAX - Word::from(43),
        ..Default::default()
    });
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 10,
            exists: false,
            storage_key: Word::MAX - Word::from(12312),
        },
        new_value: Word::from(u64::MAX),
        ..Default::default()
    });
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 10,
            exists: true,
            storage_key: Word::MAX - Word::from(43),
        },
        old_value: Word::MAX - Word::from(43),
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn write_zero_to_storage_trie() {
    init_hash_scheme();

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
            new_value: Word::from(u32::MAX),
            ..Default::default()
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
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn empty_storage_proof_empty_trie() {
    init_hash_scheme();

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
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn empty_storage_proof_singleton_trie() {
    init_hash_scheme();

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
        new_value: Word::one(),
        ..Default::default()
    });
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 11,
            exists: false,
            storage_key: Word::from(2000),
        },
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}

#[test]
fn empty_storage_proof_type_1() {
    init_hash_scheme();

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
            new_value: Word::from(u32::MAX),
            ..Default::default()
        });
    }
    updates.insert(MptUpdate {
        key: Key::AccountStorage {
            address,
            tx_id: 11,
            exists: false,
            storage_key: Word::from(3),
        },
        ..Default::default()
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
    init_hash_scheme();

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
            new_value: Word::one(),
            ..Default::default()
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
        ..Default::default()
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
    init_hash_scheme();

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
            new_value: Word::one(),
            ..Default::default()
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
        new_value: Word::one(),
        ..Default::default()
    });

    updates.fill_state_roots_from_generator(WitnessGenerator::from(&ZktrieState::default()));
    println!(
        "{}",
        serde_json::to_string_pretty(&updates.smt_traces.last().unwrap()).unwrap()
    );
}
