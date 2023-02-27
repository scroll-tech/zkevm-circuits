use super::{StateCircuit, StateCircuitConfig};
use crate::{
    table::{AccountFieldTag, CallContextFieldTag, RwTableTag, TxLogFieldTag, TxReceiptFieldTag},
    util::SubCircuit,
    witness::{MptUpdates, Rw, RwMap},
};
use bus_mapping::operation::{
    MemoryOp, Operation, OperationContainer, RWCounter, StackOp, StorageOp, RW,
};
use eth_types::{
    address,
    evm_types::{MemoryAddress, StackAddress},
    Address, Field, ToAddress, Word, U256,
};
use gadgets::binary_number::AsBits;
use halo2_proofs::arithmetic::Field as Halo2Field;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::{Bn256, Fr},
    plonk::{keygen_vk, Advice, Circuit, Column, ConstraintSystem},
};
use rand::SeedableRng;
use std::collections::{BTreeSet, HashMap};
use strum::IntoEnumIterator;

const N_ROWS: usize = 1 << 16;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum AdviceColumn {
    IsWrite,
    Address,
    AddressLimb0,
    AddressLimb1,
    StorageKey,
    StorageKeyByte0,
    StorageKeyByte1,
    Value,
    ValuePrev,
    RwCounter,
    RwCounterLimb0,
    RwCounterLimb1,
    Tag,
    TagBit0,
    TagBit1,
    TagBit2,
    TagBit3,
    LimbIndexBit0, // most significant bit
    LimbIndexBit1,
    LimbIndexBit2,
    LimbIndexBit3,
    LimbIndexBit4, // least significant bit
    InitialValue,
    IsZero, // committed_value and value are 0
    // NonEmptyWitness is the BatchedIsZero chip witness that contains the
    // inverse of the non-zero value if any in [committed_value, value]
    NonEmptyWitness,
}

impl AdviceColumn {
    pub fn value<F: Field>(&self, config: &StateCircuitConfig<F>) -> Column<Advice> {
        match self {
            Self::IsWrite => config.rw_table.is_write,
            Self::Address => config.rw_table.address,
            Self::AddressLimb0 => config.sort_keys.address.limbs[0],
            Self::AddressLimb1 => config.sort_keys.address.limbs[1],
            Self::StorageKey => config.rw_table.storage_key,
            Self::StorageKeyByte0 => config.sort_keys.storage_key.bytes[0],
            Self::StorageKeyByte1 => config.sort_keys.storage_key.bytes[1],
            Self::Value => config.rw_table.value,
            Self::ValuePrev => config.rw_table.value_prev,
            Self::RwCounter => config.rw_table.rw_counter,
            Self::RwCounterLimb0 => config.sort_keys.rw_counter.limbs[0],
            Self::RwCounterLimb1 => config.sort_keys.rw_counter.limbs[1],
            Self::Tag => config.rw_table.tag,
            Self::TagBit0 => config.sort_keys.tag.bits[0],
            Self::TagBit1 => config.sort_keys.tag.bits[1],
            Self::TagBit2 => config.sort_keys.tag.bits[2],
            Self::TagBit3 => config.sort_keys.tag.bits[3],
            Self::LimbIndexBit0 => config.lexicographic_ordering.first_different_limb.bits[0],
            Self::LimbIndexBit1 => config.lexicographic_ordering.first_different_limb.bits[1],
            Self::LimbIndexBit2 => config.lexicographic_ordering.first_different_limb.bits[2],
            Self::LimbIndexBit3 => config.lexicographic_ordering.first_different_limb.bits[3],
            Self::LimbIndexBit4 => config.lexicographic_ordering.first_different_limb.bits[4],
            Self::InitialValue => config.initial_value,
            Self::IsZero => config.is_non_exist.is_zero,
            Self::NonEmptyWitness => config.is_non_exist.nonempty_witness,
        }
    }
}

fn test_state_circuit_ok(
    memory_ops: Vec<Operation<MemoryOp>>,
    stack_ops: Vec<Operation<StackOp>>,
    storage_ops: Vec<Operation<StorageOp>>,
) {
    let rw_map = RwMap::from(&OperationContainer {
        memory: memory_ops,
        stack: stack_ops,
        storage: storage_ops,
        ..Default::default()
    });

    let circuit = StateCircuit::<Fr>::new(rw_map, N_ROWS);
    let instance = circuit.instance();

    let prover = MockProver::<Fr>::run(19, &circuit, instance).unwrap();
    let verify_result = prover.verify();
    assert_eq!(verify_result, Ok(()));
}

#[test]
fn degree() {
    let mut meta = ConstraintSystem::<Fr>::default();
    StateCircuit::<Fr>::configure(&mut meta);
    assert_eq!(meta.degree(), 9);
}

#[test]
fn verifying_key_independent_of_rw_length() {
    let params = ParamsKZG::<Bn256>::setup(17, rand_chacha::ChaCha20Rng::seed_from_u64(2));

    let no_rows = StateCircuit::<Fr>::new(RwMap::default(), N_ROWS);
    let one_row = StateCircuit::<Fr>::new(
        RwMap::from(&OperationContainer {
            memory: vec![Operation::new(
                RWCounter::from(1),
                RW::WRITE,
                MemoryOp::new(1, MemoryAddress::from(0), 32),
            )],
            ..Default::default()
        }),
        N_ROWS,
    );

    let vk_no_rows = keygen_vk(&params, &no_rows).unwrap();
    let vk_one_rows = keygen_vk(&params, &one_row).unwrap();
    assert_eq!(
        vk_no_rows.fixed_commitments(),
        vk_one_rows.fixed_commitments()
    );
    assert_eq!(
        vk_no_rows.permutation().commitments(),
        vk_one_rows.permutation().commitments()
    );
}

#[test]
fn state_circuit_simple_2() {
    let memory_op_0 = Operation::new(
        RWCounter::from(12),
        RW::WRITE,
        MemoryOp::new(1, MemoryAddress::from(0), 32),
    );
    let memory_op_1 = Operation::new(
        RWCounter::from(24),
        RW::READ,
        MemoryOp::new(1, MemoryAddress::from(0), 32),
    );

    let memory_op_2 = Operation::new(
        RWCounter::from(17),
        RW::WRITE,
        MemoryOp::new(1, MemoryAddress::from(1), 32),
    );
    let memory_op_3 = Operation::new(
        RWCounter::from(87),
        RW::READ,
        MemoryOp::new(1, MemoryAddress::from(1), 32),
    );

    let stack_op_0 = Operation::new(
        RWCounter::from(17),
        RW::WRITE,
        StackOp::new(1, StackAddress::from(1), Word::from(32)),
    );
    let stack_op_1 = Operation::new(
        RWCounter::from(87),
        RW::READ,
        StackOp::new(1, StackAddress::from(1), Word::from(32)),
    );

    let storage_op_0 = Operation::new(
        RWCounter::from(1),
        RW::WRITE,
        StorageOp::new(
            U256::from(100).to_address(),
            Word::from(0x40),
            Word::from(32),
            Word::zero(),
            1usize,
            Word::zero(),
        ),
    );
    let storage_op_1 = Operation::new(
        RWCounter::from(18),
        RW::WRITE,
        StorageOp::new(
            U256::from(100).to_address(),
            Word::from(0x40),
            Word::from(32),
            Word::from(32),
            1usize,
            Word::zero(),
        ),
    );
    let storage_op_2 = Operation::new(
        RWCounter::from(19),
        RW::WRITE,
        StorageOp::new(
            U256::from(100).to_address(),
            Word::from(0x40),
            Word::from(32),
            Word::from(32),
            1usize,
            Word::zero(),
        ),
    );

    test_state_circuit_ok(
        vec![memory_op_0, memory_op_1, memory_op_2, memory_op_3],
        vec![stack_op_0, stack_op_1],
        vec![storage_op_0, storage_op_1, storage_op_2],
    );
}

#[test]
fn state_circuit_simple_6() {
    let memory_op_0 = Operation::new(
        RWCounter::from(12),
        RW::WRITE,
        MemoryOp::new(1, MemoryAddress::from(0), 32),
    );
    let memory_op_1 = Operation::new(
        RWCounter::from(13),
        RW::READ,
        MemoryOp::new(1, MemoryAddress::from(0), 32),
    );
    let storage_op_2 = Operation::new(
        RWCounter::from(19),
        RW::WRITE,
        StorageOp::new(
            U256::from(100).to_address(),
            Word::from(0x40),
            Word::from(32),
            Word::from(32),
            1usize,
            Word::from(32),
        ),
    );
    test_state_circuit_ok(vec![memory_op_0, memory_op_1], vec![], vec![storage_op_2]);
}

#[test]
fn lexicographic_ordering_test_1() {
    let memory_op = Operation::new(
        RWCounter::from(12),
        RW::WRITE,
        MemoryOp::new(1, MemoryAddress::from(0), 32),
    );
    let storage_op = Operation::new(
        RWCounter::from(19),
        RW::WRITE,
        StorageOp::new(
            U256::from(100).to_address(),
            Word::from(0x40),
            Word::from(32),
            Word::from(32),
            1usize,
            Word::from(32),
        ),
    );
    test_state_circuit_ok(vec![memory_op], vec![], vec![storage_op]);
}

#[test]
fn lexicographic_ordering_test_2() {
    let memory_op_0 = Operation::new(
        RWCounter::from(12),
        RW::WRITE,
        MemoryOp::new(1, MemoryAddress::from(0), 32),
    );
    let memory_op_1 = Operation::new(
        RWCounter::from(13),
        RW::WRITE,
        MemoryOp::new(1, MemoryAddress::from(0), 32),
    );
    test_state_circuit_ok(vec![memory_op_0, memory_op_1], vec![], vec![]);
}

#[test]
fn first_access_for_stack_is_write() {
    let rows = vec![
        Rw::Stack {
            rw_counter: 24,
            is_write: true,
            call_id: 1,
            stack_pointer: 1022,
            value: U256::from(394500u64),
        },
        Rw::Stack {
            rw_counter: 25,
            is_write: false,
            call_id: 1,
            stack_pointer: 1022,
            value: U256::from(394500u64),
        },
    ];

    assert_eq!(verify(rows), Ok(()));
}

#[test]
fn diff_1_problem_repro() {
    let rows = vec![
        Rw::Account {
            rw_counter: 1,
            is_write: true,
            account_address: Address::default(),
            field_tag: AccountFieldTag::CodeHash,
            value: U256::zero(),
            value_prev: U256::zero(),
        },
        Rw::Account {
            rw_counter: 2,
            is_write: true,
            account_address: Address::default(),
            field_tag: AccountFieldTag::CodeHash,
            value: U256::zero(),
            value_prev: U256::zero(),
        },
    ];

    assert_eq!(verify(rows), Ok(()));
}

#[test]
fn storage_key_rlc() {
    let rows = vec![Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::from(256),
        value: U256::from(300),
        value_prev: U256::from(300),
        tx_id: 4,
        committed_value: U256::from(300),
    }];
    assert_eq!(verify(rows), Ok(()));
}

#[test]
fn tx_log_ok() {
    let rows = vec![
        Rw::Stack {
            rw_counter: 1,
            is_write: true,
            call_id: 1,
            stack_pointer: 1023,
            value: U256::from(394500u64),
        },
        Rw::TxLog {
            rw_counter: 2,
            is_write: true,
            tx_id: 1,
            log_id: 1,
            field_tag: TxLogFieldTag::Address,
            index: 0usize,
            value: U256::one(),
        },
        Rw::TxLog {
            rw_counter: 3,
            is_write: true,
            tx_id: 1,
            log_id: 1,
            field_tag: TxLogFieldTag::Topic,
            index: 0usize,
            value: U256::one(),
        },
        Rw::TxLog {
            rw_counter: 4,
            is_write: true,
            tx_id: 1,
            log_id: 1,
            field_tag: TxLogFieldTag::Topic,
            index: 1usize,
            value: U256::from(2u64),
        },
        Rw::TxLog {
            rw_counter: 5,
            is_write: true,
            tx_id: 1,
            log_id: 1,
            field_tag: TxLogFieldTag::Data,
            index: 0usize,
            value: U256::from(3u64),
        },
        Rw::TxLog {
            rw_counter: 6,
            is_write: true,
            tx_id: 1,
            log_id: 1,
            field_tag: TxLogFieldTag::Data,
            index: 1usize,
            value: U256::from(3u64),
        },
    ];

    assert_eq!(verify(rows), Ok(()));
}

#[test]
fn tx_log_bad() {
    // is_write is false
    let rows = vec![Rw::TxLog {
        rw_counter: 2,
        is_write: false,
        tx_id: 1,
        log_id: 1,
        field_tag: TxLogFieldTag::Address,
        index: 0usize,
        value: U256::zero(),
    }];

    assert_error_matches(verify(rows), "is_write is always true for TxLog");
}

#[test]
fn address_limb_mismatch() {
    let rows = vec![Rw::Account {
        rw_counter: 1,
        is_write: false,
        account_address: address!("0x000000000000000000000000000000000cafe002"),
        field_tag: AccountFieldTag::CodeHash,
        value: U256::zero(),
        value_prev: U256::zero(),
    }];
    let overrides = HashMap::from([((AdviceColumn::AddressLimb0, 0), Fr::zero())]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "mpi value matches claimed limbs");
}

#[test]
fn address_limb_out_of_range() {
    let rows = vec![Rw::Account {
        rw_counter: 1,
        is_write: false,
        account_address: address!("0x0000000000000000000000000000000000010000"),
        field_tag: AccountFieldTag::CodeHash,
        value: U256::zero(),
        value_prev: U256::zero(),
    }];
    let overrides = HashMap::from([
        ((AdviceColumn::AddressLimb0, 0), Fr::from(1 << 16)),
        ((AdviceColumn::AddressLimb1, 0), Fr::zero()),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "mpi limb fits into u16");
}

#[test]
fn storage_key_mismatch() {
    let rows = vec![Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::from(6),
        value: U256::from(34),
        value_prev: U256::from(34),
        tx_id: 4,
        committed_value: U256::from(34),
    }];
    let overrides = HashMap::from([((AdviceColumn::StorageKeyByte1, 0), Fr::one())]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "rlc encoded value matches bytes");
}

#[test]
fn storage_key_byte_out_of_range() {
    let rows = vec![Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::from(256),
        value: U256::from(500),
        value_prev: U256::from(500),
        tx_id: 4,
        committed_value: U256::from(500),
    }];
    let overrides = HashMap::from([
        ((AdviceColumn::StorageKeyByte0, 0), Fr::from(0x1000)),
        ((AdviceColumn::StorageKeyByte1, 0), Fr::zero()),
    ]);

    // This will trigger two errors: an RLC encoding error and the "fit into u8", we
    // remove the first one
    let result = verify_with_overrides(rows, overrides).map_err(|mut err| {
        err.remove(0);
        err
    });

    assert_error_matches(result, "rlc bytes fit into u8");
}

#[test]
fn is_write_nonbinary() {
    let rows = vec![Rw::CallContext {
        rw_counter: 1,
        is_write: false,
        call_id: 0,
        field_tag: CallContextFieldTag::TxId,
        value: U256::zero(),
    }];
    let overrides = HashMap::from([((AdviceColumn::IsWrite, 0), Fr::from(4))]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "is_write is boolean");
}

#[test]
fn nonlexicographic_order_tag() {
    let first = Rw::Memory {
        rw_counter: 1,
        is_write: true,
        call_id: 1,
        memory_address: 10,
        byte: 0,
    };
    let second = Rw::CallContext {
        rw_counter: 2,
        is_write: false,
        call_id: 1,
        field_tag: CallContextFieldTag::IsSuccess,
        value: U256::zero(),
    };

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(verify(vec![second, first]), "limb_difference fits into u16");
}

#[test]
fn nonlexicographic_order_field_tag() {
    let first = Rw::CallContext {
        rw_counter: 5,
        is_write: true,
        call_id: 0,
        field_tag: CallContextFieldTag::RwCounterEndOfReversion,
        value: U256::from(100),
    };
    let second = Rw::CallContext {
        rw_counter: 2,
        is_write: true,
        call_id: 0,
        field_tag: CallContextFieldTag::CallerId,
        value: U256::from(200),
    };

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(verify(vec![second, first]), "limb_difference fits into u16");
}

#[test]
fn nonlexicographic_order_id() {
    let first = Rw::CallContext {
        rw_counter: 1,
        is_write: true,
        call_id: 0,
        field_tag: CallContextFieldTag::RwCounterEndOfReversion,
        value: U256::from(100),
    };
    let second = Rw::CallContext {
        rw_counter: 2,
        is_write: true,
        call_id: 1,
        field_tag: CallContextFieldTag::RwCounterEndOfReversion,
        value: U256::from(200),
    };

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(verify(vec![second, first]), "limb_difference fits into u16");
}

#[test]
fn nonlexicographic_order_address() {
    let first = Rw::Account {
        rw_counter: 50,
        is_write: true,
        account_address: address!("0x1000000000000000000000000000000000000000"),
        field_tag: AccountFieldTag::CodeHash,
        value: U256::zero(),
        value_prev: U256::zero(),
    };
    let second = Rw::Account {
        rw_counter: 30,
        is_write: true,
        account_address: address!("0x2000000000000000000000000000000000000000"),
        field_tag: AccountFieldTag::CodeHash,
        value: U256::one(),
        value_prev: U256::zero(),
    };

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(verify(vec![second, first]), "limb_difference fits into u16");
}

#[test]
fn nonlexicographic_order_storage_key_upper() {
    let first = Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::zero(),
        value: U256::from(800),
        value_prev: U256::from(800),
        tx_id: 4,
        committed_value: U256::from(800),
    };
    let second = Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::MAX - U256::one(),
        value: U256::from(300),
        value_prev: U256::from(300),
        tx_id: 4,
        committed_value: U256::from(300),
    };

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(verify(vec![second, first]), "limb_difference fits into u16");
}

#[test]
fn nonlexicographic_order_storage_key_lower() {
    let first = Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::zero(),
        value: U256::from(200),
        value_prev: U256::from(200),
        tx_id: 4,
        committed_value: U256::from(200),
    };
    let second = Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::one(),
        value: U256::from(200),
        value_prev: U256::from(200),
        tx_id: 4,
        committed_value: U256::from(200),
    };

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(verify(vec![second, first]), "limb_difference fits into u16");
}

#[test]
fn nonlexicographic_order_rw_counter() {
    let first = Rw::CallContext {
        rw_counter: 1,
        is_write: false,
        call_id: 1,
        field_tag: CallContextFieldTag::IsSuccess,
        value: U256::zero(),
    };
    let second = Rw::CallContext {
        rw_counter: 2,
        is_write: false,
        call_id: 1,
        field_tag: CallContextFieldTag::IsSuccess,
        value: U256::zero(),
    };

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(verify(vec![second, first]), "limb_difference fits into u16");
}

#[test]
fn lexicographic_ordering_previous_limb_differences_nonzero() {
    let rows = vec![
        Rw::TxRefund {
            rw_counter: 1,
            is_write: true,
            tx_id: 23,
            value: 20,
            value_prev: 0,
        },
        Rw::Account {
            rw_counter: 2,
            is_write: true,
            account_address: address!("0x0000000000000000000000000000000000000001"),
            field_tag: AccountFieldTag::Nonce,
            value: Word::zero(),
            value_prev: Word::zero(),
        },
    ];

    // overriding first_different_limb to be in AddressLimb0 instead of Tag. The
    // limb difference between the two rows here is still 1, so no additional
    // overrides are needed.
    let overrides = HashMap::from([
        ((AdviceColumn::LimbIndexBit1, 1), Fr::one()),
        ((AdviceColumn::LimbIndexBit2, 1), Fr::one()),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(
        result,
        "limb differences before first_different_limb are all 0",
    );
}

#[ignore]
#[test]
fn read_inconsistency() {
    let rows = vec![
        Rw::Memory {
            rw_counter: 10,
            is_write: false,
            call_id: 1,
            memory_address: 10,
            byte: 0,
        },
        Rw::Memory {
            rw_counter: 40,
            is_write: false,
            call_id: 1,
            memory_address: 10,
            byte: 200,
        },
    ];

    assert_error_matches(verify(rows), "non-first access reads don't change value");
}

#[test]
fn all_padding() {
    assert_eq!(
        prover(vec![], HashMap::new()).verify_at_rows(0..100, 0..100),
        Ok(())
    );
}

#[test]
fn skipped_start_rw_counter() {
    let overrides = HashMap::from([
        (
            (AdviceColumn::RwCounter, -1),
            // The original assignment is 1 << 16.
            Fr::from((1 << 16) + 1),
        ),
        ((AdviceColumn::RwCounterLimb0, -1), Fr::one()),
    ]);

    let result = prover(vec![], overrides).verify_at_rows(N_ROWS - 1..N_ROWS, N_ROWS - 1..N_ROWS);
    assert_error_matches(result, "rw_counter increases by 1 for every non-first row");
}

#[test]
fn invalid_memory_address() {
    let rows = vec![Rw::Memory {
        rw_counter: 1,
        is_write: true,
        call_id: 1,
        memory_address: 1u64 << 32,
        byte: 12,
    }];

    assert_error_matches(verify(rows), "memory address fits into 2 limbs");
}

#[test]
fn bad_initial_memory_value() {
    let rows = vec![Rw::Memory {
        rw_counter: 1,
        is_write: true,
        call_id: 1,
        memory_address: 10,
        byte: 0,
    }];

    let v = Fr::from(200);
    let overrides = HashMap::from([
        ((AdviceColumn::Value, 0), v),
        ((AdviceColumn::ValuePrev, 0), v),
        ((AdviceColumn::IsZero, 0), Fr::zero()),
        ((AdviceColumn::NonEmptyWitness, 0), v.invert().unwrap()),
        ((AdviceColumn::InitialValue, 0), v),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "initial Memory value is 0");
}

#[test]
fn invalid_memory_value() {
    let rows = vec![Rw::Memory {
        rw_counter: 1,
        is_write: true,
        call_id: 1,
        memory_address: 10,
        byte: 1,
    }];
    let v = Fr::from(256);
    let overrides = HashMap::from([
        ((AdviceColumn::Value, 0), v),
        ((AdviceColumn::NonEmptyWitness, 0), v.invert().unwrap()),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "memory value is a byte");
}

#[test]
fn stack_read_before_write() {
    let rows = vec![Rw::Stack {
        rw_counter: 9,
        is_write: false,
        call_id: 3,
        stack_pointer: 200,
        value: U256::zero(),
    }];

    assert_error_matches(verify(rows), "first access to new stack address is a write");
}

#[test]
fn invalid_stack_address() {
    let rows = vec![Rw::Stack {
        rw_counter: 9,
        is_write: true,
        call_id: 3,
        stack_pointer: 3000,
        value: U256::from(10),
    }];

    assert_error_matches(verify(rows), "stack address fits into 10 bits");
}

#[test]
fn invalid_stack_address_change() {
    let rows = vec![
        Rw::Stack {
            rw_counter: 9,
            is_write: true,
            call_id: 3,
            stack_pointer: 100,
            value: U256::from(10),
        },
        Rw::Stack {
            rw_counter: 13,
            is_write: true,
            call_id: 3,
            stack_pointer: 102,
            value: U256::from(20),
        },
    ];

    assert_error_matches(
        verify(rows),
        "if previous row is also Stack with unchanged call id, address change is 0 or 1",
    );
}

#[test]
fn invalid_tags() {
    let first_row_offset = -isize::try_from(N_ROWS).unwrap();
    let tags: BTreeSet<usize> = RwTableTag::iter().map(|x| x as usize).collect();
    for i in 0..16 {
        if tags.contains(&i) {
            continue;
        }
        let bits: [Fr; 4] = i
            .as_bits()
            .map(|bit| if bit { Fr::one() } else { Fr::zero() });
        let overrides = HashMap::from([
            ((AdviceColumn::TagBit0, first_row_offset), bits[0]),
            ((AdviceColumn::TagBit1, first_row_offset), bits[1]),
            ((AdviceColumn::TagBit2, first_row_offset), bits[2]),
            ((AdviceColumn::TagBit3, first_row_offset), bits[3]),
            ((AdviceColumn::Tag, first_row_offset), Fr::from(i as u64)),
        ]);

        let result = prover(vec![], overrides).verify_at_rows(0..1, 0..1);

        assert_error_matches(result, "binary number value in range");
    }
}

#[test]
fn bad_initial_stack_value() {
    let rows = vec![Rw::Stack {
        rw_counter: 1,
        is_write: true,
        call_id: 1,
        stack_pointer: 10,
        value: Word::from(10),
    }];

    let overrides = HashMap::from([
        ((AdviceColumn::InitialValue, 0), Fr::from(10)),
        ((AdviceColumn::ValuePrev, 0), Fr::from(10)),
    ]);

    assert_error_matches(
        verify_with_overrides(rows, overrides),
        "initial Stack value is 0",
    );
}

#[test]
fn bad_initial_tx_access_list_account_value() {
    let rows = vec![Rw::TxAccessListAccount {
        rw_counter: 1,
        is_write: true,
        tx_id: 1,
        account_address: address!("0x0000000000000000000000000000000004356002"),
        is_warm: true,
        is_warm_prev: false,
    }];

    let overrides = HashMap::from([
        ((AdviceColumn::InitialValue, 0), Fr::from(1)),
        ((AdviceColumn::ValuePrev, 0), Fr::from(1)),
    ]);

    assert_error_matches(
        verify_with_overrides(rows, overrides),
        "initial TxAccessListAccount value is false",
    );
}

#[test]
fn bad_initial_tx_refund_value() {
    let rows = vec![Rw::TxRefund {
        rw_counter: 1,
        is_write: false,
        tx_id: 1,
        value: 0,
        value_prev: 0,
    }];
    let v = Fr::from(10);
    let overrides = HashMap::from([
        ((AdviceColumn::IsWrite, 0), Fr::from(1)),
        ((AdviceColumn::Value, 0), v),
        ((AdviceColumn::ValuePrev, 0), v),
        ((AdviceColumn::IsZero, 0), Fr::zero()),
        ((AdviceColumn::NonEmptyWitness, 0), v.invert().unwrap()),
        ((AdviceColumn::InitialValue, 0), v),
    ]);

    assert_error_matches(
        verify_with_overrides(rows, overrides),
        "initial TxRefund value is 0",
    );
}

#[test]
fn bad_initial_tx_log_value() {
    let rows = vec![Rw::TxLog {
        rw_counter: 1,
        is_write: true,
        tx_id: 800,
        log_id: 4,
        field_tag: TxLogFieldTag::Topic,
        index: 2,
        value: U256::from(300),
    }];

    let overrides = HashMap::from([
        ((AdviceColumn::InitialValue, 0), Fr::from(10)),
        ((AdviceColumn::ValuePrev, 0), Fr::from(10)),
    ]);

    assert_error_matches(
        verify_with_overrides(rows, overrides),
        "initial TxLog value is 0",
    );
}

#[test]
#[ignore = "TxReceipt constraints not yet implemented"]
fn bad_initial_tx_receipt_value() {
    let rows = vec![Rw::TxReceipt {
        rw_counter: 1,
        is_write: false,
        tx_id: 3421,
        field_tag: TxReceiptFieldTag::CumulativeGasUsed,
        value: 0,
    }];

    let overrides = HashMap::from([
        ((AdviceColumn::Value, 0), Fr::from(1900)),
        ((AdviceColumn::InitialValue, 0), Fr::from(1900)),
    ]);

    assert_error_matches(
        verify_with_overrides(rows, overrides),
        "initial TxReceipt value is 0",
    );
}

fn prover(rows: Vec<Rw>, overrides: HashMap<(AdviceColumn, isize), Fr>) -> MockProver<Fr> {
    let updates =
        MptUpdates::from_rws_with_mock_state_roots(&rows, 0xcafeu64.into(), 0xdeadbeefu64.into());
    let circuit = StateCircuit::<Fr> {
        rows,
        updates,
        overrides,
        n_rows: N_ROWS,
        exports: Default::default(),
        _marker: std::marker::PhantomData::default(),
    };
    let instance = circuit.instance();

    MockProver::<Fr>::run(17, &circuit, instance).unwrap()
}

fn verify(rows: Vec<Rw>) -> Result<(), Vec<VerifyFailure>> {
    let used_rows = rows.len();
    prover(rows, HashMap::new())
        .verify_at_rows(N_ROWS - used_rows..N_ROWS, N_ROWS - used_rows..N_ROWS)
}

fn verify_with_overrides(
    rows: Vec<Rw>,
    overrides: HashMap<(AdviceColumn, isize), Fr>,
) -> Result<(), Vec<VerifyFailure>> {
    // Sanity check that the original RwTable without overrides is valid.
    assert_eq!(verify(rows.clone()), Ok(()));

    let n_active_rows = rows.len();
    prover(rows, overrides).verify_at_rows(
        N_ROWS - n_active_rows..N_ROWS,
        N_ROWS - n_active_rows..N_ROWS,
    )
}

fn assert_error_matches(result: Result<(), Vec<VerifyFailure>>, name: &str) {
    let errors = result.expect_err("result is not an error");
    assert_eq!(errors.len(), 1, "{:?}", errors);
    match &errors[0] {
        VerifyFailure::ConstraintNotSatisfied { constraint, .. } => {
            // fields of halo2_proofs::dev::metadata::Constraint aren't public, so we have
            // to match off of its format string.
            let constraint = format!("{}", constraint);
            if !constraint.contains(name) {
                panic!("{} does not contain {}", constraint, name);
            }
        }
        VerifyFailure::Lookup {
            name: lookup_name, ..
        } => {
            assert_eq!(lookup_name, &name)
        }
        VerifyFailure::CellNotAssigned { .. } => panic!(),
        VerifyFailure::ConstraintPoisoned { .. } => panic!(),
        VerifyFailure::Permutation { .. } => panic!(),
    }
}
