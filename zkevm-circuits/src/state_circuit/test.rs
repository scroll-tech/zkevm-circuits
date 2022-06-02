use super::{StateCircuit, StateConfig};
use crate::evm_circuit::{
    table::{AccountFieldTag, CallContextFieldTag},
    witness::{Rw, RwMap},
};
use bus_mapping::operation::{
    MemoryOp, Operation, OperationContainer, RWCounter, StackOp, StorageOp, RW,
};
use eth_types::{
    address,
    evm_types::{MemoryAddress, StackAddress},
    Address, Field, ToAddress, Word, U256,
};
use halo2_proofs::{
    arithmetic::{BaseExt, Field as halo2_field},
    dev::{MockProver, VerifyFailure},
    pairing::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem},
};
use std::collections::HashMap;

#[derive(Hash, Eq, PartialEq, Clone)]
pub enum AdviceColumn {
    IsWrite,
    Address,
    AddressLimb0,
    AddressLimb1,
    StorageKey,
    StorageKeyByte0,
    StorageKeyByte1,
    StorageKeyChangeInverse,
    Value,
    RwCounter,
    RwCounterLimb0,
}

impl AdviceColumn {
    pub fn value<F: Field, const QUICK_CHECK: bool>(
        &self,
        config: &StateConfig<F, QUICK_CHECK>,
    ) -> Column<Advice> {
        match self {
            Self::IsWrite => config.rw_table.is_write,
            Self::Address => config.rw_table.address,
            Self::AddressLimb0 => config.address_mpi.limbs[0],
            Self::AddressLimb1 => config.address_mpi.limbs[1],
            Self::StorageKey => config.rw_table.storage_key,
            Self::StorageKeyByte0 => config.storage_key_rlc.bytes[0],
            Self::StorageKeyByte1 => config.storage_key_rlc.bytes[1],
            Self::StorageKeyChangeInverse => config.is_storage_key_unchanged.value_inv,
            Self::Value => config.rw_table.value,
            Self::RwCounter => config.rw_table.rw_counter,
            Self::RwCounterLimb0 => config.rw_counter_mpi.limbs[0],
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

    let randomness = Fr::rand();
    let circuit = StateCircuit::new(randomness, rw_map);
    let power_of_randomness = circuit.instance();

    let prover =
        MockProver::<Fr>::run(circuit.estimate_k(), &circuit, power_of_randomness).unwrap();
    let verify_result = prover.verify();
    assert_eq!(verify_result, Ok(()));
}

#[test]
fn degree() {
    let mut meta = ConstraintSystem::<Fr>::default();
    StateCircuit::configure(&mut meta);
    assert_eq!(meta.degree(), 18);
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
            Word::from(32),
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
            Word::from(32),
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
        Rw::Start,
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
        Rw::Start,
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
    let rows = vec![
        Rw::Start,
        Rw::AccountStorage {
            rw_counter: 1,
            is_write: false,
            account_address: Address::default(),
            storage_key: U256::from(256),
            value: U256::zero(),
            value_prev: U256::from(5),
            tx_id: 4,
            committed_value: U256::from(5),
        },
    ];

    assert_eq!(verify(rows), Ok(()));
}

#[test]
fn address_limb_mismatch() {
    let rows = vec![
        Rw::Start,
        Rw::Account {
            rw_counter: 1,
            is_write: false,
            account_address: address!("0x000000000000000000000000000000000cafe002"),
            field_tag: AccountFieldTag::CodeHash,
            value: U256::zero(),
            value_prev: U256::zero(),
        },
    ];
    let overrides = HashMap::from([((AdviceColumn::Address, 1), Fr::from(10))]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "mpi value matches claimed limbs");
}

#[test]
fn address_limb_out_of_range() {
    let rows = vec![
        Rw::Start,
        Rw::Account {
            rw_counter: 1,
            is_write: false,
            account_address: address!("0x0000000000000000000000000000000000010000"),
            field_tag: AccountFieldTag::CodeHash,
            value: U256::zero(),
            value_prev: U256::zero(),
        },
    ];
    let overrides = HashMap::from([
        ((AdviceColumn::AddressLimb0, 1), Fr::from(1 << 16)),
        ((AdviceColumn::AddressLimb1, 1), Fr::zero()),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "mpi limb fits into u16");
}

#[test]
fn storage_key_mismatch() {
    let rows = vec![
        Rw::Start,
        Rw::AccountStorage {
            rw_counter: 1,
            is_write: false,
            account_address: Address::default(),
            storage_key: U256::from(6),
            value: U256::zero(),
            value_prev: U256::from(5),
            tx_id: 4,
            committed_value: U256::from(5),
        },
    ];
    let overrides = HashMap::from([
        ((AdviceColumn::StorageKey, 1), Fr::from(10)),
        (
            (AdviceColumn::StorageKeyChangeInverse, 1),
            Fr::from(10).invert().unwrap(),
        ),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "rlc encoded value matches bytes");
}

#[test]
fn storage_key_byte_out_of_range() {
    let rows = vec![
        Rw::Start,
        Rw::AccountStorage {
            rw_counter: 1,
            is_write: false,
            account_address: Address::default(),
            storage_key: U256::from(256),
            value: U256::zero(),
            value_prev: U256::from(5),
            tx_id: 4,
            committed_value: U256::from(5),
        },
    ];
    let overrides = HashMap::from([
        ((AdviceColumn::StorageKey, 1), Fr::from(256)),
        ((AdviceColumn::StorageKeyByte0, 1), Fr::from(256)),
        ((AdviceColumn::StorageKeyByte1, 1), Fr::zero()),
        (
            (AdviceColumn::StorageKeyChangeInverse, 1),
            Fr::from(256).invert().unwrap(),
        ),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "rlc bytes fit into u8");
}

#[test]
fn is_write_nonbinary() {
    let rows = vec![
        Rw::Start,
        Rw::CallContext {
            rw_counter: 1,
            is_write: false,
            call_id: 0,
            field_tag: CallContextFieldTag::TxId,
            value: U256::one(),
        },
    ];
    let overrides = HashMap::from([((AdviceColumn::IsWrite, 1), Fr::from(4))]);

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
        value: U256::one(),
    };

    assert_eq!(verify(vec![Rw::Start, first, second]), Ok(()));
    assert_error_matches(
        verify(vec![Rw::Start, second, first]),
        "upper_limb_difference fits into u16",
    );
}

#[test]
fn nonlexicographic_order_field_tag() {
    let first = Rw::CallContext {
        rw_counter: 5,
        is_write: false,
        call_id: 0,
        field_tag: CallContextFieldTag::RwCounterEndOfReversion,
        value: U256::from(100),
    };
    let second = Rw::CallContext {
        rw_counter: 2,
        is_write: false,
        call_id: 0,
        field_tag: CallContextFieldTag::CallerId,
        value: U256::from(200),
    };

    assert_eq!(verify(vec![Rw::Start, first, second]), Ok(()));
    assert_error_matches(
        verify(vec![Rw::Start, second, first]),
        "upper_limb_difference fits into u16",
    );
}

#[test]
fn nonlexicographic_order_id() {
    let first = Rw::CallContext {
        rw_counter: 1,
        is_write: false,
        call_id: 0,
        field_tag: CallContextFieldTag::RwCounterEndOfReversion,
        value: U256::from(100),
    };
    let second = Rw::CallContext {
        rw_counter: 2,
        is_write: false,
        call_id: 1,
        field_tag: CallContextFieldTag::RwCounterEndOfReversion,
        value: U256::from(200),
    };

    assert_eq!(verify(vec![Rw::Start, first, second]), Ok(()));
    assert_error_matches(
        verify(vec![Rw::Start, second, first]),
        "upper_limb_difference fits into u16",
    );
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

    assert_eq!(verify(vec![Rw::Start, first, second]), Ok(()));
    assert_error_matches(
        verify(vec![Rw::Start, second, first]),
        "upper_limb_difference fits into u16",
    );
}

#[test]
fn nonlexicographic_order_storage_key_upper() {
    let first = Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::zero(),
        value: U256::zero(),
        value_prev: U256::from(5),
        tx_id: 4,
        committed_value: U256::from(5),
    };
    let second = Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::MAX - U256::one(),
        value: U256::zero(),
        value_prev: U256::from(5),
        tx_id: 4,
        committed_value: U256::from(5),
    };

    assert_eq!(verify(vec![Rw::Start, first, second]), Ok(()));
    assert_error_matches(
        verify(vec![Rw::Start, second, first]),
        "upper_limb_difference fits into u16",
    );
}

#[test]
fn nonlexicographic_order_storage_key_lower() {
    let first = Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::zero(),
        value: U256::zero(),
        value_prev: U256::from(5),
        tx_id: 4,
        committed_value: U256::from(5),
    };
    let second = Rw::AccountStorage {
        rw_counter: 1,
        is_write: false,
        account_address: Address::default(),
        storage_key: U256::one(),
        value: U256::zero(),
        value_prev: U256::from(5),
        tx_id: 4,
        committed_value: U256::from(5),
    };

    assert_eq!(verify(vec![Rw::Start, first, second]), Ok(()));
    assert_error_matches(
        verify(vec![Rw::Start, second, first]),
        "upper_limb_difference is zero or lower_limb_difference fits into u16",
    );
}

#[test]
fn nonlexicographic_order_rw_counter() {
    let first = Rw::CallContext {
        rw_counter: 1,
        is_write: false,
        call_id: 1,
        field_tag: CallContextFieldTag::IsSuccess,
        value: U256::one(),
    };
    let second = Rw::CallContext {
        rw_counter: 2,
        is_write: false,
        call_id: 1,
        field_tag: CallContextFieldTag::IsSuccess,
        value: U256::one(),
    };

    assert_eq!(verify(vec![Rw::Start, first, second]), Ok(()));
    assert_error_matches(
        verify(vec![Rw::Start, second, first]),
        "upper_limb_difference is zero or lower_limb_difference fits into u16",
    );
}

#[test]
#[ignore = "read consistency constraint not implemented"]
fn read_inconsistency() {
    let rows = vec![
        Rw::Start,
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

    assert_error_matches(verify(rows), "read consistency");
}

#[test]
fn invalid_start_rw_counter() {
    let rows = vec![Rw::Start];
    let overrides = HashMap::from([
        ((AdviceColumn::RwCounter, 0), Fr::from(2)),
        ((AdviceColumn::RwCounterLimb0, 0), Fr::from(2)),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "rw_counter is 0 for Start");
}

#[test]
fn invalid_memory_address() {
    let rows = vec![
        Rw::Start,
        Rw::Memory {
            rw_counter: 1,
            is_write: true,
            call_id: 1,
            memory_address: 1u64 << 32,
            byte: 12,
        },
    ];

    assert_error_matches(verify(rows), "memory address fits into 2 limbs");
}

#[test]
fn first_memory_read_nonzero() {
    let rows = vec![
        Rw::Start,
        Rw::Memory {
            rw_counter: 1,
            is_write: false,
            call_id: 1,
            memory_address: 10,
            byte: 200,
        },
    ];

    assert_error_matches(verify(rows), "read from a fresh key is 0");
}

#[test]
fn invalid_memory_value() {
    let rows = vec![
        Rw::Start,
        Rw::Memory {
            rw_counter: 1,
            is_write: true,
            call_id: 1,
            memory_address: 10,
            byte: 0,
        },
    ];
    let overrides = HashMap::from([((AdviceColumn::Value, 1), Fr::from(256))]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "memory value is a byte");
}

#[test]
fn stack_read_before_write() {
    let rows = vec![
        Rw::Start,
        Rw::Stack {
            rw_counter: 9,
            is_write: false,
            call_id: 3,
            stack_pointer: 200,
            value: U256::from(10),
        },
    ];

    assert_error_matches(verify(rows), "first access to new stack address is a write");
}

#[test]
fn invalid_stack_address() {
    let rows = vec![
        Rw::Start,
        Rw::Stack {
            rw_counter: 9,
            is_write: true,
            call_id: 3,
            stack_pointer: 3000,
            value: U256::from(10),
        },
    ];

    assert_error_matches(verify(rows), "stack address fits into 10 bits");
}

#[test]
fn invalid_stack_address_change() {
    let rows = vec![
        Rw::Start,
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
        "if call id is the same, address change is 0 or 1",
    );
}

fn prover(rows: Vec<Rw>, overrides: HashMap<(AdviceColumn, usize), Fr>) -> MockProver<Fr> {
    let randomness = Fr::rand();
    let rows = rows
        .iter()
        .map(|r| r.table_assignment(randomness))
        .collect();
    let circuit = StateCircuit {
        randomness,
        rows,
        overrides,
    };
    let power_of_randomness = circuit.instance();

    MockProver::<Fr>::run(circuit.estimate_k(), &circuit, power_of_randomness).unwrap()
}

fn verify(rows: Vec<Rw>) -> Result<(), Vec<VerifyFailure>> {
    let n_rows = rows.len();
    prover(rows, HashMap::new()).verify_at_rows(0..n_rows + 1, 0..n_rows + 1)
}

fn verify_with_overrides(
    rows: Vec<Rw>,
    overrides: HashMap<(AdviceColumn, usize), Fr>,
) -> Result<(), Vec<VerifyFailure>> {
    // Sanity check that the original RwTable without overrides is valid.
    assert_eq!(verify(rows.clone()), Ok(()));

    let n_rows = rows.len();
    prover(rows, overrides).verify_at_rows(0..n_rows + 1, 0..n_rows + 1)
}

fn assert_error_matches(result: Result<(), Vec<VerifyFailure>>, name: &str) {
    let errors = result.err().expect("result is not an error");
    let errors: Vec<_> = errors
        .iter()
        .filter(|e| {
            if let VerifyFailure::ConstraintNotSatisfied { constraint, .. } = e {
                let constraint = format!("{}", constraint);
                if constraint.contains("rw table rlc") {
                    return false;
                }
            }
            true
        })
        .collect();
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
