use super::{StateCircuit, StateConfig};
use crate::evm_circuit::{
    table::{AccountFieldTag, CallContextFieldTag, TxLogFieldTag},
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
    arithmetic::BaseExt,
    dev::{MockProver, VerifyFailure},
    pairing::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem},
};
use std::collections::HashMap;

#[derive(Hash, Eq, PartialEq)]
pub enum AdviceColumn {
    IsWrite,
    Address,
    AddressLimb0,
    AddressLimb1,
}

impl AdviceColumn {
    pub fn value<F: Field>(&self, config: &StateConfig<F>) -> Column<Advice> {
        match self {
            Self::IsWrite => config.is_write,
            Self::Address => config.address.value,
            Self::AddressLimb0 => config.address.limbs[0],
            Self::AddressLimb1 => config.address.limbs[1],
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

    let prover = MockProver::<Fr>::run(19, &circuit, power_of_randomness).unwrap();
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
        RWCounter::from(0),
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
fn address_limb_mismatch() {
    let rows = vec![Rw::Account {
        rw_counter: 1,
        is_write: false,
        account_address: address!("0x000000000000000000000000000000000cafe002"),
        field_tag: AccountFieldTag::CodeHash,
        value: U256::zero(),
        value_prev: U256::zero(),
    }];
    let overrides = HashMap::from([((AdviceColumn::Address, 1), Fr::from(10))]);

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
        ((AdviceColumn::AddressLimb0, 1), Fr::from(1 << 16)),
        ((AdviceColumn::AddressLimb1, 1), Fr::zero()),
    ]);

    let result = verify_with_overrides(rows, overrides);

    assert_error_matches(result, "mpi limb fits into u16");
}

#[test]
fn nonlexicographic_order_tag() {
    let first = Rw::Memory {
        rw_counter: 1,
        is_write: false,
        call_id: 1,
        memory_address: 10,
        byte: 12,
    };
    let second = Rw::CallContext {
        rw_counter: 2,
        is_write: false,
        call_id: 1,
        field_tag: CallContextFieldTag::IsSuccess,
        value: U256::one(),
    };

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(
        verify(vec![second, first]),
        "upper_limb_difference fits into u16",
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

    assert_eq!(verify(vec![first, second]), Ok(()));
    assert_error_matches(
        verify(vec![second, first]),
        "upper_limb_difference is zero or lower_limb_difference fits into u16",
    );
}

#[test]
fn tx_log_ok() {
    let rows = vec![Rw::TxLog {
        rw_counter: 1,
        is_write: false,
        tx_id: 1,
        log_id: u64::MAX,
        field_tag: TxLogFieldTag::Topic,
        index: u64::MAX as usize,
        value: U256::one(),
    }];

    assert_eq!(verify(rows), Ok(()));
}

#[test]
fn tx_log_failure_1() {
    let rows = vec![Rw::TxLog {
        rw_counter: 1,
        is_write: false,
        tx_id: 1,
        log_id: u64::MAX,
        field_tag: TxLogFieldTag::Topic,
        index: 1,
        value: U256::one(),
    }];

    assert_error_matches(
        verify(rows),
        "tx_log_index is always u64::MAX",
    );
}

#[test]
fn tx_log_failure_2() {
    let rows = vec![Rw::TxLog {
        rw_counter: 1,
        is_write: false,
        tx_id: 1,
        log_id: 1,
        field_tag: TxLogFieldTag::Topic,
        index: u64::MAX as usize,
        value: U256::one(),
    }];

    assert_error_matches(
        verify(rows),
        "tx_log_id is always u64::MAX",
    );
}

fn prover(rows: Vec<Rw>, overrides: HashMap<(AdviceColumn, usize), Fr>) -> MockProver<Fr> {
    let randomness = Fr::rand();
    let circuit = StateCircuit {
        randomness,
        rows,
        overrides,
    };
    let power_of_randomness = circuit.instance();

    MockProver::<Fr>::run(17, &circuit, power_of_randomness).unwrap()
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
    assert_eq!(errors.len(), 1);
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
