#![allow(unused_imports)]
use super::*;

use eth_types::U256;
use halo2_proofs::dev::MockProver;

#[test]
fn test_modexp_circuit_00() {
    let event1 = construct_modexp(Word::from(1u128), Word::from(3u128), Word::from(7u128));

    let test_circuit = ModExpCircuit(vec![event1], Default::default());
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_modexp_circuit_01() {
    let event1 = construct_modexp(Word::from(1u128), Word::from(2u128), Word::from(7u128));

    let test_circuit = ModExpCircuit(vec![event1], Default::default());
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
#[test]
fn test_modexp_circuit_02() {
    let event1 = construct_modexp(Word::from(2u128), Word::from(2u128), Word::from(7u128));
    let event2 = construct_modexp(Word::from(3u128), Word::from(21u128), Word::from(78u128));

    let test_circuit = ModExpCircuit(vec![event1, event2], Default::default());
    let prover = MockProver::run(17, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

// test all zeros case (exp == mod == base == 0)
#[test]
fn test_modexp_circuit_03() {
    let event1 = construct_modexp(Word::from(0u128), Word::from(0u128), Word::from(0u128));

    let test_circuit = ModExpCircuit(vec![event1], Default::default());
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

fn construct_modexp(base: U256, exp: U256, modulus: U256) -> BigModExp {
    let result = if modulus == Word::zero() {
        Word::zero()
    } else {
        base.pow(exp).div_mod(modulus).1
    };

    BigModExp {
        base,
        exponent: exp,
        modulus,
        result,
    }
}
