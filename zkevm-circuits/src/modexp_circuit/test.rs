#![allow(unused_imports)]
use super::*;
use halo2_proofs::dev::MockProver;

#[test]
fn test_modexp_circuit_00() {
    let base = Word::from(1u128);
    let exp = Word::from(2u128);
    let modulus = Word::from(7u128);
    let (_, result) = base.pow(exp).div_mod(modulus);
    let event1 = BigModExp {
        base,
        exponent: exp,
        modulus,
        result,
    };
    let test_circuit = ModExpCircuit(vec![event1], Default::default());
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_modexp_circuit_01() {
    let base = Word::from(1u128);
    let exp = Word::from(2u128);
    let modulus = Word::from(7u128);
    let (_, result) = base.pow(exp).div_mod(modulus);
    let event1 = BigModExp {
        base,
        exponent: exp,
        modulus,
        result,
    };
    let test_circuit = ModExpCircuit(vec![event1], Default::default());
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
#[test]
fn test_modexp_circuit_02() {
    let base = Word::from(2u128);
    let exp = Word::from(2u128);
    let modulus = Word::from(7u128);
    let (_, result) = base.pow(exp).div_mod(modulus);
    let event1 = BigModExp {
        base,
        exponent: exp,
        modulus,
        result,
    };
    let test_circuit = ModExpCircuit(vec![event1], Default::default());
    let prover = MockProver::run(16, &test_circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
