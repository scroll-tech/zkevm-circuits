#![allow(unused_imports)]
use super::*;
use crate::util::unusable_rows;
use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{Circuit, ConstraintSystem, Error},
};
use log::error;
use std::iter::zip;

use super::util::{target_part_sizes, target_part_sizes_rot, WordParts};

// This needs to be tested independent since it sets the environment variable
// which might affect other tests.
#[ignore]
#[test]
fn serial_keccak_circuit_unusable_rows() {
    for keccak_rows in NUM_BYTES_PER_WORD + 1..=32 {
        std::env::set_var("KECCAK_ROWS", format!("{keccak_rows}"));
        assert_eq!(
            KeccakCircuit::<Fr>::unusable_rows(),
            unusable_rows::<Fr, KeccakCircuit::<Fr>>(),
        )
    }
    std::env::set_var("KECCAK_ROWS", format!("{DEFAULT_KECCAK_ROWS}"));
}

fn verify<F: Field>(k: u32, inputs: Vec<Vec<u8>>, success: bool) {
    let circuit = KeccakCircuit::new(2usize.pow(k), inputs);

    let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
    let verify_result = prover.verify();
    if verify_result.is_ok() != success {
        if let Some(errors) = verify_result.err() {
            for error in errors.iter() {
                error!("{}", error);
            }
        }
        panic!();
    }
}

#[test]
fn packed_multi_keccak_simple() {
    let k = 19;
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    verify::<Fr>(k, inputs, true);
}

#[test]
fn variadic_size_check() {
    let k = 19;
    let num_rows = 2usize.pow(k);
    // Empty
    let inputs = vec![];
    let circuit = KeccakCircuit::new(num_rows, inputs);
    let prover1 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

    // Non-empty
    let inputs = vec![
        vec![],
        (0u8..1).collect::<Vec<_>>(),
        (0u8..135).collect::<Vec<_>>(),
        (0u8..136).collect::<Vec<_>>(),
        (0u8..200).collect::<Vec<_>>(),
    ];
    let circuit = KeccakCircuit::new(num_rows, inputs);
    let prover2 = MockProver::<Fr>::run(k, &circuit, vec![]).unwrap();

    assert_eq!(prover1.fixed(), prover2.fixed());
    assert_eq!(prover1.permutation(), prover2.permutation());
}

#[test]
fn test_target_part_sizes() {
    // Uniform 8 parts of 8 bits each.
    assert_eq!(target_part_sizes_rot(8, 0), vec![8, 8, 8, 8, 8, 8, 8, 8]);
    // With rotations.
    assert_eq!(target_part_sizes_rot(8, 1), vec![1, 8, 8, 8, 8, 8, 8, 8, 7]);
    assert_eq!(target_part_sizes_rot(8, 2), vec![2, 8, 8, 8, 8, 8, 8, 8, 6]);
    assert_eq!(target_part_sizes_rot(8, 8), vec![8, 8, 8, 8, 8, 8, 8, 8]);
    assert_eq!(target_part_sizes_rot(8, 9), vec![8, 1, 8, 8, 8, 8, 8, 8, 7]);

    // Parts of 11 bits and the remaining 9 bits.
    assert_eq!(target_part_sizes_rot(11, 0), vec![11, 11, 11, 11, 11, 9]);
    // With rotations.
    assert_eq!(target_part_sizes_rot(11, 1), vec![1, 11, 11, 11, 11, 11, 8]);
    assert_eq!(target_part_sizes_rot(11, 2), vec![2, 11, 11, 11, 11, 11, 7]);
    assert_eq!(target_part_sizes_rot(11, 11), vec![11, 11, 11, 11, 11, 9]);
    assert_eq!(
        target_part_sizes_rot(11, 12),
        vec![11, 1, 11, 11, 11, 11, 8]
    );

    // "uniform" is the same as rot=0
    assert_eq!(target_part_sizes(8), target_part_sizes_rot(8, 0));
    assert_eq!(target_part_sizes(11), target_part_sizes_rot(11, 0));
}

#[test]
fn test_word_parts() {
    {
        let word = WordParts::new(11, 0, true);
        // Parts of bits.
        let expected: Vec<Vec<usize>> = vec![
            (0..11).collect(),  // Length 11
            (11..22).collect(), // …
            (22..33).collect(), // …
            (33..44).collect(), // …
            (44..55).collect(), // …
            (55..64).collect(), // Length 9
        ];
        assert_eq!(word.parts.len(), expected.len());
        for (part, xbits) in zip(word.parts, expected) {
            assert_eq!(part.bits, xbits);
        }
    }

    {
        let word = WordParts::new(11, 1, false);
        // Parts of bits.
        let expected: Vec<Vec<usize>> = vec![
            (0..11).collect(),  // Length 11
            (11..22).collect(), // …
            (22..33).collect(), // …
            (33..44).collect(), // …
            (44..55).collect(), // …
            (55..63).collect(), // Length 8
            (63..64).collect(), // Length 1
        ];
        assert_eq!(word.parts.len(), expected.len());
        for (part, xbits) in zip(word.parts, expected) {
            assert_eq!(part.bits, xbits);
        }
    }
}
