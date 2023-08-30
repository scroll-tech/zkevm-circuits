#![allow(unused_imports)]
use crate::{
    bytecode_circuit::{bytecode_unroller::*, circuit::BytecodeCircuit, TestBytecodeCircuit},
    table::BytecodeFieldTag,
    util::{is_push_with_data, keccak, unusable_rows, Challenges, SubCircuit},
};
use bus_mapping::{evm::OpcodeId, state_db::CodeDB};
use eth_types::{Bytecode, Field, ToWord, Word};
use log::error;

use halo2_proofs::{
    dev::MockProver,
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::env::var;

#[test]
fn bytecode_circuit_unusable_rows() {
    assert_eq!(
        BytecodeCircuit::<Fr>::unusable_rows(),
        unusable_rows::<Fr, BytecodeCircuit::<Fr>>(),
    )
}

impl<F: Field> BytecodeCircuit<F> {
    /// Verify that the selected bytecode fulfills the circuit
    pub fn verify_raw(k: u32, bytecodes: Vec<Vec<u8>>) {
        let unrolled: Vec<_> = bytecodes.iter().map(|b| unroll(b.clone())).collect();
        Self::verify(k, unrolled, true);
    }

    pub(crate) fn verify(k: u32, bytecodes: Vec<UnrolledBytecode<F>>, success: bool) {
        let circuit = BytecodeCircuit::<F>::new(bytecodes, 2usize.pow(k));

        let prover = MockProver::<F>::run(k, &circuit, Vec::new()).unwrap();
        let result = prover.verify();
        if let Err(failures) = &result {
            for failure in failures.iter() {
                error!("{}", failure);
            }
        }
        assert_eq!(result.is_ok(), success);
    }
}

/// Test bytecode circuit with unrolled bytecode
pub fn test_bytecode_circuit_unrolled<F: Field>(
    k: u32,
    bytecodes: Vec<UnrolledBytecode<F>>,
    success: bool,
) {
    let circuit = BytecodeCircuit::<F>::new(bytecodes, 2usize.pow(k));
    let prover = MockProver::<F>::run(k, &circuit, Vec::new()).unwrap();
    let result = prover.verify_par();
    if let Err(failures) = &result {
        for failure in failures.iter() {
            error!("{}", failure);
        }
    }
    let error_msg = if success { "valid" } else { "invalid" };
    assert_eq!(result.is_ok(), success, "proof must be {error_msg}");
}

/// Verify unrolling code
fn bytecode_unrolling() {
    let k = 10;
    let mut rows = vec![];
    let mut bytecode = Bytecode::default();
    // First add all non-push bytes, which should all be seen as code
    for byte in 0u8..=255u8 {
        if !is_push_with_data(byte) {
            bytecode.write(byte, true);
            rows.push(BytecodeRow {
                code_hash: Word::zero(),
                tag: Fr::from(BytecodeFieldTag::Byte as u64),
                index: Fr::from(rows.len() as u64),
                is_code: Fr::from(true as u64),
                value: Fr::from(byte as u64),
            });
        }
    }
    // Now add the different push ops
    for n in 1..=32 {
        let data_byte = OpcodeId::PUSH32.as_u8();
        bytecode.push(
            n,
            Word::from_little_endian(&vec![data_byte; n as usize][..]),
        );
        rows.push(BytecodeRow {
            code_hash: Word::zero(),
            tag: Fr::from(BytecodeFieldTag::Byte as u64),
            index: Fr::from(rows.len() as u64),
            is_code: Fr::from(true as u64),
            value: Fr::from(OpcodeId::PUSH0.as_u64() + n as u64),
        });
        for _ in 0..n {
            rows.push(BytecodeRow {
                code_hash: Word::zero(),
                tag: Fr::from(BytecodeFieldTag::Byte as u64),
                index: Fr::from(rows.len() as u64),
                is_code: Fr::from(false as u64),
                value: Fr::from(data_byte as u64),
            });
        }
    }
    // Set the code_hash of the complete bytecode in the rows
    let code_hash = CodeDB::hash(&bytecode.to_vec()[..]).to_word();
    for row in rows.iter_mut() {
        row.code_hash = code_hash;
    }
    rows.insert(
        0,
        BytecodeRow {
            code_hash,
            tag: Fr::from(BytecodeFieldTag::Header as u64),
            index: Fr::zero(),
            is_code: Fr::zero(),
            value: Fr::from(bytecode.to_vec().len() as u64),
        },
    );
    // Unroll the bytecode
    let unrolled = unroll(bytecode.to_vec());
    // Check if the bytecode was unrolled correctly
    assert_eq!(
        UnrolledBytecode {
            bytes: bytecode.to_vec(),
            rows,
        },
        unrolled,
    );
    // Verify the unrolling in the circuit
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled], true);
}

/// Tests a fully empty circuit
#[test]
fn bytecode_empty() {
    let k = 9;
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unroll(vec![])], true);
}

#[test]
fn bytecode_simple() {
    let k = 9;
    let bytecodes = vec![unroll(vec![7u8]), unroll(vec![6u8]), unroll(vec![5u8])];
    test_bytecode_circuit_unrolled::<Fr>(k, bytecodes, true);
}

/// Tests a fully full circuit
#[test]
fn bytecode_full() {
    let k = 9;
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unroll(vec![7u8; 2usize.pow(k) - 8])], true);
}

#[test]
fn bytecode_last_row_with_byte() {
    let k = 9;
    // Last row must be a padding row, so we have one row less for actual bytecode
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unroll(vec![7u8; 2usize.pow(k) - 7])], false);
}

/// Tests a circuit with incomplete bytecode
#[test]
fn bytecode_incomplete() {
    let k = 9;
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unroll(vec![7u8; 2usize.pow(k) + 1])], false);
}

/// Tests multiple bytecodes in a single circuit
#[test]
fn bytecode_push() {
    let k = 9;
    test_bytecode_circuit_unrolled::<Fr>(
        k,
        vec![
            unroll(vec![]),
            unroll(vec![OpcodeId::PUSH32.as_u8()]),
            unroll(vec![OpcodeId::PUSH32.as_u8(), OpcodeId::ADD.as_u8()]),
            unroll(vec![OpcodeId::ADD.as_u8(), OpcodeId::PUSH32.as_u8()]),
            unroll(vec![
                OpcodeId::ADD.as_u8(),
                OpcodeId::PUSH32.as_u8(),
                OpcodeId::ADD.as_u8(),
            ]),
        ],
        true,
    );
}

/// Test invalid code_hash data
#[test]
fn bytecode_invalid_hash_data() {
    let k = 9;
    let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
    let unrolled = unroll(bytecode);
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
    // Change the code_hash on the first position (header row)
    {
        let mut invalid = unrolled;
        invalid.rows[0].code_hash += Word::one();
        log::trace!("bytecode_invalid_hash_data: Change the code_hash on the first position");
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
    // TODO: other rows code_hash are ignored by the witness generation, to
    // test other rows invalid code_hash, we would need to inject an evil
    // witness.
}

/// Test invalid index
#[test]
fn bytecode_invalid_index() {
    let k = 9;
    let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
    let unrolled = unroll(bytecode);
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
    // Start the index at 1
    {
        let mut invalid = unrolled.clone();
        for row in invalid.rows.iter_mut() {
            row.index += Fr::one();
        }
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
    // Don't increment an index once
    {
        let mut invalid = unrolled;
        invalid.rows.last_mut().unwrap().index -= Fr::one();
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
}

/// Test invalid byte data
fn bytecode_invalid_byte_data() {
    let k = 9;
    let bytecode = vec![8u8, 2, 3, 8, 9, 7, 128];
    let unrolled = unroll(bytecode);
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
    // Change the first byte
    {
        let mut invalid = unrolled.clone();
        invalid.rows[1].value = Fr::from(9u64);
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
    // Change a byte on another position
    {
        let mut invalid = unrolled.clone();
        invalid.rows[5].value = Fr::from(6u64);
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
    // Set a byte value out of range
    {
        let mut invalid = unrolled;
        invalid.rows[3].value = Fr::from(256u64);
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
}

/// Test invalid is_code data
#[test]
fn bytecode_invalid_is_code() {
    let k = 9;
    let bytecode = vec![
        OpcodeId::ADD.as_u8(),
        OpcodeId::PUSH1.as_u8(),
        OpcodeId::PUSH1.as_u8(),
        OpcodeId::SUB.as_u8(),
        OpcodeId::PUSH7.as_u8(),
        OpcodeId::ADD.as_u8(),
        OpcodeId::PUSH6.as_u8(),
    ];
    let unrolled = unroll(bytecode);
    test_bytecode_circuit_unrolled::<Fr>(k, vec![unrolled.clone()], true);
    // Mark the 3rd byte as code (is push data from the first PUSH1)
    {
        let mut invalid = unrolled.clone();
        invalid.rows[3].is_code = Fr::one();
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
    // Mark the 4rd byte as data (is code)
    {
        let mut invalid = unrolled.clone();
        invalid.rows[4].is_code = Fr::zero();
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
    // Mark the 7th byte as code (is data for the PUSH7)
    {
        let mut invalid = unrolled;
        invalid.rows[7].is_code = Fr::one();
        test_bytecode_circuit_unrolled::<Fr>(k, vec![invalid], false);
    }
}

#[test]
#[should_panic]
#[allow(clippy::clone_on_copy)]
fn bytecode_soundness_bug_1() {
    let k = 9;
    let bytecode = vec![1, 2, 3, 4];
    let bytecode_len = bytecode.len();
    let unrolled = unroll(bytecode);
    let unrolled_len = unrolled.rows.len();
    let code_hash = unrolled.rows[0].code_hash.clone();
    let mut index = bytecode_len as u64;
    let size = 100;
    let minimum_rows = 8;

    let mut overwrite = unrolled.clone();
    for i in 0..size - minimum_rows + 3 {
        if i >= unrolled_len {
            overwrite.rows.push(BytecodeRow {
                code_hash: code_hash.clone(),
                tag: Fr::one(),
                index: Fr::from(index),
                is_code: Fr::one(),
                value: Fr::from((i % 10 + 1) as u64),
            });
            index += 1;
        }
    }
    let mut circuit = BytecodeCircuit::<Fr>::new(vec![unrolled], size);
    circuit.overwrite = overwrite;

    let prover = MockProver::<Fr>::run(k, &circuit, Vec::new()).unwrap();
    prover.assert_satisfied_par();
}

/// fill bytecodes_num * bytecode_len bytes to the witness table
fn fillup_codebytes<F: Field>(
    bytecodes_num: usize,
    bytecode_len: usize,
) -> Vec<UnrolledBytecode<F>> {
    fn valid_or(base: OpcodeId, or: OpcodeId) -> OpcodeId {
        match base {
            OpcodeId::INVALID(_) => or,
            _ => base,
        }
    }

    let mut codebytes = vec![];
    (0..bytecodes_num).for_each(|_| {
        let bytecodes = (0..bytecode_len)
            .map(|v| valid_or(OpcodeId::from(v as u8), OpcodeId::STOP).as_u8())
            .collect::<Vec<u8>>();
        let unrolled_bytes = unroll::<F>(bytecodes);
        codebytes.push(unrolled_bytes);
    });
    codebytes
}

fn set_assignment_env_var(value: &str) {
    std::env::set_var("CIRCUIT_ASSIGNMENT_TYPE", value);
    let assign_var = std::env::var("CIRCUIT_ASSIGNMENT_TYPE")
        .ok()
        .unwrap_or_default();
    log::info!("CIRCUIT_ASSIGNMENT_TYPE: {}", assign_var);
}

/// Bytecode circuit parallel assignment test
/// modiefied from `fn bench_bytecode_circuit_prover()`
/// in: circuit-benchmarks/src/bytecode_circuit.rs
///
/// Run with:
/// `cargo test --package zkevm-circuits --lib
/// bytecode_circuit::test::bytecode_circuit_parallel_assignment --features scroll,parallel_syn --
/// --nocapture`
#[test]
#[cfg(feature = "scroll")]
#[cfg(feature = "parallel_syn")]
fn bytecode_circuit_parallel_assignment() {
    // Contract code size exceeds 24576 bytes may not be deployable on Mainnet.
    const MAX_BYTECODE_LEN: usize = 4096;

    let degree: u32 = 15;
    let num_rows = 1 << degree;
    const NUM_BLINDING_ROWS: usize = 7 - 1;
    let max_bytecode_row_num = num_rows - NUM_BLINDING_ROWS;
    let bytecode_len = std::cmp::min(MAX_BYTECODE_LEN, max_bytecode_row_num);
    let bytecodes_num: usize = max_bytecode_row_num / bytecode_len;
    log::info!(
        "Bytecode length: {}, Bytecodes number: {}",
        bytecode_len,
        bytecodes_num
    );

    // Create the circuit
    let bytecode_circuit = TestBytecodeCircuit::<Fr>::new(
        fillup_codebytes(bytecodes_num, bytecode_len),
        2usize.pow(degree),
    );

    // Initialize the polynomial commitment parameters
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x5d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    // Setup generation
    log::info!(
        "test bytecode circuit parallel assignment with degree = {}",
        degree
    );
    let general_params = ParamsKZG::<Bn256>::setup(degree, &mut rng);
    let verifier_params: ParamsVerifierKZG<Bn256> = general_params.verifier_params().clone();

    // Initialize the proving key
    // The serial assignment is used to generate pk and vk,
    // which are then used to verify the proof generated by the parallel assignment
    set_assignment_env_var("serial");
    let vk = keygen_vk(&general_params, &bytecode_circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&general_params, vk, &bytecode_circuit).expect("keygen_pk should not fail");

    // Create a proof
    let mut transcript = Blake2bWrite::<_, G1Affine, Challenge255<_>>::init(vec![]);

    // Proof generation
    // Set parallel assignment env var
    set_assignment_env_var("parallel");
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        XorShiftRng,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        TestBytecodeCircuit<Fr>,
    >(
        &general_params,
        &pk,
        &[bytecode_circuit],
        &[&[]],
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    let proof = transcript.finalize();

    let mut verifier_transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleStrategy::new(&general_params);
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        &verifier_params,
        pk.get_vk(),
        strategy,
        &[&[]],
        &mut verifier_transcript,
    )
    .expect("failed to verify bench circuit");

    set_assignment_env_var("");
}
