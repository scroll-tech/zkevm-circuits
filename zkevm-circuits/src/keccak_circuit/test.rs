use crate::keccak_circuit::KeccakCircuit;
use eth_types::Field;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use log::error;

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
    let k = 14;
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
    let k = 14;
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
