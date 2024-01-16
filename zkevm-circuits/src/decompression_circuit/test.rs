#[test]
fn test_basic() {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

    use crate::decompression_circuit::DecompressionCircuit;

    let circuit = DecompressionCircuit::<Fr>::default();
    let mock_prover = MockProver::run(17, &circuit, vec![]);
    assert!(mock_prover.is_ok());
    let mock_prover = mock_prover.unwrap();
    if let Err(errors) = mock_prover.verify_par() {
        log::debug!("errors.len() = {}", errors.len());
    }

    mock_prover.assert_satisfied_par();
}
