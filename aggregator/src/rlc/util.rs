use halo2_proofs::halo2curves::bn256::Fr;

pub(crate) fn rlc(inputs: &[Fr], randomness: &Fr) -> Fr {
    assert!(inputs.len() > 0);
    let mut acc = inputs[0];
    for input in inputs.iter().skip(1) {
        acc = acc * *randomness + *input;
    }

    acc
}
