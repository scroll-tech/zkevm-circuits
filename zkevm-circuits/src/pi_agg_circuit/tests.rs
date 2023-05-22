//! Test modules for aggregating public inputs

use std::marker::PhantomData;

use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};

use crate::pi_circuit::PublicData;

use super::{
    chunk::ChunkPublicData, multi_batch::MultiBatchPublicData,
    multi_batch_circuit::MultiBatchCircuit, LOG_DEGREE,
};

const TEST_MAX_TXS: usize = 4;

#[test]
fn test_pi_agg_circuit() {
    let public_data = PublicData::default();
    // this chunk spans 1 keccak round
    let chunk_1 = ChunkPublicData::<TEST_MAX_TXS> {
        public_data_vec: vec![
            public_data.clone(),
            public_data.clone(),
            public_data.clone(),
            public_data.clone(),
        ],
    };

    // this chunk spans 2 keccak rounds
    let chunk_2 = ChunkPublicData::<TEST_MAX_TXS> {
        public_data_vec: vec![
            public_data.clone(),
            public_data.clone(),
            public_data.clone(),
            public_data.clone(),
            public_data.clone(),
            public_data,
        ],
    };

    let multi_batch = MultiBatchPublicData {
        public_data_chunks: vec![
            chunk_1.clone(),
            chunk_2.clone(),
            chunk_1.clone(),
            chunk_2.clone(),
            chunk_1.clone(),
            chunk_2,
            chunk_1,
        ],
    };
    let (_, hash_digest) = multi_batch.raw_public_input_hash();
    println!("hash digest: {:?}", hash_digest);
    let raw_public_input: Vec<Fr> = hash_digest
        .0
        .iter()
        .map(|byte| Fr::from(*byte as u64))
        .collect();
    println!("rpi");
    for e in raw_public_input.iter() {
        println!("{:?}", e)
    }

    let multi_batch_circuit = MultiBatchCircuit::<Fr, TEST_MAX_TXS> {
        multi_batch_public_data: multi_batch,
        hash_digest,
        _marker: PhantomData::default(),
    };

    let mock_prover =
        MockProver::<Fr>::run(LOG_DEGREE, &multi_batch_circuit, vec![raw_public_input]).unwrap();

    mock_prover.assert_satisfied_par()
}
