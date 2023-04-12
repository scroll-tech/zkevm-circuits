#![allow(unused_imports)]
use std::cmp::max;

use super::*;
use crate::util::log2_ceil;
use eth_types::{address, U64};
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use mock::AddrOrWallet;
const NUM_BLINDING_ROWS: usize = 64;

fn run<F: Field>(
    txs: Vec<Transaction>,
    chain_id: u64,
    max_txs: usize,
    max_calldata: usize,
) -> Result<(), Vec<VerifyFailure>> {
    let k = max(
        19,
        log2_ceil(TxCircuit::<F>::min_num_rows(max_txs, max_calldata)),
    );
    // SignVerifyChip -> ECDSAChip -> MainGate instance column
    let circuit = TxCircuit::<F>::new(max_txs, max_calldata, chain_id, txs);

    let prover = match MockProver::run(k, &circuit, vec![vec![]]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    prover.verify()
}

#[test]
fn tx_circuit_2tx_2max_tx() {
    const NUM_TXS: usize = 2;
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 32;

    assert_eq!(
        run::<Fr>(
            [
                mock::CORRECT_MOCK_TXS[1].clone(),
                mock::CORRECT_MOCK_TXS[3].clone()
            ]
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                let mut mock_tx = tx.clone();
                mock_tx.transaction_idx((i + 1) as u64);
                mock_tx.into()
            })
            .collect(),
            mock::MOCK_CHAIN_ID.as_u64(),
            MAX_TXS,
            MAX_CALLDATA
        ),
        Ok(())
    );
}

#[test]
fn tx_circuit_0tx_1max_tx() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

    assert_eq!(run::<Fr>(vec![], chain_id, MAX_TXS, MAX_CALLDATA), Ok(()));
}

#[test]
fn tx_circuit_1tx_1max_tx() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

    let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

    assert_eq!(run::<Fr>(vec![tx], chain_id, MAX_TXS, MAX_CALLDATA), Ok(()));
}

#[test]
fn tx_circuit_1tx_2max_tx() {
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 32;

    let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();

    let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

    assert_eq!(run::<Fr>(vec![tx], chain_id, MAX_TXS, MAX_CALLDATA), Ok(()));
}

#[cfg(feature = "reject-eip2718")]
#[test]
fn tx_circuit_bad_address() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let mut tx = mock::CORRECT_MOCK_TXS[0].clone();
    // This address doesn't correspond to the account that signed this tx.
    tx.from = AddrOrWallet::from(address!("0x1230000000000000000000000000000000000456"));

    assert!(run::<Fr>(
        vec![tx.into()],
        mock::MOCK_CHAIN_ID.as_u64(),
        MAX_TXS,
        MAX_CALLDATA
    )
    .is_err(),);
}

#[test]
fn tx_circuit_to_is_zero() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let chain_id: u64 = mock::MOCK_CHAIN_ID.as_u64();
    let mut tx = mock::CORRECT_MOCK_TXS[5].clone();
    tx.transaction_index = U64::from(1);

    assert_eq!(
        run::<Fr>(vec![tx.into()], chain_id, MAX_TXS, MAX_CALLDATA),
        Ok(())
    );
}
