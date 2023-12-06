#![allow(unused_imports)]
use crate::{rlp_circuit_fsm::RlpCircuit, witness::Transaction};
use eth_types::{geth_types::TxType, word, Address};
use ethers_core::{
    types::{
        transaction::eip2718::TypedTransaction, Eip1559TransactionRequest,
        Eip2930TransactionRequest, Transaction as EthTransaction, TransactionRequest,
    },
    utils::rlp::{Decodable, Rlp},
};
use ethers_signers::Wallet;
use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
use mock::{eth, MOCK_CHAIN_ID};
use rand::rngs::OsRng;

#[cfg(test)]
fn get_tx(is_eip155: bool) -> Transaction {
    let rng = &mut OsRng;
    let from = Wallet::new(rng);
    let mut tx = TransactionRequest::new()
        .to(Address::random())
        .value(eth(10))
        .data(Vec::new())
        .gas_price(word!("0x4321"))
        .gas(word!("0x77320"))
        .nonce(word!("0x7f"));
    if is_eip155 {
        tx = tx.chain_id(MOCK_CHAIN_ID);
    }
    let (tx_type, unsigned_bytes) = if is_eip155 {
        (TxType::Eip155, tx.rlp().to_vec())
    } else {
        (TxType::PreEip155, tx.rlp_unsigned().to_vec())
    };
    let typed_tx: TypedTransaction = tx.into();
    let sig = from.sign_transaction_sync(&typed_tx).unwrap();
    let signed_bytes = typed_tx.rlp_signed(&sig).to_vec();

    log::debug!("num_unsigned_bytes: {}", unsigned_bytes.len());
    log::debug!("num_signed_bytes: {}", signed_bytes.len());

    Transaction::new_from_rlp_bytes(tx_type, signed_bytes, unsigned_bytes)
}

#[test]
fn test_eip_155_tx() {
    let tx = get_tx(true);
    let rlp_circuit = RlpCircuit::<Fr, Transaction> {
        txs: vec![tx],
        max_txs: 10,
        size: 500,
        _marker: Default::default(),
    };

    let mock_prover = MockProver::run(17, &rlp_circuit, vec![]);
    assert!(mock_prover.is_ok());
    let mock_prover = mock_prover.unwrap();
    if let Err(errors) = mock_prover.verify_par() {
        log::debug!("errors.len() = {}", errors.len());
    }

    mock_prover.assert_satisfied_par();
}

#[test]
fn test_pre_eip155_tx() {
    let tx = get_tx(false);
    let rlp_circuit = RlpCircuit::<Fr, Transaction> {
        txs: vec![tx],
        max_txs: 10,
        size: 500,
        _marker: Default::default(),
    };

    let mock_prover = MockProver::run(17, &rlp_circuit, vec![]);
    assert!(mock_prover.is_ok());
    let mock_prover = mock_prover.unwrap();
    if let Err(errors) = mock_prover.verify_par() {
        log::debug!("errors.len() = {}", errors.len());
    }

    mock_prover.assert_satisfied_par();
}

#[test]
fn test_l1_msg_tx() {
    let raw_tx_rlp_bytes = hex::decode("7ef901b60b825dc0941a258d17bf244c4df02d40343a7626a9d321e10580b901848ef1332e000000000000000000000000ea08a65b1829af779261e768d609e59279b510f2000000000000000000000000f2ec6b6206f6208e8f9b394efc1a01c1cbde77750000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a4232e87480000000000000000000000002b5ad5c4795c026514f8317c7a215e218dccd6cf0000000000000000000000002b5ad5c4795c026514f8317c7a215e218dccd6cf0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000094478cdd110520a8e733e2acf9e543d2c687ea5239")
        .expect("decode tx's hex shall not fail");

    let eth_tx = EthTransaction::decode(&Rlp::new(&raw_tx_rlp_bytes))
        .expect("decode tx's rlp bytes shall not fail");

    // testing sign RLP decoding
    let tx = Transaction::new_from_rlp_signed_bytes(TxType::L1Msg, eth_tx.rlp().to_vec());
    let rlp_circuit = RlpCircuit::<Fr, Transaction> {
        txs: vec![tx],
        max_txs: 10,
        size: 1000,
        _marker: Default::default(),
    };

    let mock_prover = MockProver::run(14, &rlp_circuit, vec![]);
    assert!(mock_prover.is_ok());

    let mock_prover = mock_prover.unwrap();

    mock_prover.assert_satisfied_par();
}

#[test]
fn test_eip1559_tx() {
    let raw_tx_rlp_bytes = hex::decode("02f901e901833c3139842b27f14d86012309ce540083055ca8945f65f7b609678448494de4c87521cdf6cef1e93280b8e4fa558b7100000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000016a217dedfacdf9c23edb84b57154f26a15848e60000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000028cad80bb7cf17e27c4c8f893f7945f65f7b609678448494de4c87521cdf6cef1e932e1a0d2dc2a0881b05440a4908cf506b4871b1f7eaa46ea0c5dfdcda5f52bc17164a4f8599495ad61b0a150d79219dcf64e1e6cc01f0b64c4cef842a0ba03decd934aae936605e9d437c401439ec4cefbad5795e0965100f929fe339ca0b36e2afa1a25492257090107ad99d079032e543c8dd1ffcd44cf14a96d3015ac80a0821193127789b107351f670025dd3b862f5836e5155f627a29741a251e8d28e8a07ea1e82b1bf6f29c5d0f1e4024acdb698086ac40c353704d7d5e301fb916f2e3")
        .expect("decode tx's hex shall not fail");

    let eth_tx = EthTransaction::decode(&Rlp::new(&raw_tx_rlp_bytes))
        .expect("decode tx's rlp bytes shall not fail");

    let eth_tx_req: Eip1559TransactionRequest = (&eth_tx).into();
    let typed_tx: TypedTransaction = eth_tx_req.into();
    let rlp_unsigned = typed_tx.rlp().to_vec();

    let tx = Transaction::new_from_rlp_bytes(TxType::Eip1559, raw_tx_rlp_bytes, rlp_unsigned);
    let rlp_circuit = RlpCircuit::<Fr, Transaction> {
        txs: vec![tx],
        max_txs: 10,
        size: 1000,
        _marker: Default::default(),
    };

    let mock_prover = MockProver::run(14, &rlp_circuit, vec![]);
    assert!(mock_prover.is_ok());
    let mock_prover = mock_prover.unwrap();
    if let Err(errors) = mock_prover.verify_par() {
        log::debug!("errors.len() = {}", errors.len());
    }

    mock_prover.assert_satisfied_par();
}

#[test]
fn test_eip2930_tx() {
    let raw_tx_rlp_bytes = hex::decode("01f8710183018c418502edc2c0dc8307a1209480464c21a0639510142d510c5be486f1bd801cdb87f753258d79d80080c001a0563304e8f2306c3fafed471bee76db83690ec113965c6775a8a94625dcb03774a05bcc59f5737520f7d0dc8b4f967635473e0a58526ce9ddd69c4a2454c9955f12")
        .expect("decode tx's hex shall not fail");

    let eth_tx = EthTransaction::decode(&Rlp::new(&raw_tx_rlp_bytes))
        .expect("decode tx's rlp bytes shall not fail");

    let eth_tx_req: Eip2930TransactionRequest = (&eth_tx).into();
    let typed_tx: TypedTransaction = eth_tx_req.into();
    let rlp_unsigned = typed_tx.rlp().to_vec();

    let tx = Transaction::new_from_rlp_bytes(TxType::Eip2930, raw_tx_rlp_bytes, rlp_unsigned);
    let rlp_circuit = RlpCircuit::<Fr, Transaction> {
        txs: vec![tx],
        max_txs: 10,
        size: 1000,
        _marker: Default::default(),
    };

    let mock_prover = MockProver::run(14, &rlp_circuit, vec![]);
    assert!(mock_prover.is_ok());
    let mock_prover = mock_prover.unwrap();
    if let Err(errors) = mock_prover.verify_par() {
        log::debug!("errors.len() = {}", errors.len());
    }

    mock_prover.assert_satisfied_par();
}
