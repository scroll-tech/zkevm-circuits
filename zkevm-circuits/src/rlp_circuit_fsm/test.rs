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
        tx = tx.chain_id(*MOCK_CHAIN_ID);
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

    Transaction::new_from_rlp_bytes(1, tx_type, signed_bytes, unsigned_bytes)
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
    let test_bytes = vec![
        // "02f8b1010a8404a75411850f705051f08301724b94dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000006c57d84c55b01f7022999f6c0f95daf0e319dc37000000000000000000000000000000000000000000000000000000003b9aca00c001a0634f6d4b3b4fc658c2c26c1ba0966bd39d7e993b815390f1e778af9cf28d2c22a05410b97e41240ea25eb6250e1af7554cda8991bc4159228c43cfb240503d9870",
        // "02f9025d01825cb38520955af4328521cf92558d830a1bff9400fc00900000002c00be4ef8f49c000211000c43830cc4d0b9015504673a0b85b3000bef3e26e01428d1b525a532ea7513b8f21661d0d1d76d3ecb8e1b9f1c923dbfffae4097020c532d1b995b7e3e37a1aa6369386e5939053779abd3597508b00129cd75b800073edec02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f21661d0d1d76d3ecb8e1b9f1c923dbfffae40970bb86c3dc790b0d7291f864244b559b59b30f850a8cfb40dc7c53760375530e5af29fded5e139893252993820686c92b000094b61ba302f01b0f027d40c80d8f70f77d3884776531f80b21d20e5a6b806300024b2c713b4502988e070f96cf3bea50b4811cd5844e13a81b61a8078c761b0b85b3000bef3e26e01428d1b525a532ea7513b80002594ea302f03b9eb369241e4270796e665ea1afac355cb99f0c32078ab8ba00013c08711b06ed871e5a66bebf0af6fb768d343b1d14a04b5b34ab10cf761b0b85b3000bef3e26e01428d1b525a532ea7513b8000143542ef893f7940b85b3000bef3e26e01428d1b525a532ea7513b8e1a00000000000000000000000000000000000000000000000000000000000000006f85994c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f842a0e1dd9768c9de657aca2536cf1cdd1c4536b13ec81ff764307ea8312aa7a8790da070bc879403c8b875e45ea7afbb591f1fd4bde469db47d5f0e879e44c6798d33e80a0d274986e36e16ec2d4846168d59422f68e4b8ec41690b80bdd2ee65819f238eea03d0394f6daae31ba5a276a3741cc2b3ba79b90024f80df865622a62078e72910",
        "02f90b7b01825cb38520955af4328521cf92558d830a1bff9400fc00900000002c00be4ef8f49c000211000c43830cc4d0b9015504673a0b85b3000bef3e26e01428d1b525a532ea7513b8f21661d0d1d76d3ecb8e1b9f1c923dbfffae4097020c532d1b995b7e3e37a1aa6369386e5939053779abd3597508b00129cd75b800073edec02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f21661d0d1d76d3ecb8e1b9f1c923dbfffae40970bb86c3dc790b0d7291f864244b559b59b30f850a8cfb40dc7c53760375530e5af29fded5e139893252993820686c92b000094b61ba302f01b0f027d40c80d8f70f77d3884776531f80b21d20e5a6b806300024b2c713b4502988e070f96cf3bea50b4811cd5844e13a81b61a8078c761b0b85b3000bef3e26e01428d1b525a532ea7513b80002594ea302f03b9eb369241e4270796e665ea1afac355cb99f0c32078ab8ba00013c08711b06ed871e5a66bebf0af6fb768d343b1d14a04b5b34ab10cf761b0b85b3000bef3e26e01428d1b525a532ea7513b8000143542ef909b0f89b940b85b3000bef3e26e01428d1b525a532ea7513b8f884a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008f8dd94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f8c6a0e1dd9768c9de657aca2536cf1cdd1c4536b13ec81ff764307ea8312aa7a8790da070bc879403c8b875e45ea7afbb591f1fd4bde469db47d5f0e879e44c6798d33ea0f88aa3ad276c350a067c34b2bed705e1a2cd30c7c3154f62ece8ee00939bbd2ea0be11b0e2ba48478671bfcd8fd182e025c26fbfbcf4fdf6952051d6147955a36fa09a1a5a7ef77f3399dea2a1044425aaca7fec294fdfdcacd7a960c9c94d15f0a6a091828b9b711948523369ff1651b6332e98f75bcd940a551dc7247d5af88e71faf8bc945b7e3e37a1aa6369386e5939053779abd3597508f8a5a00000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000002a0697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f20650fa00000000000000000000000000000000000000000000000000000000000000009a00000000000000000000000000000000000000000000000000000000000000000f9018394c7c53760375530e5af29fded5e13989325299382f9016ba00000000000000000000000000000000000000000000000000000000000000010a0000000000000000000000000000000000000000000000000000000000000000ba00000000000000000000000000000000000000000000000000000000000000016a0000000000000000000000000000000000000000000000000000000000000000ea051d155e8243cd6886ab3b36f59778d90f3bbb4af820bc2d4536b23ca13814bfba00000000000000000000000000000000000000000000000000000000000000013a0a7609b0290b911c4b52861d3739b36793fd0e23d9ef78cf2fa96dd1b0cbc764da00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000ca0bda2b1a2a3e35ca431f3c4b50639098537d215591b9ca3db95c24c01795a9981a0000000000000000000000000000000000000000000000000000000000000000df89b94c790b0d7291f864244b559b59b30f850a8cfb40df884a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007f8dd9406ed871e5a66bebf0af6fb768d343b1d14a04b5bf8c6a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000af8bc94f21661d0d1d76d3ecb8e1b9f1c923dbfffae4097f8a5a04d3eb812b43a439547ce41ef251d01e8ad3d0dad3fde6f2bed3d0c0e29dcdd7aa026644b9dbbd32f8882f3abce5ac1575313789ab081b0fe9f3f39c946527bfa27a072fd74a6edf1b99d41f2c81c57f871e198cb7a24fd9861e998221c4aeb776014a0a7609b0290b911c4b52861d3739b36793fd0e23d9ef78cf2fa96dd1b0cbc764da01a3159eb932a0bb66f4d5b9c1cb119796d815774e3c4904b36748d7870d915c2f8dd940f027d40c80d8f70f77d3884776531f80b21d20ef8c6a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007f8bc941a76bffd6d1fc1660e1d0e0552fde51ddbb120cff8a5a06d5257204ebe7d88fd91ae87941cb2dd9d8062b64ae5a2bd2d28ec40b9fbf6dfa030e699f4646032d62d40ca795ecffcb27a2d9d2859f21626b5a588210198e7a6a0c929f5ae32c0eabfbdd06198210bc49736d88e6501f814a66dd5b2fa59508b3ea0ea52bdd009b752a3e91262d66aae31638bc36b449d247d61d646b87a733d7d5da0877978b096db3b11862d0cdfe5f5b74f30fd7d5d29e8ce80626ed8a8bbef1beef8dd944502988e070f96cf3bea50b4811cd5844e13a81bf8c6a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007f8dd949eb369241e4270796e665ea1afac355cb99f0c32f8c6a00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000cf85994f9a2d7e60a3297e513317ad1d7ce101cc4c6c8f6f842a04b376a11d00750d42abab4d4e465d5dc4d9b1286d77cf0c819f028213ea08bdfa072fd74a6edf1b99d41f2c81c57f871e198cb7a24fd9861e998221c4aeb77601480a0d274986e36e16ec2d4846168d59422f68e4b8ec41690b80bdd2ee65819f238eea03d0394f6daae31ba5a276a3741cc2b3ba79b90024f80df865622a62078e72910",
    ];

    let mut txs: Vec<Transaction> = vec![];
    for (idx, bytes) in test_bytes.into_iter().enumerate() {
        let raw_tx_rlp_bytes = hex::decode(bytes).expect("decode tx's hex shall not fail");

        let eth_tx = EthTransaction::decode(&Rlp::new(&raw_tx_rlp_bytes))
            .expect("decode tx's rlp bytes shall not fail");

        let eth_tx_req: Eip1559TransactionRequest = (&eth_tx).into();
        let typed_tx: TypedTransaction = eth_tx_req.into();
        let rlp_unsigned = typed_tx.rlp().to_vec();

        let tx = Transaction::new_from_rlp_bytes(
            idx + 1,
            TxType::Eip1559,
            raw_tx_rlp_bytes,
            rlp_unsigned,
        );

        txs.push(tx);
    }

    assert!(
        txs.len() <= 10,
        "Maximum test cases for Rlp circuit can't exceed 10"
    );

    let rlp_circuit = RlpCircuit::<Fr, Transaction> {
        txs,
        max_txs: 10,
        size: 2 << 13,
        _marker: Default::default(),
    };

    let mock_prover = MockProver::run(16, &rlp_circuit, vec![]);
    // assert!(mock_prover.is_ok());
    let mock_prover = mock_prover.unwrap();
    if let Err(errors) = mock_prover.verify_par() {
        log::debug!("errors.len() = {}", errors.len());
    }

    mock_prover.assert_satisfied_par();
}

#[test]
fn test_eip2930_tx() {
    let bytes = "01f8710183018c418502edc2c0dc8307a1209480464c21a0639510142d510c5be486f1bd801cdb87f753258d79d80080c001a0563304e8f2306c3fafed471bee76db83690ec113965c6775a8a94625dcb03774a05bcc59f5737520f7d0dc8b4f967635473e0a58526ce9ddd69c4a2454c9955f12";

    let raw_tx_rlp_bytes = hex::decode(bytes).expect("decode tx's hex shall not fail");

    let eth_tx = EthTransaction::decode(&Rlp::new(&raw_tx_rlp_bytes))
        .expect("decode tx's rlp bytes shall not fail");

    let eth_tx_req: Eip2930TransactionRequest = (&eth_tx).into();
    let typed_tx: TypedTransaction = eth_tx_req.into();
    let rlp_unsigned = typed_tx.rlp().to_vec();

    let tx = Transaction::new_from_rlp_bytes(1, TxType::Eip2930, raw_tx_rlp_bytes, rlp_unsigned);
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
