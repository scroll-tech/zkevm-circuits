#![allow(unused_imports)]

use ethers_core::{
    types::{
        transaction::eip2718::TypedTransaction, Eip1559TransactionRequest, NameOrAddress,
        Signature, Transaction as EthTransaction, TransactionRequest,
    },
    utils::{
        keccak256,
        rlp::{Decodable, Rlp},
    },
};
use std::cmp::max;

use super::*;
use crate::{
    sig_circuit::{SigCircuit, SigCircuitConfig, SigCircuitConfigArgs},
    tx_circuit::{dev::TxCircuitTester, get_sign_data},
    util::{log2_ceil, unusable_rows},
};
use eth_types::{
    address,
    evm_types::gas_utils::{tx_access_list_gas_cost, tx_data_gas_cost},
    word, H256, U256, U64,
};
use halo2_proofs::{
    dev::{MockProver, VerifyFailure},
    halo2curves::bn256::Fr,
};
use mock::{AddrOrWallet, MockTransaction};
#[test]
fn tx_circuit_unusable_rows() {
    assert_eq!(
        TxCircuit::<Fr>::unusable_rows(),
        unusable_rows::<Fr, TxCircuitTester::<Fr>>(),
    )
}

#[cfg(test)]
fn build_pre_eip155_tx() -> Transaction {
    // pre-eip155 tx downloaded from [etherscan](https://etherscan.io/getRawTx?tx=0x9cd2288e69623b109e25edc46bc518156498b521e5c162d96e1ab392ff1d9dff)
    let eth_tx = TransactionRequest::new()
        .from(address!("0xcf40d0d2b44f2b66e07cace1372ca42b73cf21a3"))
        .nonce(word!("0x2ea8"))
        .gas_price(word!("0x098bca5a00"))
        .gas(word!("0x0249f0"))
        .value(word!("0x00"))
        .data(hex::decode("606060405260008054600160a060020a0319163317905560f2806100236000396000f3606060405260e060020a6000350463f5537ede8114601c575b6002565b3460025760f06004356024356044356000805433600160a060020a039081169116141560ea5783905080600160a060020a031663a9059cbb84846000604051602001526040518360e060020a0281526004018083600160a060020a0316815260200182815260200192505050602060405180830381600087803b1560025760325a03f1156002575050604080518481529051600160a060020a0386811693508716917fd0ed88a3f042c6bbb1e3ea406079b5f2b4b198afccaa535d837f4c63abbc4de6919081900360200190a35b50505050565b00").expect("hex data can be decoded"));

    let eth_sig = Signature {
        r: word!("0x90b751c5870e9bc071c8d6b2bf1ee80f36ee7efd8e6fbabaa25bd3b8b68cfe9b"),
        s: word!("0x79c25a01f12493a6d35f1330306d4e3c4e782fcbffc64c6809959577f41ff248"),
        v: 0x1c,
    };

    let signed_bytes = eth_tx.rlp_signed(&eth_sig).to_vec();
    let unsigned_bytes = eth_tx.rlp_unsigned().to_vec();

    let eth_tx_hash = keccak256(&signed_bytes);
    assert_eq!(
        hex::encode(eth_tx_hash),
        "9cd2288e69623b109e25edc46bc518156498b521e5c162d96e1ab392ff1d9dff"
    );

    let mut tx = Transaction::new_from_rlp_bytes(1, PreEip155, signed_bytes, unsigned_bytes);

    tx.hash = H256(eth_tx_hash);
    tx.block_number = 1;
    tx.id = 1;
    tx.nonce = eth_tx.nonce.unwrap().as_u64();
    tx.gas_price = eth_tx.gas_price.unwrap();
    tx.gas = eth_tx.gas.unwrap().as_u64();
    tx.call_data = eth_tx.data.map_or(vec![], |data| data.to_vec());
    tx.callee_address = eth_tx.to.as_ref().map(|to| match *to {
        NameOrAddress::Name(_) => panic!("eth_tx.to must be an address"),
        NameOrAddress::Address(to) => to,
    });
    tx.caller_address = eth_tx.from.unwrap();
    tx.is_create = eth_tx.to.is_none();
    tx.call_data_length = tx.call_data.len();
    tx.call_data_gas_cost = tx_data_gas_cost(&tx.call_data);
    tx.tx_data_gas_cost = tx_data_gas_cost(&tx.rlp_signed);
    tx.v = eth_sig.v;
    tx.r = eth_sig.r;
    tx.s = eth_sig.s;

    tx
}

#[cfg(test)]
fn build_l1_msg_tx() -> Transaction {
    let raw_tx_rlp_bytes = hex::decode("7ef901b60b825dc0941a258d17bf244c4df02d40343a7626a9d321e10580b901848ef1332e000000000000000000000000ea08a65b1829af779261e768d609e59279b510f2000000000000000000000000f2ec6b6206f6208e8f9b394efc1a01c1cbde77750000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000b00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000a4232e87480000000000000000000000002b5ad5c4795c026514f8317c7a215e218dccd6cf0000000000000000000000002b5ad5c4795c026514f8317c7a215e218dccd6cf0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000094478cdd110520a8e733e2acf9e543d2c687ea5239")
        .expect("decode tx's hex shall not fail");

    let eth_tx = EthTransaction::decode(&Rlp::new(&raw_tx_rlp_bytes))
        .expect("decode tx's rlp bytes shall not fail");

    let signed_bytes = eth_tx.rlp().to_vec();
    let mut tx = Transaction::new_from_rlp_signed_bytes(L1Msg, signed_bytes);

    tx.hash = eth_tx.hash;
    tx.block_number = 1;
    tx.id = 1;
    tx.nonce = eth_tx.nonce.as_u64();
    tx.gas_price = eth_tx.gas_price.unwrap_or(U256::zero());
    tx.gas = eth_tx.gas.as_u64();
    tx.call_data = eth_tx.input.to_vec();
    tx.callee_address = eth_tx.to;
    tx.caller_address = eth_tx.from;
    tx.is_create = eth_tx.to.is_none();
    tx.call_data_length = tx.call_data.len();
    tx.call_data_gas_cost = tx_data_gas_cost(&tx.call_data);
    // l1 msg's data has been charged in L1
    tx.tx_data_gas_cost = 0;
    tx.v = eth_tx.v.as_u64();
    tx.r = eth_tx.r;
    tx.s = eth_tx.s;

    tx
}

#[cfg(test)]
fn build_eip1559_tx(id: usize) -> Transaction {
    let bytes = "02f90b7b01825cb38520955af4328521cf92558d830a1bff9400fc00900000002c00be4ef8f49c000211000c43830cc4d0b9015504673a0b85b3000bef3e26e01428d1b525a532ea7513b8f21661d0d1d76d3ecb8e1b9f1c923dbfffae4097020c532d1b995b7e3e37a1aa6369386e5939053779abd3597508b00129cd75b800073edec02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f21661d0d1d76d3ecb8e1b9f1c923dbfffae40970bb86c3dc790b0d7291f864244b559b59b30f850a8cfb40dc7c53760375530e5af29fded5e139893252993820686c92b000094b61ba302f01b0f027d40c80d8f70f77d3884776531f80b21d20e5a6b806300024b2c713b4502988e070f96cf3bea50b4811cd5844e13a81b61a8078c761b0b85b3000bef3e26e01428d1b525a532ea7513b80002594ea302f03b9eb369241e4270796e665ea1afac355cb99f0c32078ab8ba00013c08711b06ed871e5a66bebf0af6fb768d343b1d14a04b5b34ab10cf761b0b85b3000bef3e26e01428d1b525a532ea7513b8000143542ef909b0f89b940b85b3000bef3e26e01428d1b525a532ea7513b8f884a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008f8dd94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f8c6a0e1dd9768c9de657aca2536cf1cdd1c4536b13ec81ff764307ea8312aa7a8790da070bc879403c8b875e45ea7afbb591f1fd4bde469db47d5f0e879e44c6798d33ea0f88aa3ad276c350a067c34b2bed705e1a2cd30c7c3154f62ece8ee00939bbd2ea0be11b0e2ba48478671bfcd8fd182e025c26fbfbcf4fdf6952051d6147955a36fa09a1a5a7ef77f3399dea2a1044425aaca7fec294fdfdcacd7a960c9c94d15f0a6a091828b9b711948523369ff1651b6332e98f75bcd940a551dc7247d5af88e71faf8bc945b7e3e37a1aa6369386e5939053779abd3597508f8a5a00000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000002a0697b2bd7bb2984c4e0dc14c79c987d37818484a62958b9c45a0e8b962f20650fa00000000000000000000000000000000000000000000000000000000000000009a00000000000000000000000000000000000000000000000000000000000000000f9018394c7c53760375530e5af29fded5e13989325299382f9016ba00000000000000000000000000000000000000000000000000000000000000010a0000000000000000000000000000000000000000000000000000000000000000ba00000000000000000000000000000000000000000000000000000000000000016a0000000000000000000000000000000000000000000000000000000000000000ea051d155e8243cd6886ab3b36f59778d90f3bbb4af820bc2d4536b23ca13814bfba00000000000000000000000000000000000000000000000000000000000000013a0a7609b0290b911c4b52861d3739b36793fd0e23d9ef78cf2fa96dd1b0cbc764da00000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000000ca0bda2b1a2a3e35ca431f3c4b50639098537d215591b9ca3db95c24c01795a9981a0000000000000000000000000000000000000000000000000000000000000000df89b94c790b0d7291f864244b559b59b30f850a8cfb40df884a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007f8dd9406ed871e5a66bebf0af6fb768d343b1d14a04b5bf8c6a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000af8bc94f21661d0d1d76d3ecb8e1b9f1c923dbfffae4097f8a5a04d3eb812b43a439547ce41ef251d01e8ad3d0dad3fde6f2bed3d0c0e29dcdd7aa026644b9dbbd32f8882f3abce5ac1575313789ab081b0fe9f3f39c946527bfa27a072fd74a6edf1b99d41f2c81c57f871e198cb7a24fd9861e998221c4aeb776014a0a7609b0290b911c4b52861d3739b36793fd0e23d9ef78cf2fa96dd1b0cbc764da01a3159eb932a0bb66f4d5b9c1cb119796d815774e3c4904b36748d7870d915c2f8dd940f027d40c80d8f70f77d3884776531f80b21d20ef8c6a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007f8bc941a76bffd6d1fc1660e1d0e0552fde51ddbb120cff8a5a06d5257204ebe7d88fd91ae87941cb2dd9d8062b64ae5a2bd2d28ec40b9fbf6dfa030e699f4646032d62d40ca795ecffcb27a2d9d2859f21626b5a588210198e7a6a0c929f5ae32c0eabfbdd06198210bc49736d88e6501f814a66dd5b2fa59508b3ea0ea52bdd009b752a3e91262d66aae31638bc36b449d247d61d646b87a733d7d5da0877978b096db3b11862d0cdfe5f5b74f30fd7d5d29e8ce80626ed8a8bbef1beef8dd944502988e070f96cf3bea50b4811cd5844e13a81bf8c6a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007f8dd949eb369241e4270796e665ea1afac355cb99f0c32f8c6a00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000cf85994f9a2d7e60a3297e513317ad1d7ce101cc4c6c8f6f842a04b376a11d00750d42abab4d4e465d5dc4d9b1286d77cf0c819f028213ea08bdfa072fd74a6edf1b99d41f2c81c57f871e198cb7a24fd9861e998221c4aeb77601480a0d274986e36e16ec2d4846168d59422f68e4b8ec41690b80bdd2ee65819f238eea03d0394f6daae31ba5a276a3741cc2b3ba79b90024f80df865622a62078e72910";
    let raw_tx_rlp_bytes = hex::decode(bytes).expect("decode tx's hex shall not fail");

    let eth_tx = EthTransaction::decode(&Rlp::new(&raw_tx_rlp_bytes))
        .expect("decode tx's rlp bytes shall not fail");

    let eth_tx_req: Eip1559TransactionRequest = (&eth_tx).into();
    let typed_tx: TypedTransaction = eth_tx_req.into();
    let rlp_unsigned = typed_tx.rlp().to_vec();

    let mut tx =
        Transaction::new_from_rlp_bytes(1, TxType::Eip1559, raw_tx_rlp_bytes, rlp_unsigned);

    tx.hash = eth_tx.hash;
    tx.block_number = 1;
    tx.id = id;
    tx.chain_id = eth_tx.chain_id.unwrap_or(U256::zero()).as_u64();
    tx.nonce = eth_tx.nonce.as_u64();
    tx.value = eth_tx.value;
    tx.gas_price = eth_tx.gas_price.unwrap_or(U256::zero());
    tx.gas = eth_tx.gas.as_u64();
    tx.max_fee_per_gas = eth_tx.max_fee_per_gas.unwrap_or(U256::zero());
    tx.max_priority_fee_per_gas = eth_tx.max_priority_fee_per_gas.unwrap_or(U256::zero());
    tx.call_data = eth_tx.input.to_vec();
    tx.callee_address = eth_tx.to;
    tx.caller_address = eth_tx.from;
    tx.is_create = eth_tx.to.is_none();
    tx.call_data_length = tx.call_data.len();
    tx.call_data_gas_cost = tx_data_gas_cost(&tx.call_data);
    tx.access_list = eth_tx.access_list.clone();
    tx.access_list_gas_cost = tx_access_list_gas_cost(&eth_tx.access_list);
    tx.tx_data_gas_cost = tx_data_gas_cost(&tx.rlp_signed);
    tx.v = eth_tx.v.as_u64();
    tx.r = eth_tx.r;
    tx.s = eth_tx.s;

    tx
}

fn run<F: Field>(
    txs: Vec<Transaction>,
    chain_id: u64,
    max_txs: usize,
    max_calldata: usize,
    start_l1_queue_index: u64,
) -> Result<(), Vec<VerifyFailure>> {
    let active_row_num = TxCircuit::<F>::min_num_rows(max_txs, max_calldata);

    let k = max(20, log2_ceil(active_row_num));
    let circuit = TxCircuitTester::<F> {
        sig_circuit: SigCircuit {
            max_verif: max_txs,
            signatures: get_sign_data(&txs, max_txs, chain_id as usize).unwrap(),
            _marker: PhantomData,
        },
        tx_circuit: TxCircuit::new(max_txs, max_calldata, chain_id, start_l1_queue_index, txs),
    };
    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };

    prover.verify_at_rows_par(0..active_row_num, 0..active_row_num)
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_1tx_2max_eip1559() {
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 3200;

    let tx = build_eip1559_tx(1);

    assert_eq!(
        run::<Fr>(vec![tx], mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA, 0),
        Ok(())
    );
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_2tx_2max_tx_eip1559() {
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 6400;

    let tx1 = build_eip1559_tx(1);
    let tx2 = build_eip1559_tx(2);

    assert_eq!(
        run::<Fr>(
            vec![tx1, tx2],
            mock::MOCK_CHAIN_ID,
            MAX_TXS,
            MAX_CALLDATA,
            0
        ),
        Ok(())
    );
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_2tx_2max_tx() {
    const NUM_TXS: usize = 2;
    const MAX_TXS: usize = 2;
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
            mock::MOCK_CHAIN_ID,
            MAX_TXS,
            MAX_CALLDATA,
            0,
        ),
        Ok(())
    );
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_0tx_1max_tx() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 80;

    assert_eq!(
        run::<Fr>(vec![], mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA, 0),
        Ok(())
    );
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_1tx_1max_tx() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

    assert_eq!(
        run::<Fr>(vec![tx], mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA, 0),
        Ok(())
    );
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_1tx_2max_tx() {
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 320;

    let tx = build_pre_eip155_tx();

    assert_eq!(
        run::<Fr>(vec![tx], mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA, 0),
        Ok(())
    );
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_l1_msg_tx() {
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 400;

    let tx = build_l1_msg_tx();

    assert_eq!(
        run::<Fr>(vec![tx], mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA, 0),
        Ok(())
    );
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_bad_address() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let mut tx = mock::CORRECT_MOCK_TXS[0].clone();
    // This address doesn't correspond to the account that signed this tx.
    tx.from = AddrOrWallet::from(address!("0x1230000000000000000000000000000000000456"));

    assert!(run::<Fr>(
        vec![tx.into()],
        mock::MOCK_CHAIN_ID,
        MAX_TXS,
        MAX_CALLDATA,
        0
    )
    .is_err(),);
}

#[test]
#[cfg(feature = "scroll")]
fn tx_circuit_to_is_zero() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let mut tx = mock::CORRECT_MOCK_TXS[5].clone();
    tx.transaction_index = U64::from(1);

    assert_eq!(
        run::<Fr>(
            vec![tx.into()],
            mock::MOCK_CHAIN_ID,
            MAX_TXS,
            MAX_CALLDATA,
            0
        ),
        Ok(())
    );
}
