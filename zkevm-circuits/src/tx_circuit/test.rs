#![allow(unused_imports)]

use ethers_core::{
    types::{NameOrAddress, Signature, Transaction as EthTransaction, TransactionRequest},
    utils::{keccak256, rlp, rlp::Decodable},
};
use std::cmp::max;

use super::*;
use crate::{
    tx_circuit::{dev::TxCircuitTester, get_sign_data},
    util::{log2_ceil, unusable_rows},
};
use eth_types::{address, evm_types::gas_utils::tx_data_gas_cost, word, H256, U256, U64};
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

    let mut tx = Transaction::new_from_rlp_bytes(PreEip155, signed_bytes, unsigned_bytes);

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

    let eth_tx = EthTransaction::decode(&rlp::Rlp::new(&raw_tx_rlp_bytes))
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
    let circuit = TxCircuitTester::<F> {
        sig_circuit: SigCircuit {
            max_verif: max_txs,
            signatures: get_sign_data(&txs, max_txs, chain_id as usize).unwrap(),
            _marker: PhantomData,
        },
        tx_circuit: TxCircuit::new(max_txs, max_calldata, chain_id, txs),
    };
    let prover = match MockProver::run(k, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{e:#?}"),
    };

    prover.verify_par()
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
            *mock::MOCK_CHAIN_ID,
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

    assert_eq!(
        run::<Fr>(vec![], *mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA),
        Ok(())
    );
}

#[test]
fn tx_circuit_1tx_1max_tx() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let tx: Transaction = mock::CORRECT_MOCK_TXS[0].clone().into();

    assert_eq!(
        run::<Fr>(vec![tx], *mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA),
        Ok(())
    );
}

#[test]
fn tx_circuit_1tx_2max_tx() {
    const MAX_TXS: usize = 2;
    const MAX_CALLDATA: usize = 320;

    let tx = build_pre_eip155_tx();

    assert_eq!(
        run::<Fr>(vec![tx], *mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA),
        Ok(())
    );
}

#[test]
fn tx_circuit_l1_msg_tx() {
    const MAX_TXS: usize = 4;
    const MAX_CALLDATA: usize = 400;

    let tx = build_l1_msg_tx();

    assert_eq!(
        run::<Fr>(vec![tx], *mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA),
        Ok(())
    );
}

#[cfg(feature = "reject-eip2718")]
#[test]
fn tx_circuit_bad_address() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let mut tx = mock::CORRECT_MOCK_TXS[0].clone();
    // This address doesn't correspond to the account that signed this tx.
    tx.from = AddrOrWallet::from(address!("0x1230000000000000000000000000000000000456"));

    assert!(run::<Fr>(vec![tx.into()], *mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA).is_err(),);
}

#[test]
fn tx_circuit_to_is_zero() {
    const MAX_TXS: usize = 1;
    const MAX_CALLDATA: usize = 32;

    let mut tx = mock::CORRECT_MOCK_TXS[5].clone();
    tx.transaction_index = U64::from(1);

    assert_eq!(
        run::<Fr>(vec![tx.into()], *mock::MOCK_CHAIN_ID, MAX_TXS, MAX_CALLDATA),
        Ok(())
    );
}
