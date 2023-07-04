use crate::{
    evm_circuit::param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64, N_BYTES_WORD},
    witness::{
        rlp_fsm::{N_BYTES_CALLDATA, N_BYTES_LIST},
        Format::L1MsgHash,
        RomTableRow,
        Tag::{BeginList, Data, EndList, Gas, Nonce, Sender, To, TxType, Value as TxValue},
    },
};
use ethers_core::utils::rlp::Encodable;

#[derive(Clone, Debug)]
pub struct L1MsgTx;

impl Encodable for L1MsgTx {
    fn rlp_append(&self, _s: &mut ethers_core::utils::rlp::RlpStream) {
        unimplemented!()
    }
}

pub fn rom_table_rows() -> Vec<RomTableRow> {
    let rows = vec![
        (TxType, BeginList, 1, vec![1]),
        (BeginList, Nonce, N_BYTES_LIST, vec![2]),
        (Nonce, Gas, N_BYTES_U64, vec![3]),
        (Gas, To, N_BYTES_U64, vec![4]),
        (To, TxValue, N_BYTES_ACCOUNT_ADDRESS, vec![5]),
        (TxValue, Data, N_BYTES_WORD, vec![6]),
        (Data, Sender, N_BYTES_CALLDATA, vec![7]),
        (Sender, EndList, N_BYTES_ACCOUNT_ADDRESS, vec![8]),
        (EndList, EndList, 0, vec![9]),
        // used to emit TxGasCostInL1
        (EndList, BeginList, 0, vec![]),
    ];

    rows.into_iter()
        .map(|row| (row.0, row.1, row.2, L1MsgHash, row.3).into())
        .collect()
}

#[cfg(test)]
mod tests {
    use bus_mapping::circuit_input_builder::TxL1Fee;
    use eth_types::{evm_types::gas_utils::tx_data_gas_cost, Transaction};

    #[test]
    fn test_l1fee_calc_pre_eip155() {
        let txs: Vec<Transaction> = serde_json::from_str(
            r#"[
                {
                    "type": "0x0",
                    "nonce": "0x4",
                    "hash": "0x8da3fedb103b6da8ccc2514094336d1a76df166238f4d8e8558fbe54cce2516a",
                    "gas": "0xd25e",
                    "gasPrice": "0x3b9aca00",
                    "from": "0x1c5a77d9fa7ef466951b2f01f724bca3a5820b63",
                    "to": "0x03f8133dd5ed58838b20af1296f62f44e69baa48",
                    "chainId": "0xcf55",
                    "value": "0x0",
                    "input": "0xa9059cbb000000000000000000000000c0c4c8baea3f6acb49b6e1fb9e2adeceeacb0ca200000000000000000000000000000000000000000000000000000000000003e8",
                    "isCreate": false,
                    "v": "0x19ecd",
                    "r": "0xaaa87d285f44e2683266d83116ee3df09313f38e91393bfe2966e947c31e4002",
                    "s": "0x9e105efcad78b8e836aa9c588e39f0d81b2d6552d04762d0e02652a9ea94b1d"    
                },
                {
                    "type": "0x0",
                    "nonce": "0x14",
                    "hash": "0xfef778b40acae6c4f00205f3dafae2af1dff90d402c19b090c4b12cad08e7461",
                    "gas": "0x5cb2",
                    "gasPrice": "0x3b9aca00",
                    "from": "0x1c5a77d9fa7ef466951b2f01f724bca3a5820b63",
                    "to": "0x58a2239aa5412f78d8f675c4d8ad5102a3fa5837",
                    "chainId": "0xcf55",
                    "value": "0x0",
                    "input": "0xb0f2b72a000000000000000000000000000000000000000000000000000000000000000a",
                    "isCreate": false,
                    "v": "0x19ece",
                    "r": "0xa0ed5a985f5b74215ba05b0c3fc2a2af1c26c65d9426867eda637fa5d7d388eb",
                    "s": "0x81054ba4a31ee6f0715f36d1005393623b97703c061afe5518a7e31ecbfda6f"
                }                
            ]"#,
        ).unwrap();

        let l1fee = TxL1Fee {
            base_fee: 0x64,
            fee_overhead: 0x17d4,
            fee_scalar: 0x4a42fc80,
        };

        let expected = [(173usize, 0xfffe8u64), (140, 0xf3f2f)];

        for (tx, (rlp_expected, l1fee_expected)) in txs.into_iter().zip(expected) {
            let rlp = tx.rlp().to_vec();
            assert_eq!(rlp.len(), rlp_expected);
            assert_eq!(l1fee.tx_l1_fee(tx_data_gas_cost(&rlp)).0, l1fee_expected)
        }
    }
}
