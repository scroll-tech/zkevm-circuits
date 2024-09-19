#[cfg(test)]
mod tx_type_test {
    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        self, address, word, Error, Word,    };
    use mock::{gwei, MockTransaction, TestContext};

    // Note: all pre-eip155 txs here for testing have signature data. don't need to generate signature dynamically
    // because ethers-rs lib's helper `sign_transaction_sync` doesn't support pre-eip155 type.
    #[test]
    fn test_legacy_tx_pre_eip155() {
        let mut tx1 = MockTransaction::default();
        // pre-eip155 tx1 downloaded from [etherscan](https://etherscan.io/getRawTx?tx=0x9cd2288e69623b109e25edc46bc518156498b521e5c162d96e1ab392ff1d9dff)
        // tx with signature::v =0x1c (28).
        let sig_data1 = (
            0x1c_u64,
            word!("0x90b751c5870e9bc071c8d6b2bf1ee80f36ee7efd8e6fbabaa25bd3b8b68cfe9b"),
            word!("0x79c25a01f12493a6d35f1330306d4e3c4e782fcbffc64c6809959577f41ff248"),
        );

        tx1
            .from(address!("0xcf40d0d2b44f2b66e07cace1372ca42b73cf21a3"))
            .nonce(word!("0x2ea8"))
            .gas_price(word!("0x098bca5a00"))
            .gas(word!("0x0249f0"))
            .value(word!("0x00"))
            // Set tx type to pre-eip155.
            .transaction_type(0)
            .input(hex::decode("606060405260008054600160a060020a0319163317905560f2806100236000396000f3606060405260e060020a6000350463f5537ede8114601c575b6002565b3460025760f06004356024356044356000805433600160a060020a039081169116141560ea5783905080600160a060020a031663a9059cbb84846000604051602001526040518360e060020a0281526004018083600160a060020a0316815260200182815260200192505050602060405180830381600087803b1560025760325a03f1156002575050604080518481529051600160a060020a0386811693508716917fd0ed88a3f042c6bbb1e3ea406079b5f2b4b198afccaa535d837f4c63abbc4de6919081900360200190a35b50505050565b00")
            .expect("hex data can be decoded").into())
            .sig_data(sig_data1);

        // pre-eip155 tx2 refers to https://github.com/scroll-tech/go-ethereum/blob/develop/cmd/evm/testdata/3/txs.json.
        let mut tx2 = MockTransaction::default();
        // tx with signature::v =0x1b (27).
        let sig_data2 = (
            0x1b_u64,
            word!("0x88544c93a564b4c28d2ffac2074a0c55fdd4658fe0d215596ed2e32e3ef7f56b"),
            word!("0x7fb4075d54190f825d7c47bb820284757b34fd6293904a93cddb1d3aa961ac28"),
        );

        tx2.from(address!("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b"))
            .to(address!("0x095e7baea6a6c7c4c2dfeb977efac326af552d87"))
            .nonce(word!("0x0"))
            .gas_price(word!("0x1"))
            .gas(word!("0x5f5e100"))
            .value(word!("0x186a0"))
            // Set tx type to pre-eip155.
            .transaction_type(0)
            .sig_data(sig_data2);

        for tx in [tx1, tx2] {
            let ctx = build_legacy_ctx(gwei(8_000_000), &tx).unwrap();
            CircuitTestBuilder::new_from_test_ctx(ctx)
                .params(CircuitsParams {
                    max_calldata: 300,
                    ..Default::default()
                })
                .run()
        }
    }

    // build pre-eip155 tx
    fn build_legacy_ctx(
        sender_balance: Word,
        tx: &MockTransaction,
    ) -> Result<TestContext<1, 1>, Error> {
        TestContext::new(
            None,
            |accs| {
                accs[0]
                    .address(tx.from.address())
                    .balance(sender_balance)
                    .nonce(tx.nonce);
            },
            |mut txs, _accs| {
                txs[0].clone_from(tx);
            },
            |block, _tx| block.number(0xcafeu64),
        )
    }
}
