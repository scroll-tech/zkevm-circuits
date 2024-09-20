// tests for eip155 tx
#[cfg(test)]
mod tx_type_test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{Error, Word};
    use ethers_signers::Signer;
    use mock::{eth, gwei, TestContext, MOCK_ACCOUNTS, MOCK_WALLETS};

    #[test]
    fn test_eip155() {
        let ctx = build_ctx(gwei(80_000)).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn build_ctx(sender_balance: Word) -> Result<TestContext<2, 1>, Error> {
        TestContext::new(
            None,
            |accs| {
                accs[0]
                    .address(MOCK_WALLETS[0].address())
                    .balance(sender_balance);
                accs[1].address(MOCK_ACCOUNTS[0]).balance(eth(1));
            },
            |mut txs, _accs| {
                txs[0]
                    .from(MOCK_WALLETS[0].clone())
                    .to(MOCK_ACCOUNTS[0])
                    .gas(40_000.into())
                    .gas_price(30_000.into())
                    .value(gwei(20_000))
                    // Set tx type to EIP-155.
                    .transaction_type(0);
            },
            |block, _tx| block.number(0xcafeu64),
        )
    }
}
