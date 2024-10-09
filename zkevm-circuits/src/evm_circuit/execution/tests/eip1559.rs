#[cfg(test)]
mod tx_type_test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{Error, Word};
    use ethers_signers::Signer;
    use mock::{eth, gwei, TestContext, MOCK_ACCOUNTS, MOCK_WALLETS};

    #[test]
    fn test_eip1559_tx_for_equal_balance() {
        let balance = if cfg!(feature = "scroll") {
            // l1 fee
            gwei(80_000) + Word::from(279u64)
        } else {
            gwei(80_000)
        };
        let ctx = build_ctx(balance, gwei(2), gwei(2)).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn test_eip1559_tx_for_less_balance() {
        let res = build_ctx(gwei(79_999), gwei(2), gwei(2));

        #[cfg(not(feature = "scroll"))]
        let expected_err = "Failed to run Trace, err: Failed to apply config.Transactions[0]: insufficient funds for gas * price + value: address 0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241 have 79999000000000 want 80000000000000";

        // "80000000000279": 279 is l1 fee
        #[cfg(feature = "scroll")]
        let expected_err = "Failed to run Trace, err: insufficient funds for gas * price + value: address 0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241 have 79999000000000 want 80000000000279";

        // Address `0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241` in error message comes from
        // MOCK_WALLETS[0] in build_ctx.

        // Return a tracing error if insufficient sender balance.
        if let Error::TracingError(err) = res.unwrap_err() {
            assert_eq!(err, expected_err);
        } else {
            panic!("Must be a tracing error");
        }
    }

    #[test]
    fn test_eip1559_tx_for_more_balance() {
        let ctx = build_ctx(gwei(80_001), gwei(2), gwei(2)).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn test_eip1559_tx_for_gas_fee_cap_gt_gas_tip_cap() {
        // Should be successful if `max_fee_per_gas > max_priority_fee_per_gas`.
        let balance = if cfg!(feature = "scroll") {
            // l1 fee
            gwei(80_000) + Word::from(279u64)
        } else {
            gwei(80_000)
        };
        let ctx = build_ctx(balance, gwei(2), gwei(1)).unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn test_eip1559_tx_for_gas_fee_cap_lt_gas_tip_cap() {
        let res = build_ctx(gwei(80_000), gwei(1), gwei(2));

        #[cfg(not(feature = "scroll"))]
        let expected_err = "Failed to run Trace, err: Failed to apply config.Transactions[0]: max priority fee per gas higher than max fee per gas: address 0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241, maxPriorityFeePerGas: 2000000000, maxFeePerGas: 1000000000";
        #[cfg(feature = "scroll")]
        let expected_err = "Failed to run Trace, err: max priority fee per gas higher than max fee per gas: address 0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241, maxPriorityFeePerGas: 2000000000, maxFeePerGas: 1000000000";
        // Address `0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241` in error message comes from
        // MOCK_WALLETS[0] in build_ctx.

        // Return a tracing error if `max_fee_per_gas < max_priority_fee_per_gas`.
        if let Error::TracingError(err) = res.unwrap_err() {
            assert_eq!(err, expected_err);
        } else {
            panic!("Must be a tracing error");
        }
    }

    fn build_ctx(
        sender_balance: Word,
        max_fee_per_gas: Word,
        max_priority_fee_per_gas: Word,
    ) -> Result<TestContext<2, 1>, Error> {
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
                    .gas(30_000.into())
                    .value(gwei(20_000))
                    .max_fee_per_gas(max_fee_per_gas)
                    .max_priority_fee_per_gas(max_priority_fee_per_gas)
                    .transaction_type(2); // Set tx type to EIP-1559.
            },
            |block, _tx| block.number(0xcafeu64),
        )
    }
}
