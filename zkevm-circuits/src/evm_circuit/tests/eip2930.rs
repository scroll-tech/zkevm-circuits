// tests for eip2930
#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{address, AccessList, AccessListItem, Error, Word, H256};
    use ethers_signers::Signer;
    use mock::{eth, gwei, TestContext, MOCK_ACCOUNTS, MOCK_WALLETS};

    // test with empty access list.
    #[test]
    fn test_eip2930_tx_for_empty_access_list() {
        // CASE1: tx not set access list, `access_list` field is none.
        let ctx = build_ctx(gwei(80_000), None).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();

        // CASE2: tx set empty (neither address nor storage keys at all) access list into
        // `access_list` field. this field is not none.
        let test_access_list: AccessList = AccessList(vec![]);

        let ctx = build_ctx(gwei(80_000), Some(test_access_list)).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    // test with non empty access list(address + storage keys list)
    #[test]
    fn test_eip2930_non_empty_access_list() {
        let test_access_list: AccessList = AccessList(vec![
            AccessListItem {
                address: address!("0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241"),
                // one storage key
                storage_keys: [10].map(H256::from_low_u64_be).to_vec(),
            },
            AccessListItem {
                address: address!("0x0000000000000000000000000000000000001111"),
                // two storage keys
                storage_keys: [10, 11].map(H256::from_low_u64_be).to_vec(),
            },
            AccessListItem {
                address: address!("0x0000000000000000000000000000000000002222"),
                // three storage keys
                storage_keys: [20, 22, 50].map(H256::from_low_u64_be).to_vec(),
            },
        ]);

        let ctx = build_ctx(gwei(80_000), Some(test_access_list)).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    // test with non empty access list(only address list)
    #[test]
    fn test_eip2930_only_address_access_list() {
        let test_access_list: AccessList = AccessList(vec![
            AccessListItem {
                address: address!("0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241"),
                // no storage keys
                storage_keys: Vec::new(),
            },
            AccessListItem {
                address: address!("0x0000000000000000000000000000000000001111"),
                // no storage keys
                storage_keys: Vec::new(),
            },
        ]);

        let ctx = build_ctx(gwei(80_000), Some(test_access_list)).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn build_ctx(
        sender_balance: Word,
        access_list: Option<AccessList>,
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
                    .gas(40_000.into())
                    .gas_price(30_000.into())
                    .value(gwei(20_000))
                    .transaction_type(1); // Set tx type to EIP-2930.

                if let Some(acc_list) = access_list {
                    txs[0].access_list(acc_list);
                }
            },
            |block, _tx| block.number(0xcafeu64),
        )
    }
}
