use super::{CachedRegion, Cell};
use crate::{
    evm_circuit::util::{
        constraint_builder::EVMConstraintBuilder,
        math_gadget::{IsEqualGadget, IsZeroGadget},
        not, or, select,
    },
    table::TxFieldTag,
    util::Expr,
    witness::Transaction,
};
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::{
    evm_types::GasCost,
    geth_types::{access_list_size, TxType},
    Field,
};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

/// Transaction gadget to handle access-list for EIP-1559 and EIP-2930
#[derive(Clone, Debug)]
pub(crate) struct TxAccessListGadget<F> {
    is_eip1559_tx: IsEqualGadget<F>,
    is_eip2930_tx: IsEqualGadget<F>,
    is_address_len_zero: IsZeroGadget<F>,
    is_storage_key_len_zero: IsZeroGadget<F>,
    address_len: Cell<F>,
    storage_key_len: Cell<F>,
}

impl<F: Field> TxAccessListGadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        tx_id: Expression<F>,
        tx_type: Expression<F>,
    ) -> Self {
        let [is_eip1559_tx, is_eip2930_tx] = [TxType::Eip1559, TxType::Eip2930]
            .map(|val| IsEqualGadget::construct(cb, tx_type.expr(), (val as u64).expr()));

        let (address_len, storage_key_len, is_address_len_zero, is_storage_key_len_zero) = cb.condition(
            or::expr([is_eip1559_tx.expr(), is_eip2930_tx.expr()]),
            |cb| {
                let [(address_len, is_address_len_zero), (storage_key_len, is_storage_key_len_zero)] = [
                    TxFieldTag::AccessListAddressesLen,
                    TxFieldTag::AccessListStorageKeysLen,
                ]
                .map(|field_tag| {
                    let len = cb.tx_context(tx_id.expr(), field_tag, None);
                    let is_len_zero = IsZeroGadget::construct(cb, len.expr());

                    (len, is_len_zero)
                });

        cb.condition(not::expr(is_address_len_zero.expr()), |cb| {
                // Let copy-circuit to write the tx-table's access list addresses into rw-table.
                cb.copy_table_lookup(
                    tx_id.expr(),
                    CopyDataType::AccessListAddresses.expr(),
                    tx_id.expr(),
                    CopyDataType::AccessListAddresses.expr(),
                    // Access list address index starts from 1 in tx-table.
                    1.expr(),
                    address_len.expr() + 1.expr(),
                    1.expr(),
                    address_len.expr(),
                    0.expr(),
                    address_len.expr(),
                ); });

        cb.condition(not::expr(is_storage_key_len_zero.expr()), |cb| {
                // Let copy-circuit to write the tx-table's access list storage keys into rw-table.
                cb.copy_table_lookup(
                    tx_id.expr(),
                    CopyDataType::AccessListStorageKeys.expr(),
                    tx_id.expr(),
                    CopyDataType::AccessListStorageKeys.expr(),
                    // Access list storage key index starts from 0 in tx-table.
                    0.expr(),
                    storage_key_len.expr(),
                    0.expr(),
                    storage_key_len.expr(),
                    0.expr(),
                    storage_key_len.expr(),
                );
        });

        (address_len, storage_key_len, is_address_len_zero, is_storage_key_len_zero)
            });

        Self {
            is_eip1559_tx,
            is_eip2930_tx,
            is_address_len_zero,
            is_storage_key_len_zero,
            address_len,
            storage_key_len,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        tx: &Transaction,
    ) -> Result<(), Error> {
        self.is_eip1559_tx.assign(
            region,
            offset,
            F::from(tx.tx_type as u64),
            F::from(TxType::Eip1559 as u64),
        )?;
        self.is_eip2930_tx.assign(
            region,
            offset,
            F::from(tx.tx_type as u64),
            F::from(TxType::Eip2930 as u64),
        )?;

        let (address_len, storage_key_len) = access_list_size(&tx.access_list);

        self.is_address_len_zero
            .assign(region, offset, F::from(address_len))?;
        self.is_storage_key_len_zero
            .assign(region, offset, F::from(storage_key_len))?;

        self.address_len
            .assign(region, offset, Value::known(F::from(address_len)))?;
        self.storage_key_len
            .assign(region, offset, Value::known(F::from(storage_key_len)))?;

        Ok(())
    }

    pub(crate) fn gas_cost(&self) -> Expression<F> {
        select::expr(
            or::expr([self.is_eip1559_tx.expr(), self.is_eip2930_tx.expr()]),
            self.address_len.expr() * GasCost::ACCESS_LIST_PER_ADDRESS.expr()
                + self.storage_key_len.expr() * GasCost::ACCESS_LIST_PER_STORAGE_KEY.expr(),
            0.expr(),
        )
    }

    pub(crate) fn rw_delta_expr(&self) -> Expression<F> {
        self.address_len.expr() + self.storage_key_len.expr()
    }

    pub(crate) fn rw_delta_value(tx: &Transaction) -> u64 {
        let (address_len, storage_key_len) = access_list_size(&tx.access_list);

        address_len + storage_key_len
    }
}


// tests for eip2930
#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{Error, Word};
    use ethers_signers::Signer;
    use mock::{eth, gwei, TestContext, MOCK_ACCOUNTS, MOCK_WALLETS};

    #[test]
    fn test_eip2930_tx_for_empty_access_list() {
        let ctx = build_ctx(gwei(80_000), gwei(2), gwei(2)).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    // TODO: need to enable for scroll feature after merging this PR
    // <https://github.com/scroll-tech/go-ethereum/pull/578>.
    #[cfg(not(feature = "scroll"))]
    #[test]
    fn test_eip1559_tx_for_less_balance() {
        let res = build_ctx(gwei(79_999), gwei(2), gwei(2));

        // Return a tracing error if insufficient sender balance.
        if let Error::TracingError(err) = res.unwrap_err() {
            assert_eq!(err, "Failed to run Trace, err: Failed to apply config.Transactions[0]: insufficient funds for gas * price + value: address 0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241 have 79999000000000 want 80000000000000");
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
        let ctx = build_ctx(gwei(80_000), gwei(2), gwei(1)).unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    // TODO: need to enable for scroll feature after merging this PR
    // <https://github.com/scroll-tech/go-ethereum/pull/578>.
    #[cfg(not(feature = "scroll"))]
    #[test]
    fn test_eip1559_tx_for_gas_fee_cap_lt_gas_tip_cap() {
        let res = build_ctx(gwei(80_000), gwei(1), gwei(2));

        // Return a tracing error if `max_fee_per_gas < max_priority_fee_per_gas`.
        if let Error::TracingError(err) = res.unwrap_err() {
            assert_eq!(err, "Failed to run Trace, err: Failed to apply config.Transactions[0]: max priority fee per gas higher than max fee per gas: address 0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241, maxPriorityFeePerGas: 2000000000, maxFeePerGas: 1000000000");
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
                    .gas_price(30_000.into())
                    .value(gwei(20_000))
                    .transaction_type(1); // Set tx type to EIP-2930.
            },
            |block, _tx| block.number(0xcafeu64),
        )
    }
}
