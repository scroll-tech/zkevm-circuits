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
    use eth_types::{Error, Word, AccessList, AccessListItem, address, H256};
    use ethers_signers::Signer;
    use mock::{eth, gwei, TestContext, MOCK_ACCOUNTS, MOCK_WALLETS};

    #[test]
    fn test_eip2930_tx_for_empty_access_list() {
        let ctx = build_ctx(gwei(80_000), None).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn test_eip2930_non_empty_access_list() {
        let test_access_list = AccessList(vec![
            AccessListItem {
                address: address!("0xEeFca179F40D3B8b3D941E6A13e48835a3aF8241"),
                storage_keys: [10, 11].map(H256::from_low_u64_be).to_vec(),
            },
            AccessListItem {
                address: address!("0x0000000000000000000000000000000000001111"),
                storage_keys: [10, 11].map(H256::from_low_u64_be).to_vec(),
            },
            AccessListItem {
                address: address!("0x0000000000000000000000000000000000002222"),
                storage_keys: [20, 22].map(H256::from_low_u64_be).to_vec(),
            },
        ]);

        let ctx = build_ctx(gwei(80_000), Some(test_access_list)).unwrap();
        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    // TODO: check if other types' test required.

    fn build_ctx(
        sender_balance: Word,
        access_list: Option<AccessList>
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
                
                if access_list.is_some(){
                    txs[0].access_list(access_list.unwrap());
                } 
            },
            |block, _tx| block.number(0xcafeu64),
        )
    }
}
