use super::{CachedRegion, Cell};
use crate::{
    evm_circuit::util::{
        constraint_builder::EVMConstraintBuilder, math_gadget::IsEqualGadget, select,
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

/// Transaction EIP-2930 gadget to handle optional access-list
#[derive(Clone, Debug)]
pub(crate) struct TxEip2930Gadget<F> {
    is_eip2930_tx: IsEqualGadget<F>,
    access_list_address_len: Cell<F>,
    access_list_storage_key_len: Cell<F>,
}

impl<F: Field> TxEip2930Gadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        tx_id: Expression<F>,
        tx_type: Expression<F>,
    ) -> Self {
        let is_eip2930_tx = IsEqualGadget::construct(cb, tx_type, (TxType::Eip2930 as u64).expr());

        let [access_list_address_len, access_list_storage_key_len] =
            cb.condition(is_eip2930_tx.expr(), |cb| {
                let [address_len, storage_key_len] = [
                    TxFieldTag::AccessListAddressesLen,
                    TxFieldTag::AccessListStorageKeysLen,
                ]
                .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));

                // Let copy-circuit to write the tx-table's access list addresses into rw-table.
                cb.copy_table_lookup(
                    tx_id.expr(),
                    CopyDataType::AccessListAddresses.expr(),
                    tx_id.expr(),
                    CopyDataType::AccessListAddresses.expr(),
                    0.expr(),
                    address_len.expr(),
                    0.expr(),
                    address_len.expr(),
                    0.expr(),
                    // TODO
                    0.expr(),
                );

                // Let copy-circuit to write the tx-table's access list storage keys into rw-table.
                cb.copy_table_lookup(
                    tx_id.expr(),
                    CopyDataType::AccessListStorageKeys.expr(),
                    tx_id.expr(),
                    CopyDataType::AccessListStorageKeys.expr(),
                    0.expr(),
                    storage_key_len.expr(),
                    0.expr(),
                    storage_key_len.expr(),
                    0.expr(),
                    // TODO
                    0.expr(),
                );

                [address_len, storage_key_len]
            });

        Self {
            is_eip2930_tx,
            access_list_address_len,
            access_list_storage_key_len,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        tx: &Transaction,
    ) -> Result<(), Error> {
        self.is_eip2930_tx.assign(
            region,
            offset,
            F::from(tx.tx_type as u64),
            F::from(TxType::Eip2930 as u64),
        )?;

        let (access_list_address_len, access_list_storage_key_len) =
            access_list_size(&tx.access_list);

        self.access_list_address_len.assign(
            region,
            offset,
            Value::known(F::from(access_list_address_len)),
        )?;
        self.access_list_storage_key_len.assign(
            region,
            offset,
            Value::known(F::from(access_list_storage_key_len)),
        )?;

        Ok(())
    }

    pub(crate) fn gas_cost(&self) -> Expression<F> {
        select::expr(
            self.is_eip2930_tx.expr(),
            self.access_list_address_len.expr() * GasCost::ACCESS_LIST_PER_ADDRESS.expr()
                + self.access_list_storage_key_len.expr()
                    * GasCost::ACCESS_LIST_PER_STORAGE_KEY.expr(),
            0.expr(),
        )
    }

    pub(crate) fn rw_delta(&self) -> Expression<F> {
        // TODO
        0.expr()
    }
}
