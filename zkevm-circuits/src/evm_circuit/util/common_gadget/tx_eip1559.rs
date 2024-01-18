//! TxEip1559Gadget is used to check sender balance before fee and value
//! transfer for EIP-1559 transactions.
//! Reference the geth code as:
//! <https://github.com/ethereum/go-ethereum/blob/master/core/state_transition.go#L234>
//! <https://github.com/scroll-tech/go-ethereum/blob/develop/core/state_transition.go#L218>

use super::CachedRegion;
use crate::{
    evm_circuit::{
        util::{
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{AddWordsGadget, IsEqualGadget, LtWordGadget, MulWordByU64Gadget},
            sum, Expr, Word,
        },
        witness::Transaction,
    },
    table::TxFieldTag,
};
use eth_types::{geth_types::TxType, Field, ToLittleEndian, U256};
use halo2_proofs::plonk::{Error, Expression};

/// Transaction EIP-1559 gadget to check sender balance before transfer
#[derive(Clone, Debug)]
pub(crate) struct TxEip1559Gadget<F> {
    is_eip1559_tx: IsEqualGadget<F>,
    // MaxFeePerGas
    gas_fee_cap: Word<F>,
    // MaxPriorityFeePerGas
    gas_tip_cap: Word<F>,
    mul_gas_fee_cap_by_gas: MulWordByU64Gadget<F>,
    balance_check: AddWordsGadget<F, 3, true>,
    // Error condition
    // <https://github.com/ethereum/go-ethereum/blob/master/core/state_transition.go#L255>
    is_insufficient_balance: LtWordGadget<F>,
    // Error condition
    // <https://github.com/ethereum/go-ethereum/blob/master/core/state_transition.go#L304>
    gas_fee_cap_lt_gas_tip_cap: LtWordGadget<F>,
}

impl<F: Field> TxEip1559Gadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        tx_id: Expression<F>,
        tx_type: Expression<F>,
        tx_gas: Expression<F>,
        tx_l1_fee: &Word<F>,
        value: &Word<F>,
        sender_balance: &Word<F>,
    ) -> Self {
        let is_eip1559_tx = IsEqualGadget::construct(cb, tx_type, (TxType::Eip1559 as u64).expr());

        let [gas_fee_cap, gas_tip_cap] =
            [TxFieldTag::MaxFeePerGas, TxFieldTag::MaxPriorityFeePerGas]
                .map(|field_tag| cb.tx_context_as_word(tx_id.expr(), field_tag, None));

        let (
            mul_gas_fee_cap_by_gas,
            balance_check,
            is_insufficient_balance,
            gas_fee_cap_lt_gas_tip_cap,
        ) = cb.condition(is_eip1559_tx.expr(), |cb| {
            let mul_gas_fee_cap_by_gas =
                MulWordByU64Gadget::construct(cb, gas_fee_cap.clone(), tx_gas);

            let min_balance = cb.query_word_rlc();
            let balance_check = AddWordsGadget::construct(
                cb,
                [
                    mul_gas_fee_cap_by_gas.product().clone(),
                    value.clone(),
                    tx_l1_fee.clone(),
                ],
                min_balance.clone(),
            );

            let is_insufficient_balance = LtWordGadget::construct(cb, sender_balance, &min_balance);
            let gas_fee_cap_lt_gas_tip_cap =
                LtWordGadget::construct(cb, &gas_fee_cap, &gas_tip_cap);

            cb.require_zero(
                "Sender balance must be sufficient, and gas_fee_cap >= gas_tip_cap",
                sum::expr([
                    is_insufficient_balance.expr(),
                    gas_fee_cap_lt_gas_tip_cap.expr(),
                ]),
            );

            (
                mul_gas_fee_cap_by_gas,
                balance_check,
                is_insufficient_balance,
                gas_fee_cap_lt_gas_tip_cap,
            )
        });

        Self {
            is_eip1559_tx,
            gas_fee_cap,
            gas_tip_cap,
            mul_gas_fee_cap_by_gas,
            balance_check,
            is_insufficient_balance,
            gas_fee_cap_lt_gas_tip_cap,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        tx: &Transaction,
        tx_l1_fee: U256,
        sender_balance_prev: U256,
    ) -> Result<(), Error> {
        self.is_eip1559_tx.assign(
            region,
            offset,
            F::from(tx.tx_type as u64),
            F::from(TxType::Eip1559 as u64),
        )?;
        self.gas_fee_cap
            .assign(region, offset, Some(tx.max_fee_per_gas.to_le_bytes()))?;
        self.gas_tip_cap.assign(
            region,
            offset,
            Some(tx.max_priority_fee_per_gas.to_le_bytes()),
        )?;
        let mul_gas_fee_cap_by_gas = tx.max_fee_per_gas * tx.gas;
        self.mul_gas_fee_cap_by_gas.assign(
            region,
            offset,
            tx.max_fee_per_gas,
            tx.gas,
            mul_gas_fee_cap_by_gas,
        )?;
        let min_balance = mul_gas_fee_cap_by_gas + tx.value + tx_l1_fee;
        self.balance_check.assign(
            region,
            offset,
            [mul_gas_fee_cap_by_gas, tx.value, tx_l1_fee],
            min_balance,
        )?;
        self.is_insufficient_balance
            .assign(region, offset, sender_balance_prev, min_balance)?;
        self.gas_fee_cap_lt_gas_tip_cap.assign(
            region,
            offset,
            tx.max_fee_per_gas,
            tx.max_priority_fee_per_gas,
        )
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{Error, Word};
    use mock::{eth, gwei, TestContext, MOCK_ACCOUNTS};

    #[test]
    fn test_eip1559_tx_for_equal_balance() {
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
            assert_eq!(err, "Failed to run Trace, err: Failed to apply config.Transactions[0]: insufficient funds for gas * price + value: address 0x000000000000000000000000000000000CAfe111 have 79999000000000 want 80000000000000");
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
            assert_eq!(err, "Failed to run Trace, err: Failed to apply config.Transactions[0]: max priority fee per gas higher than max fee per gas: address 0x000000000000000000000000000000000CAfe111, maxPriorityFeePerGas: 2000000000, maxFeePerGas: 1000000000");
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
                accs[0].address(MOCK_ACCOUNTS[0]).balance(sender_balance);
                accs[1].address(MOCK_ACCOUNTS[1]).balance(eth(1));
            },
            |mut txs, _accs| {
                txs[0]
                    .from(MOCK_ACCOUNTS[0])
                    .to(MOCK_ACCOUNTS[1])
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
