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
    table::{BlockContextFieldTag, TxFieldTag},
    util::Field,
};
use eth_types::{geth_types::TxType, ToLittleEndian, U256};
use gadgets::util::select;
use halo2_proofs::plonk::{Error, Expression};

/// Transaction EIP-1559 gadget to check sender balance before transfer
#[derive(Clone, Debug)]
pub(crate) struct TxEip1559Gadget<F> {
    is_eip1559_tx: IsEqualGadget<F>,
    // MaxFeePerGas
    gas_fee_cap: Word<F>,
    // MaxPriorityFeePerGas
    gas_tip_cap: Word<F>,
    // condition for min(
    // gas_tip_cap, gas_fee_cap - base_fee_per_gas)
    gas_tip_cap_lt_gas_fee_cap_minus_base_fee: LtWordGadget<F>,
    // gas_fee_cap - base_fee_per_gas
    gas_sub_base_fee: AddWordsGadget<F, 2, true>,
    // check tx_gas_price = effective_gas_price = priority_fee_per_gas +
    // block.base_fee_per_gas
    effective_gas_price_check: AddWordsGadget<F, 2, true>,
    mul_gas_fee_cap_by_gas: MulWordByU64Gadget<F>,
    balance_check: AddWordsGadget<F, 3, true>,
    // Error condition
    // <https://github.com/ethereum/go-ethereum/blob/master/core/state_transition.go#L241>
    is_insufficient_balance: LtWordGadget<F>,
    // Error condition
    // <https://github.com/ethereum/go-ethereum/blob/master/core/state_transition.go#L310>
    gas_fee_cap_lt_gas_tip_cap: LtWordGadget<F>,
    // base fee from block context
    base_fee: Word<F>,
    // Error condition
    // <https://github.com/ethereum/go-ethereum/blob/master/core/state_transition.go#L316>
    gas_fee_cap_lt_base_fee: LtWordGadget<F>,
}

impl<F: Field> TxEip1559Gadget<F> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        tx_id: Expression<F>,
        tx_type: Expression<F>,
        tx_gas: Expression<F>,
        // tx_gas_price is looked up from TxTable in begin_tx gadget.
        tx_gas_price: &Word<F>,
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
            base_fee,
            gas_fee_cap_lt_base_fee,
            gas_tip_cap_lt_gas_fee_cap_minus_base_fee,
            gas_sub_base_fee,
            effective_gas_price_check,
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
            // lookup base fee from block.
            let base_fee = cb.query_word_rlc();
            cb.block_lookup(BlockContextFieldTag::BaseFee.expr(), cb.curr.state.block_number.expr(), base_fee.expr());
            // constrain GasFeeCap not less than BaseFee
            let gas_fee_cap_lt_base_fee =
                LtWordGadget::construct(cb, &gas_fee_cap, &base_fee);

            // calculating min(
            //     gas_tip_cap
            //     gas_fee_cap - base_fee_per_gas,
            // );
            let gas_fee_cap_minus_base_fee_per_gas = cb.query_word_rlc();
            let gas_fee_cap_minus_base_fee_per_gas_check = AddWordsGadget::construct(cb, [base_fee.clone(), gas_fee_cap_minus_base_fee_per_gas.clone()], gas_fee_cap.clone());
            let tip_comparator = LtWordGadget::construct(cb, &gas_tip_cap, &gas_fee_cap_minus_base_fee_per_gas);
            // let effective_gas_price = priority_fee_per_gas + base_fee_per_gas;
            let priority_fee_per_gas = cb.query_word_rlc();
            cb.require_equal("constrain priority_fee_per_gas = min(gas_tip_cap, gas_fee_cap - base_fee_per_gas)", priority_fee_per_gas.expr(), select::expr(
                tip_comparator.expr(),
                gas_tip_cap.expr(),
                gas_fee_cap_minus_base_fee_per_gas.expr()));
            // constrain tx_gas_price = effective_gas_price within below `AddWordsGadget`.
            let effective_gas_price_check = AddWordsGadget::construct(cb, [base_fee.clone(), priority_fee_per_gas], tx_gas_price.clone());

            cb.require_zero(
                "Sender balance must be sufficient, and gas_fee_cap >= gas_tip_cap, and gas_fee_cap >= base_fee",
                sum::expr([
                    is_insufficient_balance.expr(),
                    gas_fee_cap_lt_gas_tip_cap.expr(),
                    gas_fee_cap_lt_base_fee.expr(),
                ]),
            );

            (
                mul_gas_fee_cap_by_gas,
                balance_check,
                is_insufficient_balance,
                gas_fee_cap_lt_gas_tip_cap,
                base_fee,
                gas_fee_cap_lt_base_fee,
                tip_comparator,
                gas_fee_cap_minus_base_fee_per_gas_check,
                effective_gas_price_check,
            )
        });

        Self {
            is_eip1559_tx,
            gas_fee_cap,
            gas_tip_cap,
            gas_tip_cap_lt_gas_fee_cap_minus_base_fee,
            gas_sub_base_fee,
            effective_gas_price_check,
            mul_gas_fee_cap_by_gas,
            balance_check,
            is_insufficient_balance,
            gas_fee_cap_lt_gas_tip_cap,
            base_fee,
            gas_fee_cap_lt_base_fee,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        tx: &Transaction,
        tx_l1_fee: U256,
        sender_balance_prev: U256,
        base_fee: U256,
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
        let diff_gas_base_fee = if tx.max_fee_per_gas >= base_fee {
            tx.max_fee_per_gas - base_fee
        } else {
            0u64.into()
        };
        let priority_fee_per_gas = tx.max_priority_fee_per_gas.min(diff_gas_base_fee);
        self.gas_sub_base_fee.assign(
            region,
            offset,
            [base_fee, diff_gas_base_fee],
            tx.max_fee_per_gas,
        )?;
        self.gas_tip_cap_lt_gas_fee_cap_minus_base_fee.assign(
            region,
            offset,
            tx.max_priority_fee_per_gas,
            diff_gas_base_fee,
        )?;

        self.effective_gas_price_check.assign(
            region,
            offset,
            [base_fee, priority_fee_per_gas],
            tx.gas_price,
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
        self.base_fee
            .assign(region, offset, Some(base_fee.to_le_bytes()))?;
        self.gas_fee_cap_lt_gas_tip_cap.assign(
            region,
            offset,
            tx.max_fee_per_gas,
            tx.max_priority_fee_per_gas,
        )?;
        self.gas_fee_cap_lt_base_fee
            .assign(region, offset, tx.max_fee_per_gas, base_fee)
    }
}

#[cfg(test)]
mod test {
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
