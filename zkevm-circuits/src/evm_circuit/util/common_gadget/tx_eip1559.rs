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
