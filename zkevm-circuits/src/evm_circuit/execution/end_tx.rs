use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        table::{BlockContextFieldTag, CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::UpdateBalanceGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{
                AddWordsGadget, ConstantDivisionGadget, MinMaxGadget, MulWordByU64Gadget,
            },
            Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::MAX_REFUND_QUOTIENT_OF_GAS_USED, Field, ToScalar};
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct EndTxGadget<F> {
    tx_id: Cell<F>,
    tx_gas: Cell<F>,
    max_refund: ConstantDivisionGadget<F, N_BYTES_GAS>,
    refund: Cell<F>,
    effective_refund: MinMaxGadget<F, N_BYTES_GAS>,
    mul_gas_price_by_refund: MulWordByU64Gadget<F>,
    tx_caller_address: Cell<F>,
    gas_fee_refund: UpdateBalanceGadget<F, 2, true>,
    sub_gas_price_by_base_fee: AddWordsGadget<F, 2, true>,
    mul_effective_tip_by_gas_used: MulWordByU64Gadget<F>,
    coinbase: Cell<F>,
    coinbase_reward: UpdateBalanceGadget<F, 2, true>,
}

impl<F: Field> ExecutionGadget<F> for EndTxGadget<F> {
    const NAME: &'static str = "EndTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EndTx;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        let [tx_gas, tx_caller_address] =
            [TxContextFieldTag::Gas, TxContextFieldTag::CallerAddress]
                .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));
        let tx_gas_price = cb.tx_context_as_word(tx_id.expr(), TxContextFieldTag::GasPrice, None);

        // Calculate effective gas to refund
        let gas_used = tx_gas.expr() - cb.curr.state.gas_left.expr();
        let max_refund = ConstantDivisionGadget::construct(
            cb,
            gas_used.clone(),
            MAX_REFUND_QUOTIENT_OF_GAS_USED as u64,
        );
        let refund = cb.query_cell();
        cb.tx_refund_read(tx_id.expr(), refund.expr());
        let effective_refund = MinMaxGadget::construct(cb, max_refund.quotient(), refund.expr());

        // Add effective_refund * tx_gas_price back to caller's balance
        let mul_gas_price_by_refund = MulWordByU64Gadget::construct(
            cb,
            tx_gas_price.clone(),
            effective_refund.min() + cb.curr.state.gas_left.expr(),
        );
        let gas_fee_refund = UpdateBalanceGadget::construct(
            cb,
            tx_caller_address.expr(),
            vec![mul_gas_price_by_refund.product().clone()],
            None,
        );

        // Add gas_used * effective_tip to coinbase's balance
        let coinbase = cb.query_cell();
        let base_fee = cb.query_word();
        for (tag, value) in [
            (BlockContextFieldTag::Coinbase, coinbase.expr()),
            (BlockContextFieldTag::BaseFee, base_fee.expr()),
        ] {
            cb.block_lookup(tag.expr(), None, value);
        }
        let effective_tip = cb.query_word();
        let sub_gas_price_by_base_fee =
            AddWordsGadget::construct(cb, [effective_tip.clone(), base_fee], tx_gas_price);
        let mul_effective_tip_by_gas_used =
            MulWordByU64Gadget::construct(cb, effective_tip, gas_used);
        let coinbase_reward = UpdateBalanceGadget::construct(
            cb,
            coinbase.expr(),
            vec![mul_effective_tip_by_gas_used.product().clone()],
            None,
        );

        cb.condition(
            cb.next.execution_state_selector([ExecutionState::BeginTx]),
            |cb| {
                cb.call_context_lookup(
                    false.expr(),
                    Some(cb.next.state.rw_counter.expr()),
                    CallContextFieldTag::TxId,
                    tx_id.expr() + 1.expr(),
                );

                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(5.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        cb.condition(
            cb.next.execution_state_selector([ExecutionState::EndBlock]),
            |cb| {
                cb.require_step_state_transition(StepStateTransition {
                    rw_counter: Delta(4.expr()),
                    ..StepStateTransition::any()
                });
            },
        );

        Self {
            tx_id,
            tx_gas,
            max_refund,
            refund,
            effective_refund,
            mul_gas_price_by_refund,
            tx_caller_address,
            gas_fee_refund,
            sub_gas_price_by_base_fee,
            mul_effective_tip_by_gas_used,
            coinbase,
            coinbase_reward,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let gas_used = tx.gas - step.gas_left;
        let (refund, _) = block.rws[step.rw_indices[1]].tx_refund_value_pair();
        let [(caller_balance, caller_balance_prev), (coinbase_balance, coinbase_balance_prev)] =
            [step.rw_indices[2], step.rw_indices[3]].map(|idx| block.rws[idx].account_value_pair());

        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;
        self.tx_gas.assign(region, offset, Some(F::from(tx.gas)))?;
        let (max_refund, _) = self.max_refund.assign(region, offset, gas_used as u128)?;
        self.refund.assign(region, offset, Some(F::from(refund)))?;
        self.effective_refund.assign(
            region,
            offset,
            F::from(max_refund as u64),
            F::from(refund),
        )?;
        let effective_refund = refund.min(max_refund as u64);
        let gas_fee_refund = tx.gas_price * (effective_refund + step.gas_left);
        self.mul_gas_price_by_refund.assign(
            region,
            offset,
            tx.gas_price,
            effective_refund + step.gas_left,
            gas_fee_refund,
        )?;
        self.tx_caller_address
            .assign(region, offset, tx.caller_address.to_scalar())?;
        self.gas_fee_refund.assign(
            region,
            offset,
            caller_balance_prev,
            vec![gas_fee_refund],
            caller_balance,
        )?;
        let effective_tip = tx.gas_price - block.context.base_fee;
        self.sub_gas_price_by_base_fee.assign(
            region,
            offset,
            [effective_tip, block.context.base_fee],
            tx.gas_price,
        )?;
        self.mul_effective_tip_by_gas_used.assign(
            region,
            offset,
            effective_tip,
            gas_used,
            effective_tip * gas_used,
        )?;
        self.coinbase
            .assign(region, offset, block.context.coinbase.to_scalar())?;
        self.coinbase_reward.assign(
            region,
            offset,
            coinbase_balance_prev,
            vec![effective_tip * gas_used],
            coinbase_balance,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::run_test_circuit_incomplete_fixed_table, witness::block_convert,
    };
    use eth_types::{self, address, bytecode, geth_types::GethData, Word};
    use mock::TestContext;

    fn test_ok(block: GethData) {
        let block_data = bus_mapping::mock::BlockData::new_from_geth_data(block);
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&block_data.eth_block, &block_data.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db);

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn end_tx_gadget_simple() {
        // TODO: Enable this with respective code when SSTORE is implemented.
        // Tx with non-capped refund
        // test_ok(vec![mock_tx(
        //     address!("0x00000000000000000000000000000000000000fe"),
        //     Some(27000),
        //     None,
        // )]);
        // Tx with capped refund
        // test_ok(vec![mock_tx(
        //     address!("0x00000000000000000000000000000000000000fe"),
        //     Some(65000),
        //     None,
        // )]);

        // Multiple txs
        test_ok(
            // Get the execution steps from the external tracer
            TestContext::<2, 2>::new(
                None,
                |accs| {
                    accs[0]
                        .address(address!("0x00000000000000000000000000000000000000fe"))
                        .balance(Word::from(10u64.pow(19)))
                        .code(bytecode! { STOP });
                    accs[1]
                        .address(address!("0x00000000000000000000000000000000000000fd"))
                        .balance(Word::from(10u64.pow(19)));
                },
                |mut txs, accs| {
                    txs[0]
                        .to(accs[0].address)
                        .from(accs[1].address)
                        .value(Word::from(10u64.pow(17)));
                    txs[1]
                        .to(accs[0].address)
                        .from(accs[1].address)
                        .value(Word::from(10u64.pow(17)));
                },
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap()
            .into(),
        );
    }
}
