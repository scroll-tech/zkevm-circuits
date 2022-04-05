use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_GAS,
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::TransferWithGasFeeGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{MulWordByU64Gadget, RangeCheckGadget},
            select, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Region, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct BeginTxGadget<F> {
    tx_id: Cell<F>,
    tx_nonce: Cell<F>,
    tx_gas: Cell<F>,
    tx_gas_price: Word<F>,
    mul_gas_fee_by_gas: MulWordByU64Gadget<F>,
    tx_caller_address: Cell<F>,
    tx_callee_address: Cell<F>,
    tx_is_create: Cell<F>,
    tx_value: Word<F>,
    tx_call_data_length: Cell<F>,
    tx_call_data_gas_cost: Cell<F>,
    reversion_info: ReversionInfo<F>,
    sufficient_gas_left: RangeCheckGadget<F, N_BYTES_GAS>,
    transfer_with_gas_fee: TransferWithGasFeeGadget<F>,
    code_hash: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for BeginTxGadget<F> {
    const NAME: &'static str = "BeginTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BeginTx;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id = cb.curr.state.rw_counter.clone();

        let tx_id = cb.call_context(Some(call_id.expr()), CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info(None);

        let [tx_nonce, tx_gas, tx_caller_address, tx_callee_address, tx_is_create, tx_call_data_length, tx_call_data_gas_cost] =
            [
                TxContextFieldTag::Nonce,
                TxContextFieldTag::Gas,
                TxContextFieldTag::CallerAddress,
                TxContextFieldTag::CalleeAddress,
                TxContextFieldTag::IsCreate,
                TxContextFieldTag::CallDataLength,
                TxContextFieldTag::CallDataGasCost,
            ]
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag, None));
        let [tx_gas_price, tx_value] = [TxContextFieldTag::GasPrice, TxContextFieldTag::Value]
            .map(|field_tag| cb.tx_context_as_word(tx_id.expr(), field_tag, None));

        // Add first step constraint to have both rw_counter and tx_id to be 1
        cb.add_constraint_first_step(
            "rw_counter is initialized to be 1",
            1.expr() - cb.curr.state.rw_counter.expr(),
        );
        cb.add_constraint_first_step("tx_id is initialized to be 1", 1.expr() - tx_id.expr());

        // Increase caller's nonce.
        // (tx caller's nonce always increases even tx ends with error)
        cb.account_write(
            tx_caller_address.expr(),
            AccountFieldTag::Nonce,
            tx_nonce.expr() + 1.expr(),
            tx_nonce.expr(),
            None,
        );

        // TODO: Implement EIP 1559 (currently it only supports legacy
        // transaction format)
        // Calculate transaction gas fee
        let mul_gas_fee_by_gas =
            MulWordByU64Gadget::construct(cb, tx_gas_price.clone(), tx_gas.expr());

        // TODO: Take gas cost of access list (EIP 2930) into consideration.
        // Use intrinsic gas
        let intrinsic_gas_cost = select::expr(
            tx_is_create.expr(),
            GasCost::CREATION_TX.expr(),
            GasCost::TX.expr(),
        ) + tx_call_data_gas_cost.expr();

        // Check gas_left is sufficient
        let gas_left = tx_gas.expr() - intrinsic_gas_cost;
        let sufficient_gas_left = RangeCheckGadget::construct(cb, gas_left.clone());

        // Prepare access list of caller and callee
        cb.account_access_list_write(
            tx_id.expr(),
            tx_caller_address.expr(),
            1.expr(),
            0.expr(),
            None,
        );
        cb.account_access_list_write(
            tx_id.expr(),
            tx_callee_address.expr(),
            1.expr(),
            0.expr(),
            None,
        );

        // Transfer value from caller to callee
        let transfer_with_gas_fee = TransferWithGasFeeGadget::construct(
            cb,
            tx_caller_address.expr(),
            tx_callee_address.expr(),
            tx_value.clone(),
            mul_gas_fee_by_gas.product().clone(),
            &mut reversion_info,
        );

        // TODO: Handle creation transaction
        // TODO: Handle precompiled

        // Read code_hash of callee
        let code_hash = cb.query_cell();
        cb.account_read(
            tx_callee_address.expr(),
            AccountFieldTag::CodeHash,
            code_hash.expr(),
        );

        // Setup next call's context.
        for (field_tag, value) in [
            (CallContextFieldTag::Depth, 1.expr()),
            (CallContextFieldTag::CallerAddress, tx_caller_address.expr()),
            (CallContextFieldTag::CalleeAddress, tx_callee_address.expr()),
            (CallContextFieldTag::CallDataOffset, 0.expr()),
            (
                CallContextFieldTag::CallDataLength,
                tx_call_data_length.expr(),
            ),
            (CallContextFieldTag::Value, tx_value.expr()),
            (CallContextFieldTag::IsStatic, 0.expr()),
            (CallContextFieldTag::LastCalleeId, 0.expr()),
            (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
            (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
            (CallContextFieldTag::IsRoot, 1.expr()),
            (CallContextFieldTag::IsCreate, 0.expr()),
            (CallContextFieldTag::CodeSource, code_hash.expr()),
        ] {
            cb.call_context_lookup(false.expr(), Some(call_id.expr()), field_tag, value);
        }

        cb.require_step_state_transition(StepStateTransition {
            // 19 read/write including:
            //   - Read CallContext TxId
            //   - Read CallContext RwCounterEndOfReversion
            //   - Read CallContext IsPersistent
            //   - Write Account Nonce
            //   - Write TxAccessListAccount
            //   - Write TxAccessListAccount
            //   - Write Account Balance
            //   - Write Account Balance
            //   - Read Account CodeHash
            //   - Read CallContext Depth
            //   - Read CallContext CallerAddress
            //   - Read CallContext CalleeAddress
            //   - Read CallContext CallDataOffset
            //   - Read CallContext CallDataLength
            //   - Read CallContext Value
            //   - Read CallContext IsStatic
            //   - Read CallContext LastCalleeId
            //   - Read CallContext LastCalleeReturnDataOffset
            //   - Read CallContext LastCalleeReturnDataLength
            rw_counter: Delta(22.expr()),
            call_id: To(call_id.expr()),
            is_root: To(true.expr()),
            is_create: To(false.expr()),
            code_source: To(code_hash.expr()),
            gas_left: To(gas_left),
            state_write_counter: To(2.expr()),
            ..StepStateTransition::new_context()
        });

        Self {
            tx_id,
            tx_nonce,
            tx_gas,
            tx_gas_price,
            mul_gas_fee_by_gas,
            tx_caller_address,
            tx_callee_address,
            tx_is_create,
            tx_value,
            tx_call_data_length,
            tx_call_data_gas_cost,
            reversion_info,
            sufficient_gas_left,
            transfer_with_gas_fee,
            code_hash,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let gas_fee = tx.gas_price * tx.gas;
        let [caller_balance_pair, callee_balance_pair, (callee_code_hash, _)] =
            [step.rw_indices[6], step.rw_indices[7], step.rw_indices[8]]
                .map(|idx| block.rws[idx].account_value_pair());

        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;
        self.tx_nonce
            .assign(region, offset, Some(F::from(tx.nonce)))?;
        self.tx_gas.assign(region, offset, Some(F::from(tx.gas)))?;
        self.tx_gas_price
            .assign(region, offset, Some(tx.gas_price.to_le_bytes()))?;
        self.mul_gas_fee_by_gas
            .assign(region, offset, tx.gas_price, tx.gas, gas_fee)?;
        self.tx_caller_address
            .assign(region, offset, tx.caller_address.to_scalar())?;
        self.tx_callee_address
            .assign(region, offset, tx.callee_address.to_scalar())?;
        self.tx_is_create
            .assign(region, offset, Some(F::from(tx.is_create as u64)))?;
        self.tx_call_data_length.assign(
            region,
            offset,
            Some(F::from(tx.call_data_length as u64)),
        )?;
        self.tx_call_data_gas_cost
            .assign(region, offset, Some(F::from(tx.call_data_gas_cost)))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.sufficient_gas_left
            .assign(region, offset, F::from(tx.gas - step.gas_cost))?;
        self.transfer_with_gas_fee.assign(
            region,
            offset,
            caller_balance_pair,
            callee_balance_pair,
            tx.value,
            gas_fee,
        )?;
        self.code_hash.assign(
            region,
            offset,
            Some(RandomLinearCombination::random_linear_combine(
                callee_code_hash.to_le_bytes(),
                block.randomness,
            )),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::{rand_bytes, rand_range, run_test_circuit_incomplete_fixed_table},
        witness::block_convert,
    };
    use bus_mapping::{evm::OpcodeId, mock::BlockData};
    use eth_types::{self, address, bytecode, evm_types::GasCost, geth_types::GethData, Word};
    use mock::TestContext;

    fn test_ok(tx: eth_types::Transaction, is_success: bool) {
        let code = if is_success {
            bytecode! {
                PUSH1(0)
                PUSH1(0)
                RETURN
            }
        } else {
            bytecode! {
                PUSH1(0)
                PUSH1(0)
                REVERT
            }
        };

        let from = tx.from;
        let to = tx.to.unwrap_or_default();

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(to)
                    .balance(Word::from(10u64.pow(10)))
                    .code(code);
                accs[1].address(from).balance(Word::from(10u64.pow(19)));
            },
            |mut txs, _accs| {
                txs[0]
                    .to(tx.to.unwrap())
                    .from(tx.from)
                    .gas_price(tx.gas_price.unwrap())
                    .gas(tx.gas)
                    .input(tx.input)
                    .value(tx.value);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();

        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    fn mock_tx(
        value: Option<Word>,
        gas: Option<u64>,
        gas_price: Option<Word>,
        calldata: Vec<u8>,
    ) -> eth_types::Transaction {
        let from = address!("0x00000000000000000000000000000000000000fe");
        let to = address!("0x00000000000000000000000000000000000000ff");
        let minimal_gas =
            Word::from(GasCost::TX.as_u64() + 2 * OpcodeId::PUSH32.constant_gas_cost().as_u64());
        let point_one_ether = Word::from(10u64.pow(17));
        let two_gwei = Word::from(2_000_000_000);
        eth_types::Transaction {
            from,
            to: Some(to),
            value: value.unwrap_or(point_one_ether),
            gas: gas.map(Word::from).unwrap_or(minimal_gas),
            gas_price: gas_price.or(Some(two_gwei)),
            input: calldata.into(),
            ..Default::default()
        }
    }

    #[test]
    fn begin_tx_gadget_simple() {
        // Transfer 1 ether, successfully
        test_ok(mock_tx(None, None, None, vec![]), true);

        // Transfer 1 ether, tx reverts
        test_ok(mock_tx(None, None, None, vec![]), false);

        // Transfer nothing with some calldata
        test_ok(
            mock_tx(None, Some(21086), None, vec![1, 2, 3, 4, 0, 0, 0, 0]),
            false,
        );
    }

    #[test]
    fn begin_tx_gadget_rand() {
        let point_one_ether = Word::from(10u8).pow(Word::from(17u8));

        // Transfer random ether, successfully
        test_ok(
            mock_tx(
                Some(Word::from_little_endian(&rand_bytes(32)) % point_one_ether),
                None,
                None,
                vec![],
            ),
            true,
        );

        // Transfer nothing with random gas_price, successfully
        test_ok(
            mock_tx(
                None,
                None,
                Some(Word::from(rand_range(0..47619047619047u64))),
                vec![],
            ),
            true,
        );

        // Transfer random ether, tx reverts
        test_ok(
            mock_tx(
                Some(Word::from_little_endian(&rand_bytes(32)) % point_one_ether),
                None,
                None,
                vec![],
            ),
            false,
        );

        // Transfer nothing with random gas_price, tx reverts
        test_ok(
            mock_tx(
                None,
                None,
                Some(Word::from(rand_range(0..476190476190476u64))),
                vec![],
            ),
            false,
        );
    }
}
