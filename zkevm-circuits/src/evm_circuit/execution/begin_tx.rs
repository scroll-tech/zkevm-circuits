use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_GAS, STACK_CAPACITY},
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::TransferWithGasFeeGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            math_gadget::{MulWordByU64Gadget, RangeCheckGadget},
            select, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::evm_types::GasCost;
use eth_types::{ToLittleEndian, ToScalar};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

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
    rw_counter_end_of_reversion: Cell<F>,
    is_persistent: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, N_BYTES_GAS>,
    transfer_with_gas_fee: TransferWithGasFeeGadget<F>,
    code_hash: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for BeginTxGadget<F> {
    const NAME: &'static str = "BeginTx";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BeginTx;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id = cb.curr.state.rw_counter.clone();

        let [tx_id, rw_counter_end_of_reversion, is_persistent] = [
            CallContextFieldTag::TxId,
            CallContextFieldTag::RwCounterEndOfReversion,
            CallContextFieldTag::IsPersistent,
        ]
        .map(|field_tag| cb.call_context(Some(call_id.expr()), field_tag));

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
            .map(|field_tag| cb.tx_context(tx_id.expr(), field_tag));
        let [tx_gas_price, tx_value] = [TxContextFieldTag::GasPrice, TxContextFieldTag::Value]
            .map(|field_tag| cb.tx_context_as_word(tx_id.expr(), field_tag));

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
        );

        // TODO: Implement EIP 1559 (currently it only supports legacy
        // transaction format)
        // Calculate transaction gas fee
        let mul_gas_fee_by_gas =
            MulWordByU64Gadget::construct(cb, tx_gas_price.clone(), tx_gas.clone(), true);

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
        cb.account_access_list_write(tx_id.expr(), tx_caller_address.expr(), 1.expr(), 0.expr());
        cb.account_access_list_write(tx_id.expr(), tx_callee_address.expr(), 1.expr(), 0.expr());

        // Transfer value from caller to callee
        let transfer_with_gas_fee = TransferWithGasFeeGadget::construct(
            cb,
            tx_caller_address.expr(),
            tx_callee_address.expr(),
            tx_value.clone(),
            mul_gas_fee_by_gas.product().clone(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        // Assume it's not a creation transaction nor calling a precompiled
        cb.add_constraint(
            "Handling of creation transaction has yet to be determined",
            tx_is_create.expr(),
        );

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
        ] {
            cb.call_context_lookup(Some(call_id.expr()), field_tag, value);
        }

        cb.require_step_state_transition(StepStateTransition {
            // 16 read/write including:
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
            rw_counter: Delta(16.expr()),
            call_id: To(call_id.expr()),
            is_root: To(1.expr()),
            is_create: To(0.expr()),
            opcode_source: To(code_hash.expr()),
            program_counter: To(0.expr()),
            stack_pointer: To(STACK_CAPACITY.expr()),
            gas_left: To(gas_left),
            memory_word_size: To(0.expr()),
            state_write_counter: To(2.expr()),
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
            rw_counter_end_of_reversion,
            is_persistent,
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
        tx: &Transaction<F>,
        call: &Call<F>,
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
        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Some(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;
        self.is_persistent
            .assign(region, offset, Some(F::from(call.is_persistent as u64)))?;
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
        param::STACK_CAPACITY,
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag},
        test::{rand_fp, rand_range, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
        witness::{Block, Bytecode, Call, ExecStep, Rw, Transaction},
    };
    use eth_types::evm_types::{GasCost, OpcodeId};
    use eth_types::{self, address, Address, ToLittleEndian, ToWord, Word};
    use std::convert::TryInto;

    fn test_ok(tx: eth_types::Transaction, result: bool) {
        let rw_counter_end_of_reversion = if result { 0 } else { 20 };

        let gas_fee = tx.gas * tx.gas_price.unwrap_or_else(Word::zero);
        let call_data_gas_cost = tx
            .input
            .0
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 });
        let intrinsic_gas_cost = if tx.to.is_none() {
            GasCost::CREATION_TX.as_u64()
        } else {
            GasCost::TX.as_u64()
        } + call_data_gas_cost;

        let from_balance_prev = Word::from(10).pow(20.into());
        let to_balance_prev = Word::zero();
        let from_balance = from_balance_prev - tx.value - gas_fee;
        let to_balance = to_balance_prev + tx.value;

        let randomness = rand_fp();
        let bytecode = Bytecode::new(vec![OpcodeId::STOP.as_u8()]);
        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                nonce: tx.nonce.try_into().unwrap(),
                gas: tx.gas.try_into().unwrap(),
                gas_price: tx.gas_price.unwrap_or_else(Word::zero),
                caller_address: tx.from,
                callee_address: tx.to.unwrap_or_else(Address::zero),
                is_create: tx.to.is_none(),
                value: tx.value,
                call_data: tx.input.to_vec(),
                call_data_length: tx.input.0.len(),
                call_data_gas_cost,
                calls: vec![Call {
                    id: 1,
                    is_root: true,
                    is_create: false,
                    opcode_source: RandomLinearCombination::random_linear_combine(
                        bytecode.hash.to_le_bytes(),
                        randomness,
                    ),
                    result: Word::from(result as usize),
                    rw_counter_end_of_reversion,
                    is_persistent: result,
                    ..Default::default()
                }],
                steps: vec![
                    ExecStep {
                        rw_indices: (0..16 + if result { 0 } else { 2 }).collect(),
                        execution_state: ExecutionState::BeginTx,
                        rw_counter: 1,
                        gas_cost: intrinsic_gas_cost,
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 17,
                        program_counter: 0,
                        stack_pointer: STACK_CAPACITY,
                        gas_left: 0,
                        opcode: Some(OpcodeId::STOP),
                        state_write_counter: 2,
                        ..Default::default()
                    },
                ],
            }],
            rws: [
                vec![
                    Rw::CallContext {
                        rw_counter: 1,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::TxId,
                        value: Word::one(),
                    },
                    Rw::CallContext {
                        rw_counter: 2,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::RwCounterEndOfReversion,
                        value: Word::from(rw_counter_end_of_reversion),
                    },
                    Rw::CallContext {
                        rw_counter: 3,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::IsPersistent,
                        value: Word::from(result as u64),
                    },
                    Rw::Account {
                        rw_counter: 4,
                        is_write: true,
                        account_address: tx.from,
                        field_tag: AccountFieldTag::Nonce,
                        value: tx.nonce + Word::one(),
                        value_prev: tx.nonce,
                    },
                    Rw::TxAccessListAccount {
                        rw_counter: 5,
                        is_write: true,
                        tx_id: 1,
                        account_address: tx.from,
                        value: true,
                        value_prev: false,
                    },
                    Rw::TxAccessListAccount {
                        rw_counter: 6,
                        is_write: true,
                        tx_id: 1,
                        account_address: tx.to.unwrap(),
                        value: true,
                        value_prev: false,
                    },
                    Rw::Account {
                        rw_counter: 7,
                        is_write: true,
                        account_address: tx.from,
                        field_tag: AccountFieldTag::Balance,
                        value: from_balance,
                        value_prev: from_balance_prev,
                    },
                    Rw::Account {
                        rw_counter: 8,
                        is_write: true,
                        account_address: tx.to.unwrap_or_else(Address::zero),
                        field_tag: AccountFieldTag::Balance,
                        value: to_balance,
                        value_prev: to_balance_prev,
                    },
                    Rw::Account {
                        rw_counter: 9,
                        is_write: false,
                        account_address: tx.to.unwrap_or_else(Address::zero),
                        field_tag: AccountFieldTag::CodeHash,
                        value: bytecode.hash,
                        value_prev: bytecode.hash,
                    },
                    Rw::CallContext {
                        rw_counter: 10,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::Depth,
                        value: Word::one(),
                    },
                    Rw::CallContext {
                        rw_counter: 11,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::CallerAddress,
                        value: tx.from.to_word(),
                    },
                    Rw::CallContext {
                        rw_counter: 12,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::CalleeAddress,
                        value: tx.to.unwrap_or_else(Address::zero).to_word(),
                    },
                    Rw::CallContext {
                        rw_counter: 13,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::CallDataOffset,
                        value: Word::zero(),
                    },
                    Rw::CallContext {
                        rw_counter: 14,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::CallDataLength,
                        value: tx.input.0.len().into(),
                    },
                    Rw::CallContext {
                        rw_counter: 15,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::Value,
                        value: tx.value,
                    },
                    Rw::CallContext {
                        rw_counter: 16,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::IsStatic,
                        value: Word::zero(),
                    },
                ],
                if result {
                    vec![]
                } else {
                    vec![
                        Rw::Account {
                            rw_counter: 19,
                            is_write: true,
                            account_address: tx.to.unwrap_or_else(Address::zero),
                            field_tag: AccountFieldTag::Balance,
                            value: to_balance_prev,
                            value_prev: to_balance,
                        },
                        Rw::Account {
                            rw_counter: 20,
                            is_write: true,
                            account_address: tx.from,
                            field_tag: AccountFieldTag::Balance,
                            value: from_balance_prev,
                            value_prev: from_balance,
                        },
                    ]
                },
            ]
            .concat(),
            bytecodes: vec![bytecode],
            ..Default::default()
        };
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
        let minimal_gas = Word::from(21000);
        let one_ether = Word::from(10).pow(18.into());
        let two_gwei = Word::from(2_000_000_000);
        eth_types::Transaction {
            from,
            to: Some(to),
            value: value.unwrap_or(one_ether),
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
            mock_tx(None, Some(21080), None, vec![1, 2, 3, 4, 0, 0, 0, 0]),
            false,
        );
    }

    #[test]
    fn begin_tx_gadget_rand() {
        // Transfer random ether, successfully
        test_ok(
            mock_tx(
                Some(Word::from(rand_range(0..=u64::MAX))),
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
                Some(Word::from(rand_range(0..42857142857143u64))),
                vec![],
            ),
            true,
        );

        // Transfer random ether, tx reverts
        test_ok(
            mock_tx(
                Some(Word::from(rand_range(0..=u64::MAX))),
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
                Some(Word::from(rand_range(0..42857142857143u64))),
                vec![],
            ),
            false,
        );
    }
}
