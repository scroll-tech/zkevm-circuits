use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            select, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use halo2_proofs::{
    circuit::Region,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct SstoreGadget<F> {
    same_context: SameContextGadget<F>,
    call_id: Cell<F>,
    tx_id: Cell<F>,
    rw_counter_end_of_reversion: Cell<F>,
    is_persistent: Cell<F>,
    callee_address: Cell<F>,
    key: Word<F>,
    value: Word<F>,
    value_prev: Word<F>,
    committed_value: Word<F>,
    is_warm: Cell<F>,
    tx_refund_prev: Word<F>,
    gas_cost: SstoreGasGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for SstoreGadget<F> {
    const NAME: &'static str = "SSTORE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SSTORE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let call_id = cb.query_cell();
        let [tx_id, rw_counter_end_of_reversion, is_persistent, callee_address] = [
            CallContextFieldTag::TxId,
            CallContextFieldTag::RwCounterEndOfReversion,
            CallContextFieldTag::IsPersistent,
            CallContextFieldTag::CalleeAddress,
        ]
        .map(|field_tag| cb.call_context(Some(call_id.expr()), field_tag));

        let key = cb.query_word();
        // Pop the key from the stack
        cb.stack_pop(key.expr());

        let value = cb.query_word();
        // Pop the value from the stack
        cb.stack_pop(value.expr()); // TODO: 79

        let value_prev = cb.query_word();
        let committed_value = cb.query_word();
        cb.account_storage_write_with_reversion(
            callee_address.expr(),
            key.expr(),
            value.expr(),
            value_prev.expr(),
            tx_id.expr(),
            committed_value.expr(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_write_with_reversion(
            tx_id.expr(),
            callee_address.expr(),
            key.expr(),
            true.expr(),
            is_warm.expr(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        let gas_cost = SstoreGasGadget::construct(
            cb,
            value.clone(),
            value_prev.clone(),
            committed_value.clone(),
            is_warm.clone(),
        );

        // TODO: TxRefund
        let tx_refund_prev = cb.query_word();
        let tx_refund = cb.query_word();
        cb.tx_refund_write_with_reversion(
            tx_id.expr(),
            tx_refund.expr(),
            tx_refund_prev.expr(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(9.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(-2.expr()),
            state_write_counter: To(3.expr()),
            ..Default::default()
        };
        let same_context =
            SameContextGadget::construct(cb, opcode, step_state_transition, Some(gas_cost.expr()));

        Self {
            same_context,
            call_id,
            tx_id,
            rw_counter_end_of_reversion,
            is_persistent,
            callee_address,
            key,
            value,
            value_prev,
            committed_value,
            is_warm,
            tx_refund_prev,
            gas_cost,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        self.call_id
            .assign(region, offset, Some(F::from(call.id as u64)))?;

        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;
        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Some(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;
        self.is_persistent
            .assign(region, offset, Some(F::from(call.is_persistent as u64)))?;
        self.callee_address
            .assign(region, offset, call.callee_address.to_scalar())?;

        let [key, value] =
            [step.rw_indices[4], step.rw_indices[5]].map(|idx| block.rws[idx].stack_value());
        self.key.assign(region, offset, Some(key.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        let (_, value_prev, _, committed_value) = block.rws[step.rw_indices[6]].storage_value_aux();
        self.value_prev
            .assign(region, offset, Some(value_prev.to_le_bytes()))?;
        self.committed_value
            .assign(region, offset, Some(committed_value.to_le_bytes()))?;

        let (_, is_warm) = block.rws[step.rw_indices[7]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Some(F::from(is_warm as u64)))?;

        let (_, tx_refund_prev) = block.rws[step.rw_indices[8]].tx_refund_value_pair();
        self.tx_refund_prev
            .assign(region, offset, Some(tx_refund_prev.to_le_bytes()))?;

        self.gas_cost.assign(region, offset, value, value_prev, committed_value, is_warm)?;

        Ok(())
    }
}

// TODO:
#[derive(Clone, Debug)]
pub(crate) struct SstoreGasGadget<F> {
    value: Word<F>,
    value_prev: Word<F>,
    committed_value: Word<F>,
    is_warm: Cell<F>,
    gas_cost: Expression<F>,
}

// TODO:
impl<F: Field> SstoreGasGadget<F> {
    pub(crate) fn construct(
        _cb: &mut ConstraintBuilder<F>,
        value: Word<F>,
        value_prev: Word<F>,
        committed_value: Word<F>,
        is_warm: Cell<F>,
    ) -> Self {
        let warm_case_gas = GasCost::WARM_STORAGE_READ_COST.expr();
        let gas_cost = select::expr(
            is_warm.expr(),
            warm_case_gas.expr(),
            warm_case_gas + GasCost::COLD_SLOAD_COST.expr(),
        );

        Self {
            value,
            value_prev,
            committed_value,
            is_warm,
            gas_cost,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }
    
    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: eth_types::Word,
        value_prev: eth_types::Word,
        committed_value: eth_types::Word,
        is_warm: bool,
    ) -> Result<(), Error> {
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        self.value_prev
            .assign(region, offset, Some(value_prev.to_le_bytes()))?;
        self.committed_value
            .assign(region, offset, Some(committed_value.to_le_bytes()))?;
        self.is_warm
            .assign(region, offset, Some(F::from(is_warm as u64)))?;
        Ok(())
    }
}

// TODO:
#[derive(Clone, Debug)]
pub(crate) struct SstoreTxRefundGadget<F> {
    value: Expression<F>,
    value_prev: Expression<F>,
    committed_value: Expression<F>,
    is_warm: Expression<F>,
    tx_refund_old: Expression<F>,
    tx_refund_new: Expression<F>,
}

// TODO:
impl<F: Field> SstoreTxRefundGadget<F> {
    pub(crate) fn construct(
        _cb: &mut ConstraintBuilder<F>,
        value: Expression<F>,
        value_prev: Expression<F>,
        committed_value: Expression<F>,
        tx_refund_old: Expression<F>,
        is_warm: Expression<F>,
    ) -> Self {
        let tx_refund_new = select::expr(
            is_warm.expr(),
            GasCost::WARM_STORAGE_READ_COST.expr(),
            GasCost::COLD_SLOAD_COST.expr(),
        );

        Self {
            value,
            value_prev,
            committed_value,
            is_warm,
            tx_refund_old,
            tx_refund_new,
        }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        // Return the new tx_refund
        self.tx_refund_new.clone()
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        param::STACK_CAPACITY,
        step::ExecutionState,
        table::{CallContextFieldTag, RwTableTag},
        test::{rand_fp, rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };

    use bus_mapping::evm::OpcodeId;
    use eth_types::{address, bytecode, evm_types::GasCost, Address, ToLittleEndian, ToWord, Word};
    use std::convert::TryInto;

    fn calc_expected_gas_cost(
        value: Word,
        value_prev: Word,
        committed_value: Word,
        is_warm: bool,
    ) -> u64 {
        let warm_case_gas = GasCost::WARM_STORAGE_READ_COST.as_u64();
        if is_warm {
            return warm_case_gas;
        } else {
            return warm_case_gas + GasCost::COLD_SLOAD_COST.as_u64();
        }
    }

    fn test_ok(
        tx: eth_types::Transaction,
        key: Word,
        value: Word,
        value_prev: Word,
        committed_value: Word,
        is_warm: bool,
        result: bool,
    ) {
        let gas = calc_expected_gas_cost(value, value_prev, committed_value, is_warm);
        let rw_counter_end_of_reversion = if result { 0 } else { 14 };

        let call_data_gas_cost = tx
            .input
            .0
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 });

        let randomness = rand_fp();
        let bytecode = Bytecode::from(&bytecode! {
            PUSH32(value)
            PUSH32(key)
            #[start]
            SSTORE
            STOP
        });
        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                nonce: tx.nonce.try_into().unwrap(),
                gas: tx.gas.try_into().unwrap(),
                gas_price: tx.gas_price.unwrap_or_else(Word::zero),
                caller_address: tx.from,
                callee_address: tx.to.unwrap(),
                is_create: tx.to.is_none(),
                value: tx.value,
                call_data: tx.input.to_vec(),
                call_data_length: tx.input.0.len(),
                call_data_gas_cost,
                calls: vec![Call {
                    id: 1,
                    is_root: true,
                    is_create: false,
                    code_source: CodeSource::Account(bytecode.hash),
                    rw_counter_end_of_reversion,
                    is_persistent: result,
                    is_success: result,
                    callee_address: tx.to.unwrap(),
                    ..Default::default()
                }],
                steps: vec![
                    ExecStep {
                        rw_indices: [
                            vec![
                                (RwTableTag::CallContext, 0),
                                (RwTableTag::CallContext, 1),
                                (RwTableTag::CallContext, 2),
                                (RwTableTag::CallContext, 3),
                                (RwTableTag::Stack, 0),
                                (RwTableTag::Stack, 1),
                                (RwTableTag::AccountStorage, 0),
                                (RwTableTag::TxAccessListAccountStorage, 0),
                                (RwTableTag::TxRefund, 0),
                            ],
                            if result {
                                vec![]
                            } else {
                                vec![
                                    (RwTableTag::TxRefund, 1),
                                    (RwTableTag::TxAccessListAccountStorage, 1),
                                    (RwTableTag::AccountStorage, 1),
                                ]
                            },
                        ]
                        .concat(),
                        execution_state: ExecutionState::SSTORE,
                        rw_counter: 1,
                        program_counter: 66,
                        stack_pointer: STACK_CAPACITY,
                        gas_left: gas,
                        gas_cost: gas,
                        opcode: Some(OpcodeId::SSTORE),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 10,
                        program_counter: 67,
                        stack_pointer: STACK_CAPACITY - 2,
                        gas_left: 0,
                        opcode: Some(OpcodeId::STOP),
                        state_write_counter: 3,
                        ..Default::default()
                    },
                ],
            }],
            rws: RwMap(
                [
                    (
                        RwTableTag::Stack,
                        vec![
                            Rw::Stack {
                                rw_counter: 5,
                                is_write: false,
                                call_id: 1,
                                stack_pointer: STACK_CAPACITY,
                                value: key,
                            },
                            Rw::Stack {
                                rw_counter: 6,
                                is_write: false,
                                call_id: 1,
                                stack_pointer: STACK_CAPACITY + 1,
                                value,
                            },
                        ],
                    ),
                    (
                        RwTableTag::AccountStorage,
                        [
                            vec![Rw::AccountStorage {
                                rw_counter: 7,
                                is_write: true,
                                account_address: tx.to.unwrap(),
                                storage_key: key,
                                value: value,
                                value_prev: value_prev,
                                tx_id: 1usize,
                                committed_value: committed_value,
                            }],
                            if result {
                                vec![]
                            } else {
                                vec![Rw::AccountStorage {
                                    rw_counter: rw_counter_end_of_reversion,
                                    is_write: true,
                                    account_address: tx.to.unwrap(),
                                    storage_key: key,
                                    value: value_prev,
                                    value_prev: value,
                                    tx_id: 1usize,
                                    committed_value: committed_value,
                                }]
                            },
                        ]
                        .concat(),
                    ),
                    (
                        RwTableTag::TxAccessListAccountStorage,
                        [
                            vec![Rw::TxAccessListAccountStorage {
                                rw_counter: 8,
                                is_write: true,
                                tx_id: 1usize,
                                account_address: tx.to.unwrap(),
                                storage_key: key,
                                value: true,
                                value_prev: is_warm,
                            }],
                            if result {
                                vec![]
                            } else {
                                vec![Rw::TxAccessListAccountStorage {
                                    rw_counter: rw_counter_end_of_reversion - 1,
                                    is_write: true,
                                    tx_id: 1usize,
                                    account_address: tx.to.unwrap(),
                                    storage_key: key,
                                    value: is_warm,
                                    value_prev: true,
                                }]
                            },
                        ]
                        .concat(),
                    ),
                    (
                        RwTableTag::TxRefund,
                        [
                            vec![Rw::TxRefund {
                                rw_counter: 9,
                                is_write: true,
                                tx_id: 1usize,
                                value: Word::from(0), // TODO:
                                value_prev: Word::from(998),
                            }],
                            if result {
                                vec![]
                            } else {
                                vec![Rw::TxRefund {
                                    rw_counter: rw_counter_end_of_reversion - 2,
                                    is_write: true,
                                    tx_id: 1usize,
                                    value: Word::from(998),
                                    value_prev: Word::from(0), // TODO:
                                }]
                            },
                        ]
                        .concat(),
                    ),
                    (
                        RwTableTag::CallContext,
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
                            Rw::CallContext {
                                rw_counter: 4,
                                is_write: false,
                                call_id: 1,
                                field_tag: CallContextFieldTag::CalleeAddress,
                                value: tx.to.unwrap().to_word(),
                            },
                        ],
                    ),
                ]
                .into(),
            ),
            bytecodes: vec![bytecode],
            ..Default::default()
        };

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    fn mock_tx() -> eth_types::Transaction {
        let from = address!("0x00000000000000000000000000000000000000fe");
        let to = address!("0x00000000000000000000000000000000000000ff");
        eth_types::Transaction {
            from,
            to: Some(to),
            ..Default::default()
        }
    }

    #[test]
    fn sstore_gadget_warm() {
        // persist cases
        test_ok(
            mock_tx(),
            0x030201.into(),
            0x060504.into(),
            0x060504.into(),
            0x060504.into(),
            true,
            true,
        );

        // revert cases
        test_ok(
            mock_tx(),
            0x030201.into(),
            0x060504.into(),
            0x060504.into(),
            0x060504.into(),
            true,
            false,
        );
    }

    #[test]
    fn sstore_gadget_cold() {
        // persist cases
        test_ok(
            mock_tx(),
            0x030201.into(),
            0x060504.into(),
            0x060504.into(),
            0x060504.into(),
            false,
            true,
        );

        // revert cases
        test_ok(
            mock_tx(),
            0x030201.into(),
            0x060504.into(),
            0x060504.into(),
            0x060504.into(),
            false,
            false,
        );
    }
}
