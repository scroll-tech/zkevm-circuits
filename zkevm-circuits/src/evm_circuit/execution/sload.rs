use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition, Transition::Delta,
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
pub(crate) struct SloadGadget<F> {
    same_context: SameContextGadget<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    callee_address: Cell<F>,
    key: Cell<F>,
    value: Cell<F>,
    committed_value: Cell<F>,
    is_warm: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for SloadGadget<F> {
    const NAME: &'static str = "SLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SLOAD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info(None);
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);

        let key = cb.query_cell();
        // Pop the key from the stack
        cb.stack_pop(key.expr());

        let value = cb.query_cell();
        let committed_value = cb.query_cell();
        cb.account_storage_read(
            callee_address.expr(),
            key.expr(),
            value.expr(),
            tx_id.expr(),
            committed_value.expr(),
        );

        cb.stack_push(value.expr());

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_write(
            tx_id.expr(),
            callee_address.expr(),
            key.expr(),
            true.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        let gas_cost = SloadGasGadget::construct(cb, is_warm.expr()).expr();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(8.expr()),
            program_counter: Delta(1.expr()),
            state_write_counter: Delta(1.expr()),
            gas_left: Delta(-gas_cost),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            tx_id,
            reversion_info,
            callee_address,
            key,
            value,
            committed_value,
            is_warm,
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

        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.callee_address
            .assign(region, offset, call.callee_address.to_scalar())?;

        let [key, value] =
            [step.rw_indices[4], step.rw_indices[6]].map(|idx| block.rws[idx].stack_value());
        self.key.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                key.to_le_bytes(),
                block.randomness,
            )),
        )?;
        self.value.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                value.to_le_bytes(),
                block.randomness,
            )),
        )?;

        let (_, committed_value) = block.rws[step.rw_indices[5]].aux_pair();
        self.committed_value.assign(
            region,
            offset,
            Some(Word::random_linear_combine(
                committed_value.to_le_bytes(),
                block.randomness,
            )),
        )?;

        let (_, is_warm) = block.rws[step.rw_indices[7]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Some(F::from(is_warm as u64)))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SloadGasGadget<F> {
    is_warm: Expression<F>,
    gas_cost: Expression<F>,
}

impl<F: Field> SloadGasGadget<F> {
    pub(crate) fn construct(_cb: &mut ConstraintBuilder<F>, is_warm: Expression<F>) -> Self {
        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_SLOAD.expr(),
        );

        Self { is_warm, gas_cost }
    }

    pub(crate) fn expr(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        param::STACK_CAPACITY,
        step::ExecutionState,
        table::{CallContextFieldTag, RwTableTag},
        test::{rand_fp, rand_word, run_test_circuit_incomplete_fixed_table},
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };

    use bus_mapping::evm::OpcodeId;
    use eth_types::{address, bytecode, evm_types::GasCost, ToWord, Word};
    use std::convert::TryInto;

    fn test_ok(
        tx: eth_types::Transaction,
        key: Word,
        value: Word,
        is_warm: bool,
        is_persistent: bool,
    ) {
        let rw_counter_end_of_reversion = if is_persistent { 0 } else { 19 };

        let call_data_gas_cost = tx
            .input
            .0
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 });

        let randomness = rand_fp();
        let bytecode = Bytecode::from(&bytecode! {
            PUSH32(key)
            #[start]
            SLOAD
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
                    is_persistent,
                    is_success: is_persistent,
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
                                (RwTableTag::AccountStorage, 0),
                                (RwTableTag::Stack, 1),
                                (RwTableTag::TxAccessListAccountStorage, 0),
                            ],
                            if is_persistent {
                                vec![]
                            } else {
                                vec![(RwTableTag::TxAccessListAccountStorage, 1)]
                            },
                        ]
                        .concat(),
                        execution_state: ExecutionState::SLOAD,
                        rw_counter: 9,
                        program_counter: 33,
                        stack_pointer: STACK_CAPACITY,
                        gas_left: if is_warm {
                            GasCost::WARM_ACCESS.as_u64()
                        } else {
                            GasCost::COLD_SLOAD.as_u64()
                        },
                        gas_cost: if is_warm {
                            GasCost::WARM_ACCESS.as_u64()
                        } else {
                            GasCost::COLD_SLOAD.as_u64()
                        },
                        opcode: Some(OpcodeId::SLOAD),
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP,
                        rw_counter: 17,
                        program_counter: 34,
                        stack_pointer: STACK_CAPACITY,
                        gas_left: 0,
                        opcode: Some(OpcodeId::STOP),
                        state_write_counter: 1,
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
                                rw_counter: 13,
                                is_write: false,
                                call_id: 1,
                                stack_pointer: STACK_CAPACITY,
                                value: key,
                            },
                            Rw::Stack {
                                rw_counter: 15,
                                is_write: true,
                                call_id: 1,
                                stack_pointer: STACK_CAPACITY,
                                value,
                            },
                        ],
                    ),
                    (
                        RwTableTag::AccountStorage,
                        vec![Rw::AccountStorage {
                            rw_counter: 14,
                            is_write: false,
                            account_address: tx.to.unwrap(),
                            storage_key: key,
                            value,
                            value_prev: value,
                            tx_id: 1,
                            committed_value: Word::zero(),
                        }],
                    ),
                    (
                        RwTableTag::TxAccessListAccountStorage,
                        [
                            vec![Rw::TxAccessListAccountStorage {
                                rw_counter: 16,
                                is_write: true,
                                tx_id: 1,
                                account_address: tx.to.unwrap(),
                                storage_key: key,
                                value: true,
                                value_prev: is_warm,
                            }],
                            if is_persistent {
                                vec![]
                            } else {
                                vec![Rw::TxAccessListAccountStorage {
                                    rw_counter: rw_counter_end_of_reversion,
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
                        RwTableTag::CallContext,
                        vec![
                            Rw::CallContext {
                                rw_counter: 9,
                                is_write: false,
                                call_id: 1,
                                field_tag: CallContextFieldTag::TxId,
                                value: Word::one(),
                            },
                            Rw::CallContext {
                                rw_counter: 10,
                                is_write: false,
                                call_id: 1,
                                field_tag: CallContextFieldTag::RwCounterEndOfReversion,
                                value: Word::from(rw_counter_end_of_reversion),
                            },
                            Rw::CallContext {
                                rw_counter: 11,
                                is_write: false,
                                call_id: 1,
                                field_tag: CallContextFieldTag::IsPersistent,
                                value: Word::from(is_persistent as u64),
                            },
                            Rw::CallContext {
                                rw_counter: 12,
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
    fn sload_gadget_simple() {
        test_ok(mock_tx(), 0x030201.into(), 0x060504.into(), true, true);
        test_ok(mock_tx(), 0x030201.into(), 0x060504.into(), true, false);
        test_ok(mock_tx(), 0x030201.into(), 0x060504.into(), false, true);
        test_ok(mock_tx(), 0x030201.into(), 0x060504.into(), false, false);
    }

    #[test]
    fn sload_gadget_rand() {
        let key = rand_word();
        let value = rand_word();
        test_ok(mock_tx(), key, value, true, true);
        test_ok(mock_tx(), key, value, true, false);
        test_ok(mock_tx(), key, value, false, true);
        test_ok(mock_tx(), key, value, false, false);
    }
}
