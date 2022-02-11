use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::STACK_CAPACITY,
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::{SameContextGadget, TransferWithGasFeeGadget},
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
use eth_types::{evm_types::GasCost, ToLittleEndian, ToScalar};
use halo2::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Error, Expression},
};

#[derive(Clone, Debug)]
pub(crate) struct SloadGadget<F> {
    same_context: SameContextGadget<F>,
    call_id: Cell<F>,
    tx_id: Cell<F>,
    rw_counter_end_of_reversion: Cell<F>,
    is_persistent: Cell<F>,
    callee_address: Cell<F>,
    key: Word<F>,
    value: Word<F>,
    committed_value: Word<F>,
    is_warm: Cell<F>,
    gas: SloadGasGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for SloadGadget<F> {
    const NAME: &'static str = "SLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SLOAD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // TODO:
        // Use rw_counter of the step which triggers next call as its call_id.
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
        let committed_value = cb.query_word();
        cb.account_storage_read(
            callee_address.expr(),
            key.expr(),
            value.expr(),
            tx_id.expr(),
            committed_value.expr(),
        );

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_write_with_reversion(
            tx_id.expr(),
            0.expr(), // TODO: callee_address.expr(),
            key.expr(),
            false.expr(), // TODO:
            false.expr(), // TODO: is_warm.expr(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        cb.stack_push(value.expr());

        let gas = SloadGasGadget::construct(cb, is_warm.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(8.expr()),
            program_counter: Delta(1.expr()),
            state_write_counter: To(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            Some(gas.gas_cost()),
        );

        Self {
            same_context: same_context,
            call_id: call_id,
            tx_id: tx_id,
            rw_counter_end_of_reversion: rw_counter_end_of_reversion,
            is_persistent: is_persistent,
            callee_address: callee_address,
            key: key,
            value: value,
            committed_value: committed_value,
            is_warm: is_warm,
            gas: gas,
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
            [step.rw_indices[4], step.rw_indices[7]].map(|idx| block.rws[idx].stack_value());
        self.key.assign(region, offset, Some(key.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        let (_, committed_value) = block.rws[step.rw_indices[5]].aux_pair();
        self.committed_value
            .assign(region, offset, Some(committed_value.to_le_bytes()))?;

        let (_, is_warm) = block.rws[step.rw_indices[6]].accesslist_value_pair();
        self.is_warm
            .assign(region, offset, Some(F::from(is_warm as u64)))?;

        // self.gas.assign(region, offset, Some(F::from(is_warm as u64)))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SloadGasGadget<F> {
    is_warm: Expression<F>,
    gas_cost: Expression<F>,
}

impl<F: FieldExt> SloadGasGadget<F> {
    pub(crate) fn construct(cb: &mut ConstraintBuilder<F>, is_warm: Expression<F>) -> Self {
        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_STORAGE_READ_COST.expr(),
            GasCost::COLD_SLOAD_COST.expr(),
        );

        Self {
            is_warm: is_warm,
            gas_cost: gas_cost,
        }
    }

    pub(crate) fn gas_cost(&self) -> Expression<F> {
        // Return the gas cost
        self.gas_cost.clone()
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        param::STACK_CAPACITY,
        step::ExecutionState,
        table::CallContextFieldTag,
        test::{rand_fp, rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination,
        witness::{self, Block, Bytecode, Call, ExecStep, Rw, Transaction},
    };
    use crate::test_util::run_test_circuits;
    use bus_mapping::evm::OpcodeId;
    use eth_types::{address, bytecode, evm_types::GasCost, Address, ToLittleEndian, ToWord, Word};
    use std::convert::TryInto;

    fn test_ok(tx: eth_types::Transaction, key: Word, value: Word, is_warm: bool, result: bool) {
        let rw_counter_end_of_reversion = if result { 0 } else { 19 };

        let call_data_gas_cost = tx
            .input
            .0
            .iter()
            .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 });

        let randomness = rand_fp();
        let bytecode = Bytecode::from(&bytecode! {
            // TODO: SSTORE first
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
                    callee_address: tx.to.unwrap_or_else(Address::zero),
                    ..Default::default()
                }],
                steps: vec![
                    ExecStep {
                        // TODO:
                        rw_indices: (0..8 + if result { 0 } else { 2 }).collect(),
                        execution_state: ExecutionState::SLOAD,
                        rw_counter: 9,
                        program_counter: 33,
                        stack_pointer: STACK_CAPACITY,
                        gas_left: if is_warm {
                            GasCost::WARM_STORAGE_READ_COST.as_u64()
                        } else {
                            GasCost::COLD_SLOAD_COST.as_u64()
                        },
                        gas_cost: if is_warm {
                            GasCost::WARM_STORAGE_READ_COST.as_u64()
                        } else {
                            GasCost::COLD_SLOAD_COST.as_u64()
                        },
                        opcode: Some(OpcodeId::SLOAD), // TODO:
                        ..Default::default()
                    },
                    ExecStep {
                        execution_state: ExecutionState::STOP, // TODO: revert?
                        rw_counter: 17,
                        program_counter: 34,
                        stack_pointer: STACK_CAPACITY,
                        gas_left: 0,
                        opcode: Some(OpcodeId::STOP), // TODO:
                        state_write_counter: 1,
                        ..Default::default()
                    },
                ],
            }],
            rws: [
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
                        value: Word::from(result as u64),
                    },
                    Rw::CallContext {
                        rw_counter: 12,
                        is_write: false,
                        call_id: 1,
                        field_tag: CallContextFieldTag::CalleeAddress,
                        value: tx.to.unwrap().to_word(),
                    },
                    Rw::Stack {
                        rw_counter: 13,
                        is_write: false,
                        call_id: 1,
                        stack_pointer: STACK_CAPACITY,
                        value: key,
                    },
                    Rw::AccountStorage {
                        rw_counter: 14,
                        is_write: false,
                        address: tx.to.unwrap(),
                        key: key,
                        value: value,
                        value_prev: value,
                        tx_id: 1,
                        committed_value: Word::zero(),
                    },
                    Rw::TxAccessListAccountStorage {
                        rw_counter: 15,
                        is_write: true,
                        tx_id: 1,
                        address: Address::zero(), // TODO: tx.to.unwrap(),
                        key: key,
                        value: false,      // TODO:
                        value_prev: false, // TODO:
                    },
                    Rw::Stack {
                        rw_counter: 16,
                        is_write: true,
                        call_id: 1,
                        stack_pointer: STACK_CAPACITY,
                        value: value,
                    },
                ],
                if result {
                    vec![]
                } else {
                    vec![Rw::TxAccessListAccountStorage {
                        rw_counter: 19,
                        is_write: true,
                        tx_id: 1usize,
                        address: tx.to.unwrap_or_else(Address::zero),
                        key: key,
                        value: true,
                        value_prev: true,
                    }]
                },
            ]
            .concat(),
            bytecodes: vec![bytecode],
            ..Default::default()
        };

        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    fn mock_tx() -> eth_types::Transaction {
        let from = address!("0x00000000000000000000000000000000000000fe");
        let to = address!("0x00000000000000000000000000000000000000ff");
        let minimal_gas = Word::from(21000);
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

        test_ok(mock_tx(), 0x090705.into(), 0x060504.into(), true, true);
        test_ok(mock_tx(), 0x090705.into(), 0x060504.into(), true, false);
        test_ok(mock_tx(), 0x090705.into(), 0x060504.into(), false, true);
        test_ok(mock_tx(), 0x090705.into(), 0x060504.into(), false, false);
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
