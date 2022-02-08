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
    // tx_id: Cell<F>,
    key: Word<F>,
    value: Word<F>,
    // committed_value: Word<F>,
    gas: SloadGasGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for SloadGadget<F> {
    const NAME: &'static str = "SLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SLOAD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Use rw_counter of the step which triggers next call as its call_id.
        let call_id = cb.curr.state.rw_counter.clone();
        let [tx_id, rw_counter_end_of_reversion, is_persistent] = [
            CallContextFieldTag::TxId,
            CallContextFieldTag::RwCounterEndOfReversion,
            CallContextFieldTag::IsPersistent,
        ]
        .map(|field_tag| cb.call_context(Some(call_id.expr()), field_tag));
        let tx_callee_address = cb.tx_context(tx_id.expr(), TxContextFieldTag::CalleeAddress);

        let key = cb.query_word();
        // Pop the key from the stack
        cb.stack_pop(key.expr());

        let is_warm = cb.query_bool();
        cb.storage_slot_access_list_read(
            tx_id.expr(),
            tx_callee_address.expr(),
            key.expr(),
            is_warm.expr(),
        );

        let gas = SloadGasGadget::construct(cb, is_warm.expr());

        let value = cb.query_word();
        let committed_value = cb.query_word();
        cb.storage_slot_read(
            tx_callee_address.expr(),
            key.expr(),
            value.expr(),
            tx_id.expr(),
            committed_value.expr(),
        );

        cb.storage_slot_access_list_write_with_reversion(
            tx_id.expr(),
            tx_callee_address.expr(),
            key.expr(),
            true.expr(),
            is_warm.expr(),
            is_persistent.expr(),
            rw_counter_end_of_reversion.expr(),
        );

        cb.stack_push(value.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(8.expr()),      // TODO:
            program_counter: Delta(1.expr()), // TODO:
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            Some(gas.gas_cost().expr()),
        );

        Self {
            same_context: same_context,
            // tx_id: tx_id,
            key: key,
            value: value,
            // committed_value: committed_value,
            gas: gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction<F>,
        _call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [key, value] =
            [step.rw_indices[3], step.rw_indices[7]].map(|idx| block.rws[idx].stack_value());
        self.key.assign(region, offset, Some(key.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        // TODO:
        // self.gas.assign(region, offset,
        // ???

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
    use eth_types::{address, bytecode, Address, ToLittleEndian, Word};
    use std::convert::TryInto;

    fn test_ok(tx: eth_types::Transaction, key: Word, _value: Word, result: bool) {
        let rw_counter_end_of_reversion = if result { 0 } else { 19 };

        // TODO:
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
                    ..Default::default()
                }],
                steps: vec![
                    ExecStep {
                        rw_indices: (8..17 + if result { 0 } else { 2 }).collect(),
                        execution_state: ExecutionState::SLOAD,
                        rw_counter: 9,
                        program_counter: 33,
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
                    /* Rw::Account {
                     *     rw_counter: 4,
                     *     is_write: true,
                     *     account_address: tx.from,
                     *     field_tag: AccountFieldTag::Nonce,
                     *     value: tx.nonce + Word::one(),
                     *     value_prev: tx.nonce,
                     * },
                     * Rw::TxAccessListAccount {
                     *     rw_counter: 5,
                     *     is_write: true,
                     *     tx_id: 1,
                     *     account_address: tx.from,
                     *     value: true,
                     *     value_prev: false,
                     * }, */
                ],
                if result {
                    vec![]
                } else {
                    vec![Rw::TxAccessListStorageSlot {
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

        // assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
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
        test_ok(mock_tx(), 0x030201.into(), 0x060504.into(), true);
        test_ok(mock_tx(), 0x090705.into(), 0x060504.into(), true);
        // TODO: false
    }

    #[test]
    fn sload_gadget_rand() {
        let key = rand_word();
        let value = rand_word();
        test_ok(mock_tx(), key, value, true);
        test_ok(mock_tx(), key, value, true);
        // TODO: false
    }
}
