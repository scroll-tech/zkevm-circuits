use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_GAS;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::{
    cal_sstore_gas_cost_for_assignment, RestoreContextGadget, SstoreGasGadget,
};
use crate::evm_circuit::util::constraint_builder::Transition::{Delta, Same};
use crate::evm_circuit::util::constraint_builder::{ConstraintBuilder, StepStateTransition};
use crate::evm_circuit::util::math_gadget::LtGadget;
use crate::evm_circuit::util::{CachedRegion, Cell};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::table::CallContextFieldTag;
use crate::util::Expr;
use eth_types::evm_types::OpcodeId;
use eth_types::{Field, ToScalar};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGSstoreGadget<F> {
    opcode: Cell<F>,
    tx_id: Cell<F>,
    is_static: Cell<F>,
    callee_address: Cell<F>,
    phase2_key: Cell<F>,
    phase2_value: Cell<F>,
    phase2_value_prev: Cell<F>,
    phase2_original_value: Cell<F>,
    is_warm: Cell<F>,
    rw_counter_end_of_reversion: Cell<F>,
    gas_cost: SstoreGasGadget<F>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGSstoreGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasSSTORE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasSSTORE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());
        cb.require_equal(
            "ErrorOutOfGasSSTORE opcode must be SSTORE",
            opcode.expr(),
            OpcodeId::SSTORE.expr(),
        );

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_static = cb.call_context(None, CallContextFieldTag::IsStatic);
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);

        // Constrain `is_static` is false.
        cb.require_zero("is_static == false", is_static.expr());

        let phase2_key = cb.query_cell_phase2();
        let phase2_value = cb.query_cell_phase2();
        let phase2_value_prev = cb.query_cell_phase2();
        let phase2_original_value = cb.query_cell_phase2();
        let is_warm = cb.query_bool();

        cb.stack_pop(phase2_key.expr());
        cb.stack_pop(phase2_value.expr());

        cb.account_storage_read(
            callee_address.expr(),
            phase2_key.expr(),
            phase2_value_prev.expr(),
            tx_id.expr(),
            phase2_original_value.expr(),
        );

        cb.account_storage_access_list_read(
            tx_id.expr(),
            callee_address.expr(),
            phase2_key.expr(),
            is_warm.expr(),
        );

        let gas_cost = SstoreGasGadget::construct(
            cb,
            phase2_value.clone(),
            phase2_value_prev.clone(),
            phase2_original_value.clone(),
            is_warm.clone(),
        );

        // Verify the amount of gas available is less than the amount of gas cost.
        let insufficient_gas =
            LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost.expr());
        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas.expr(),
            1.expr(),
        );

        // Current call must fail.
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 0.expr());

        let rw_counter_end_of_reversion = cb.query_cell();
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::RwCounterEndOfReversion,
            rw_counter_end_of_reversion.expr(),
        );

        // Go to EndTx only when is_root.
        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );

        // When it's a root call.
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // Do step state transition.
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(9.expr() + cb.curr.state.reversible_write_counter.expr()),
                ..StepStateTransition::any()
            });
        });

        // When it's an internal call, need to restore caller's state as finishing this
        // call. Restore caller state to next StepState.
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        // Constrain RwCounterEndOfReversion.
        let rw_counter_end_of_step =
            cb.curr.state.rw_counter.expr() + cb.rw_counter_offset() - 1.expr();
        cb.require_equal(
            "rw_counter_end_of_reversion = rw_counter_end_of_step + reversible_counter",
            rw_counter_end_of_reversion.expr(),
            rw_counter_end_of_step + cb.curr.state.reversible_write_counter.expr(),
        );

        Self {
            opcode,
            tx_id,
            is_static,
            callee_address,
            phase2_key,
            phase2_value,
            phase2_value_prev,
            phase2_original_value,
            is_warm,
            rw_counter_end_of_reversion,
            gas_cost,
            insufficient_gas,
            restore_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        let [key, value] =
            [step.rw_indices[3], step.rw_indices[4]].map(|idx| block.rws[idx].stack_value());
        let (_, value_prev, _, original_value) = block.rws[step.rw_indices[5]].storage_value_aux();
        let (_, is_warm) = block.rws[step.rw_indices[6]].tx_access_list_value_pair();
        let gas_cost =
            cal_sstore_gas_cost_for_assignment(value, value_prev, original_value, is_warm);

        log::debug!(
            "ErrorOutOfGasSSTORE: gas_left = {}, gas_cost = {}",
            step.gas_left,
            gas_cost
        );

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.is_static
            .assign(region, offset, Value::known(F::from(call.is_static as u64)))?;
        self.callee_address.assign(
            region,
            offset,
            Value::known(
                call.callee_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;
        self.phase2_key
            .assign(region, offset, region.word_rlc(key))?;
        self.phase2_value
            .assign(region, offset, region.word_rlc(value))?;
        self.phase2_value_prev
            .assign(region, offset, region.word_rlc(value_prev))?;
        self.phase2_original_value
            .assign(region, offset, region.word_rlc(original_value))?;
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;
        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Value::known(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;
        self.gas_cost.assign(
            region,
            offset,
            gas_cost,
            value,
            value_prev,
            original_value,
            is_warm,
        )?;
        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(gas_cost)),
        )?;
        self.restore_context
            .assign(region, offset, block, call, step, 9)
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::evm_circuit::util::common_gadget::cal_sstore_gas_cost_for_assignment;
    use crate::test_util::{run_test_circuits, BytecodeTestConfig};
    use eth_types::evm_types::{GasCost, OpcodeId};
    use eth_types::{bytecode, Bytecode, ToWord, U256};
    use mock::{eth, TestContext, MOCK_ACCOUNTS};

    const TESTING_STORE_KEY: U256 = U256([0, 0, 0, 0x030201]);

    #[test]
    fn test_oog_sstore_no_refund() {
        [false, true].into_iter().for_each(|is_warm| {
            // value_prev == value
            let testing_data = TestingData::new(
                TESTING_STORE_KEY,
                0x060504.into(),
                0x060504.into(),
                0x060504.into(),
                is_warm,
            );
            test_root(&testing_data);
            test_internal(0x20, 0x00, &testing_data);
            test_internal(0x1010, 0xff, &testing_data);
        });
    }

    #[test]
    fn test_oog_sstore_delete_slot() {
        [false, true].into_iter().for_each(|is_warm| {
            // value_prev != value, original_value != value, value == 0
            let testing_data = TestingData::new(
                TESTING_STORE_KEY,
                0x0.into(),
                0x060505.into(),
                0x060506.into(),
                is_warm,
            );
            test_root(&testing_data);
            test_internal(0x20, 0x00, &testing_data);
            test_internal(0x1010, 0xff, &testing_data);
        });
    }

    #[test]
    fn test_oog_sstore_reset_existing() {
        [false, true].into_iter().for_each(|is_warm| {
            // value_prev != value, original_value == value, original_value != 0
            let testing_data = TestingData::new(
                TESTING_STORE_KEY,
                0x060504.into(),
                0x060505.into(),
                0x060504.into(),
                is_warm,
            );
            test_root(&testing_data);
            test_internal(0x20, 0x00, &testing_data);
            test_internal(0x1010, 0xff, &testing_data);
        });
    }

    #[test]
    fn test_oog_sstore_reset_inexistent() {
        [false, true].into_iter().for_each(|is_warm| {
            // value_prev != value, original_value == value, original_value == 0
            let testing_data = TestingData::new(
                TESTING_STORE_KEY,
                0.into(),
                0x060505.into(),
                0.into(),
                is_warm,
            );
            test_root(&testing_data);
            test_internal(0x20, 0x00, &testing_data);
            test_internal(0x1010, 0xff, &testing_data);
        });
    }

    #[test]
    fn test_oog_sstore_recreate_slot() {
        [false, true].into_iter().for_each(|is_warm| {
            // value_prev != value, original_value != value_prev, original_value != value,
            // value_prev == 0
            let testing_data = TestingData::new(
                TESTING_STORE_KEY,
                0x060504.into(),
                0x0.into(),
                0x060506.into(),
                is_warm,
            );
            test_root(&testing_data);
            test_internal(0x20, 0x00, &testing_data);
            test_internal(0x1010, 0xff, &testing_data);
        });
    }

    #[test]
    fn test_oog_sstore_recreate_slot_and_reset_inexistent() {
        [false, true].into_iter().for_each(|is_warm| {
            // value_prev != value, original_value != value_prev, original_value == value,
            // value_prev == 0
            let testing_data = TestingData::new(
                TESTING_STORE_KEY,
                0x060504.into(),
                0x0.into(),
                0x060504.into(),
                is_warm,
            );
            test_root(&testing_data);
            test_internal(0x20, 0x00, &testing_data);
            test_internal(0x1010, 0xff, &testing_data);
        });
    }

    struct TestingData {
        key: U256,
        value: U256,
        value_prev: U256,
        original_value: U256,
        is_warm: bool,
        gas_cost: u64,
        bytecode: Bytecode,
    }

    impl TestingData {
        pub fn new(
            key: U256,
            value: U256,
            value_prev: U256,
            original_value: U256,
            is_warm: bool,
        ) -> Self {
            let mut bytecode = bytecode! {
                PUSH32(value_prev)
                PUSH32(key)
                SSTORE
            };
            let mut gas_cost = 2 * OpcodeId::PUSH32.constant_gas_cost().0
                + cal_sstore_gas_cost_for_assignment(
                    value_prev,
                    original_value,
                    original_value,
                    false,
                );
            if is_warm {
                bytecode.append(&bytecode! {
                    PUSH32(value)
                    PUSH32(key)
                    SSTORE
                });
                gas_cost += 2 * OpcodeId::PUSH32.constant_gas_cost().0
                    + cal_sstore_gas_cost_for_assignment(value, value_prev, original_value, true);
            }

            Self {
                key,
                value,
                value_prev,
                original_value,
                is_warm,
                gas_cost,
                bytecode,
            }
        }
    }

    fn test_root(testing_data: &TestingData) {
        let ctx = TestContext::<2, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(MOCK_ACCOUNTS[0])
                    .balance(eth(10))
                    .code(testing_data.bytecode.clone())
                    .storage([(testing_data.key, testing_data.original_value)].into_iter());
                accs[1].address(MOCK_ACCOUNTS[1]).balance(eth(10));
            },
            |mut txs, accs| {
                // Decrease expected gas cost (by 1) to trigger out of gas error.
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas((GasCost::TX.0 + testing_data.gas_cost - 1).into());
            },
            |block, _tx| block.number(0xcafe_u64),
        )
        .unwrap();

        let test_config = BytecodeTestConfig {
            enable_state_circuit_test: true,
            ..Default::default()
        };
        assert_eq!(run_test_circuits(ctx, Some(test_config),), Ok(()));
    }

    fn test_internal(call_data_offset: usize, call_data_length: usize, testing_data: &TestingData) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = testing_data.bytecode.clone();
        let gas_cost_b = testing_data.gas_cost;

        // Code A calls code B.
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(U256::from_big_endian(&rand_bytes(8)))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            // Decrease expected gas cost (by 1) to trigger out of gas error.
            PUSH32(gas_cost_b - 1) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(addr_b)
                    .code(code_b)
                    .storage([(testing_data.key, testing_data.original_value)].into_iter());
                accs[1].address(addr_a).code(code_a);
                accs[2].address(mock::MOCK_ACCOUNTS[2]).balance(eth(10));
            },
            |mut txs, accs| {
                txs[0].from(accs[2].address).to(accs[1].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        let test_config = BytecodeTestConfig {
            enable_state_circuit_test: true,
            ..Default::default()
        };
        assert_eq!(run_test_circuits(ctx, Some(test_config),), Ok(()));
    }
}
