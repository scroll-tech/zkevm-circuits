use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_GAS;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::{RestoreContextGadget, SloadGasGadget};
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
pub(crate) struct ErrorOOGSloadGadget<F> {
    opcode: Cell<F>,
    tx_id: Cell<F>,
    callee_address: Cell<F>,
    phase2_key: Cell<F>,
    is_warm: Cell<F>,
    insufficient_gas: LtGadget<F, N_BYTES_GAS>,
    rw_counter_end_of_reversion: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGSloadGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasSLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasSLOAD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());
        cb.require_equal(
            "ErrorOutOfGasSLOAD opcode must be SLOAD",
            opcode.expr(),
            OpcodeId::SLOAD.expr(),
        );

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);

        let phase2_key = cb.query_cell_phase2();
        cb.stack_pop(phase2_key.expr());

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_read(
            tx_id.expr(),
            callee_address.expr(),
            phase2_key.expr(),
            is_warm.expr(),
        );

        // Verify the amount of gas available is less than the amount of gas cost.
        let gas_cost = SloadGasGadget::construct(cb, is_warm.expr()).expr();
        let insufficient_gas = LtGadget::construct(cb, cb.curr.state.gas_left.expr(), gas_cost);
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
                rw_counter: Delta(6.expr() + cb.curr.state.reversible_write_counter.expr()),
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
            callee_address,
            phase2_key,
            is_warm,
            insufficient_gas,
            rw_counter_end_of_reversion,
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
        let phase2_key = block.rws[step.rw_indices[2]].stack_value();
        let (is_warm, _) = block.rws[step.rw_indices[3]].tx_access_list_value_pair();
        let gas_cost = SloadGasGadget::<F>::cal_gas_cost_for_assignment(is_warm);
        log::debug!(
            "ErrorOutOfGasSLOAD: gas_left = {}, gas_cost = {}",
            step.gas_left,
            gas_cost
        );

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
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
            .assign(region, offset, region.word_rlc(phase2_key))?;
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;
        self.insufficient_gas.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(gas_cost)),
        )?;
        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Value::known(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;
        self.restore_context
            .assign(region, offset, block, call, step, 6)
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::run_test_circuits;
    use eth_types::evm_types::{GasCost, OpcodeId};
    use eth_types::{bytecode, Bytecode, ToWord, U256};
    use mock::test_ctx::helpers::account_0_code_account_1_no_code;
    use mock::TestContext;

    const TESTING_LOAD_KEY: U256 = U256([0, 0, 0, 0x030201]);
    const TESTING_LOAD_VALUE: U256 = U256([0, 0, 0, 0x060504]);

    #[test]
    fn test_oog_sload_root() {
        test_root(false);
        test_root(true);
    }

    #[test]
    fn test_oog_sload_internal() {
        test_internal(0x20, 0x00, false);
        test_internal(0x1010, 0xff, false);
        test_internal(0x20, 0x00, true);
        test_internal(0x1010, 0xff, true);
    }

    struct TestingData {
        bytecode: Bytecode,
        gas_cost: u64,
    }

    impl TestingData {
        pub fn new(is_warm: bool) -> Self {
            let mut bytecode = Bytecode::default();
            let mut gas_cost = OpcodeId::PUSH32.constant_gas_cost().0 + GasCost::COLD_SLOAD.0;
            if is_warm {
                bytecode.append(&bytecode! {
                    PUSH32(TESTING_LOAD_KEY)
                    SLOAD
                });
                gas_cost += OpcodeId::PUSH32.constant_gas_cost().0 + GasCost::WARM_ACCESS.0;
            }
            bytecode.append(&bytecode! {
                PUSH32(TESTING_LOAD_KEY)
                SLOAD
            });

            Self { bytecode, gas_cost }
        }
    }

    fn test_root(is_warm: bool) {
        let testing_data = TestingData::new(is_warm);

        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(testing_data.bytecode),
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

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }

    fn test_internal(call_data_offset: usize, call_data_length: usize, is_warm: bool) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let testing_data = TestingData::new(is_warm);
        let code_b = testing_data.bytecode;
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
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(U256::from(1_u64 << 20));
            },
            |mut txs, accs| {
                txs[0].from(accs[2].address).to(accs[1].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }
}
