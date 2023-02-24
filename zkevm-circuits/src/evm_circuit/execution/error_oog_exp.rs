use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_GAS;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::RestoreContextGadget;
use crate::evm_circuit::util::constraint_builder::Transition::{Delta, Same};
use crate::evm_circuit::util::constraint_builder::{ConstraintBuilder, StepStateTransition};
use crate::evm_circuit::util::math_gadget::{ByteSizeGadget, LtGadget};
use crate::evm_circuit::util::{CachedRegion, Cell, Word};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::table::CallContextFieldTag;
use crate::util::Expr;
use eth_types::evm_types::{GasCost, OpcodeId};
use eth_types::{Field, ToLittleEndian};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::EXP`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGExpGadget<F> {
    opcode: Cell<F>,
    rw_counter_end_of_reversion: Cell<F>,
    base: Word<F>,
    exponent: Word<F>,
    exponent_byte_size: ByteSizeGadget<F>,
    insufficient_gas_cost: LtGadget<F, N_BYTES_GAS>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGExpGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasEXP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasEXP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        cb.require_equal(
            "ErrorOutOfGasEXP opcode must be EXP",
            opcode.expr(),
            OpcodeId::EXP.expr(),
        );

        let base = cb.query_word_rlc();
        let exponent = cb.query_word_rlc();
        cb.stack_pop(base.expr());
        cb.stack_pop(exponent.expr());

        let exponent_byte_size = ByteSizeGadget::construct(
            cb,
            exponent
                .cells
                .iter()
                .map(Expr::expr)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        let insufficient_gas_cost = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            // static_gas = 10
            // dynamic_gas = exponent_byte_size * 50
            // gas_cost = dynamic_gas + static_gas
            exponent_byte_size.byte_size() * GasCost::EXP_BYTE_TIMES.0.expr()
                + OpcodeId::EXP.constant_gas_cost().expr(),
        );

        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas_cost.expr(),
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
                rw_counter: Delta(4.expr() + cb.curr.state.reversible_write_counter.expr()),
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
            rw_counter_end_of_reversion,
            base,
            exponent,
            exponent_byte_size,
            insufficient_gas_cost,
            restore_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        let [base, exponent] = [0, 1].map(|idx| block.rws[step.rw_indices[idx]].stack_value());

        log::debug!(
            "ErrorOutOfGasEXP: gas_left = {}, gas_cost = {}",
            step.gas_left,
            step.gas_cost,
        );

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.rw_counter_end_of_reversion.assign(
            region,
            offset,
            Value::known(F::from(call.rw_counter_end_of_reversion as u64)),
        )?;
        self.base.assign(region, offset, Some(base.to_le_bytes()))?;
        self.exponent
            .assign(region, offset, Some(exponent.to_le_bytes()))?;
        self.exponent_byte_size.assign(region, offset, exponent)?;
        self.insufficient_gas_cost.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(step.gas_cost)),
        )?;
        self.restore_context
            .assign(region, offset, block, call, step, 4)
    }
}

#[cfg(test)]
mod tests {
    use crate::evm_circuit::test::{rand_bytes, rand_word};
    use crate::test_util::CircuitTestBuilder;
    use eth_types::evm_types::{GasCost, OpcodeId};
    use eth_types::{bytecode, Bytecode, ToWord, U256};
    use mock::test_ctx::helpers::account_0_code_account_1_no_code;
    use mock::{eth, TestContext, MOCK_ACCOUNTS};

    #[test]
    fn test_oog_exp() {
        [
            U256::zero(),
            U256::one(),
            1023.into(),
            U256::MAX,
            rand_word(),
        ]
        .into_iter()
        .for_each(|exponent| {
            let testing_data = TestingData::new(exponent);

            test_root(&testing_data);
            test_internal(&testing_data);
        })
    }

    struct TestingData {
        bytecode: Bytecode,
        gas_cost: u64,
    }

    impl TestingData {
        pub fn new(exponent: U256) -> Self {
            let bytecode = bytecode! {
                PUSH32(exponent)
                PUSH32(rand_word())
                EXP
            };

            let gas_cost = OpcodeId::PUSH32.constant_gas_cost().0 * 2
                + OpcodeId::EXP.constant_gas_cost().0
                + ((exponent.bits() as u64 + 7) / 8) * GasCost::EXP_BYTE_TIMES.0;

            Self { bytecode, gas_cost }
        }
    }

    fn test_root(testing_data: &TestingData) {
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(testing_data.bytecode.clone()),
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

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_internal(testing_data: &TestingData) {
        let (addr_a, addr_b) = (MOCK_ACCOUNTS[0], MOCK_ACCOUNTS[1]);

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
            PUSH32(0x00) // argsLength
            PUSH32(0x20) // argsOffset
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
                accs[2].address(MOCK_ACCOUNTS[2]).balance(eth(10));
            },
            |mut txs, accs| {
                txs[0].from(accs[2].address).to(accs[1].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
