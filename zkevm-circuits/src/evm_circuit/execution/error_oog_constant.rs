use crate::evm_circuit::{
    execution::ExecutionGadget,
    //param::{N_BYTES_GAS, N_BYTES_MEMORY_WORD_SIZE},
    step::ExecutionState,
    //table::CallContextFieldTag,
    util::{
        //common_gadget::RestoreContextGadget,
        constraint_builder::ConstraintBuilder,
        //math_gadget::{IsEqualGadget, IsZeroGadget, RangeCheckGadget},
        //memory_gadget::{address_high, address_low, MemoryExpansionGadget},
        CachedRegion,
        Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::Field;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGConstantGadget<F> {
    opcode: Cell<F>,
    /* constrain gas left is less than required
     * gas_required: Cell<F>,
     * insufficient_gas: RangeCheckGadget<F, N_BYTES_GAS>,
     *restore_context: RestoreContextGadget<F>, */
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGConstantGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasConstant";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasConstant;

    // Support other OOG due to pure memory including CREATE, RETURN and REVERT
    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        // let gas_required = cb.query_cell();

        // // Check if the amount of gas available is less than the amount of gas
        // // required
        // let insufficient_gas =  RangeCheckGadget::construct(
        //         cb,
        //         gas_required.expr() - cb.curr.state.gas_left.expr(),
        //     );

        // let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        // cb.require_equal(
        //     "Go to EndTx only when is_root",
        //     cb.curr.state.is_root.expr(),
        //     is_to_end_tx,
        // );

        // // When it's a root call
        // cb.condition(cb.curr.state.is_root.expr(), |cb| {
        //     // When a transaction ends with this error case, this call must be not
        // persistent     cb.call_context_lookup(
        //         false.expr(),
        //         None,
        //         CallContextFieldTag::IsPersistent,
        //         0.expr(),
        //     );

        //     // Do step state transition
        //     cb.require_step_state_transition(StepStateTransition {
        //         call_id: Same,
        //         rw_counter: Delta(1.expr()),
        //         ..StepStateTransition::any()
        //     });
        // });

        // When it's an internal call
        // let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(),
        // |cb| {     RestoreContextGadget::construct(cb, 1.expr(), 0.expr(),
        // 0.expr()) });

        // TODO: Use ContextSwitchGadget to switch call context to caller's and
        // consume all gas_left.

        Self {
            opcode,
            /* gas_required,
             * insufficient_gas,
             * restore_context, */
        }
    }

    fn assign_exec_step(
        &self,
        _region: &mut CachedRegion<'_, '_, F>,
        _offset: usize,
        _block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        _step: &ExecStep,
    ) -> Result<(), Error> {
        // let opcode = step.opcode.unwrap();

        // Inputs/Outputs
        // self.gas_required.assign(region, offset, Some(F::from(step.gas_cost)))?;
        // // Gas insufficient check
        // // Get `gas_available` variable here once it's available
        // self.insufficient_gas
        //     .assign(region, offset, F::from(step.gas_cost - step.gas_left))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::run_test_circuit_incomplete_fixed_table, witness::block_convert,
    };
    use crate::test_util::run_test_circuits;
    use bus_mapping::{evm::OpcodeId, mock::BlockData};
    use eth_types::{self, bytecode, evm_types::GasCost, geth_types::GethData, Word};
    use mock::{
        eth, gwei, test_ctx::helpers::account_0_code_account_1_no_code, TestContext, MOCK_ACCOUNTS,
    };

    fn gas(call_data: &[u8]) -> Word {
        Word::from(
            GasCost::TX.as_u64()
                + 2 * OpcodeId::PUSH32.constant_gas_cost().as_u64()
                + call_data
                    .iter()
                    .map(|&x| if x == 0 { 4 } else { 16 })
                    .sum::<u64>(),
        )
    }

    fn test_oog_constant(tx: eth_types::Transaction, is_success: bool) {
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
                //REVERT
            }
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, _accs| {
                txs[0]
                    .to(tx.to.unwrap())
                    .from(tx.from)
                    .gas_price(tx.gas_price.unwrap())
                    .gas(tx.gas - 1)
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

    fn mock_tx(value: Word, gas_price: Word, calldata: Vec<u8>) -> eth_types::Transaction {
        let from = MOCK_ACCOUNTS[1];
        let to = MOCK_ACCOUNTS[0];
        eth_types::Transaction {
            from,
            to: Some(to),
            value,
            gas: gas(&calldata),
            gas_price: Some(gas_price),
            input: calldata.into(),
            ..Default::default()
        }
    }

    #[test]
    fn oog_constant_gadget_simple() {
        // Transfer 1 ether, successfully
        // in root call
        test_oog_constant(mock_tx(eth(1), gwei(2), vec![]), false);
        // TODO: add internal call test
    }

    /*
        #[test]
        fn stack_overflow_simple() {
            test_stack_overflow(OpcodeId::PUSH1, &[1]);
        }
        fn test_stack_overflow(opcode: OpcodeId, bytes: &[u8]) {
            assert!(bytes.len() as u8 == opcode.as_u8() - OpcodeId::PUSH1.as_u8() + 1,);

            let mut bytecode = bytecode! {
                .write_op(opcode)
            };
            for b in bytes {
                bytecode.write(*b);
            }
            // still add 1024 causes stack overflow
            for _ in 0..1025 {
                bytecode.write_op(opcode);
                for b in bytes {
                    bytecode.write(*b);
                }
            }
            // append final stop op code
            bytecode.write_op(OpcodeId::STOP);

            assert_eq!(
                run_test_circuits(
                    TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                    None
                ),
                Ok(())
            );
        }
    */
    fn test_stack_underflow(value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            POP
            POP
            STOP
        };

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None
            ),
            Ok(())
        );
    }

    #[test]
    fn pop_gadget_underflow() {
        test_stack_underflow(Word::from(0x030201));
    }
}
