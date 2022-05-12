use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::CallContextFieldTag,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition,
                Transition::{Delta, Same},
            },
            math_gadget::IsZeroGadget,
            Cell,
        },
        witness::{Block, Call, CodeSource, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct StopGadget<F> {
    code_size: Cell<F>,
    is_out_of_range: IsZeroGadget<F>,
    opcode: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for StopGadget<F> {
    const NAME: &'static str = "STOP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::STOP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let code_size = cb.bytecode_length(cb.curr.state.code_source.expr());
        let is_out_of_range =
            IsZeroGadget::construct(cb, code_size.expr() - cb.curr.state.program_counter.expr());
        let opcode = cb.query_cell();
        cb.condition(1.expr() - is_out_of_range.expr(), |cb| {
            cb.opcode_lookup(opcode.expr(), 1.expr());
        });

        // We do the responsible opcode check explicitly here because we're not using
        // the `SameContextGadget` for `STOP`.
        cb.require_equal(
            "Opcode should be STOP",
            opcode.expr(),
            OpcodeId::STOP.expr(),
        );

        // Call ends with STOP must be successful
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 1.expr());

        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr() + is_to_end_tx.clone(),
            2.expr() * cb.curr.state.is_root.expr() * is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // When a transaction ends with STOP, this call must be persistent
            cb.call_context_lookup(
                false.expr(),
                None,
                CallContextFieldTag::IsPersistent,
                1.expr(),
            );

            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(2.expr()),
                ..StepStateTransition::any()
            });
        });

        // When it's an internal call
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(cb, Delta(13.expr()), 0.expr(), 0.expr())
        });

        Self {
            code_size,
            is_out_of_range,
            opcode,
            restore_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let code = block
            .bytecodes
            .iter()
            .find(|b| {
                let CodeSource::Account(code_source) = &call.code_source;
                b.hash == *code_source
            })
            .expect("could not find current environment's bytecode");
        self.code_size
            .assign(region, offset, Some(F::from(code.bytes.len() as u64)))?;

        self.is_out_of_range.assign(
            region,
            offset,
            F::from(code.bytes.len() as u64) - F::from(step.program_counter),
        )?;

        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Some(F::from(opcode.as_u64())))?;

        self.restore_context
            .assign(region, offset, block, call, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        test::run_test_circuit_incomplete_fixed_table, witness::block_convert,
    };
    use eth_types::{address, bytecode, Bytecode, Word};
    use itertools::Itertools;
    use mock::TestContext;

    fn test_ok(bytecode: Bytecode, is_root: bool) {
        let block_data = if is_root {
            bus_mapping::mock::BlockData::new_from_geth_data(
                TestContext::<2, 1>::new(
                    None,
                    |accs| {
                        accs[0]
                            .address(address!("0x0000000000000000000000000000000000000000"))
                            .balance(Word::from(1u64 << 30));
                        accs[1]
                            .address(address!("0x0000000000000000000000000000000000000010"))
                            .balance(Word::from(1u64 << 20))
                            .code(bytecode);
                    },
                    |mut txs, accs| {
                        txs[0]
                            .from(accs[0].address)
                            .to(accs[1].address)
                            .gas(Word::from(30000));
                    },
                    |block, _tx| block.number(0xcafeu64),
                )
                .unwrap()
                .into(),
            )
        } else {
            bus_mapping::mock::BlockData::new_from_geth_data(
                TestContext::<3, 1>::new(
                    None,
                    |accs| {
                        accs[0]
                            .address(address!("0x0000000000000000000000000000000000000000"))
                            .balance(Word::from(1u64 << 30));
                        accs[1]
                            .address(address!("0x0000000000000000000000000000000000000010"))
                            .balance(Word::from(1u64 << 20))
                            .code(bytecode! {
                                PUSH1(0)
                                PUSH1(0)
                                PUSH1(0)
                                PUSH1(0)
                                PUSH1(0)
                                PUSH1(0x20)
                                GAS
                                CALL
                                STOP
                            });
                        accs[2]
                            .address(address!("0x0000000000000000000000000000000000000020"))
                            .balance(Word::from(1u64 << 20))
                            .code(bytecode);
                    },
                    |mut txs, accs| {
                        txs[0]
                            .from(accs[0].address)
                            .to(accs[1].address)
                            .gas(Word::from(30000));
                    },
                    |block, _tx| block.number(0xcafeu64),
                )
                .unwrap()
                .into(),
            )
        };
        let mut builder = block_data.new_circuit_input_builder();
        builder
            .handle_block(&block_data.eth_block, &block_data.geth_traces)
            .unwrap();
        let block = block_convert(&builder.block, &builder.code_db);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn stop_gadget_simple() {
        let bytecodes = vec![
            bytecode! {
                PUSH1(0)
                STOP
            },
            bytecode! {
                PUSH1(0)
            },
        ];
        let is_roots = vec![true, false];
        for (bytecode, is_root) in bytecodes.into_iter().cartesian_product(is_roots) {
            test_ok(bytecode, is_root);
        }
    }
}
