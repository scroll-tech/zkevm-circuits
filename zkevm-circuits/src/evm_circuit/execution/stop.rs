use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::{BytecodeLengthGadget, RestoreContextGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::{Delta, Same, To},
            },
            math_gadget::LtGadget,
            not, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::{Expr, Field},
};
use bus_mapping::evm::OpcodeId;
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct StopGadget<F> {
    is_within_range: LtGadget<F, N_BYTES_PROGRAM_COUNTER>,
    opcode: Cell<F>,
    #[cfg(feature = "dual_bytecode")]
    is_first_bytecode_table: Cell<F>,
    restore_context: RestoreContextGadget<F>,
    /// Wraps the bytecode length and lookup.
    code_len_gadget: BytecodeLengthGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for StopGadget<F> {
    const NAME: &'static str = "STOP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::STOP;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        #[cfg(feature = "dual_bytecode")]
        let is_first_bytecode_table = cb.query_bool();

        let code_len_gadget = BytecodeLengthGadget::construct(
            cb,
            cb.curr.state.code_hash.clone(),
            #[cfg(feature = "dual_bytecode")]
            is_first_bytecode_table.expr(),
        );

        let is_within_range = LtGadget::construct(
            cb,
            cb.curr.state.program_counter.expr(),
            code_len_gadget.code_length.expr(),
        );

        cb.condition(is_within_range.expr(), |cb| {
            // TODO: refactor op_code lookup into helper later.
            #[cfg(not(feature = "dual_bytecode"))]
            cb.opcode_lookup(opcode.expr(), 1.expr());

            #[cfg(feature = "dual_bytecode")]
            {
                cb.condition(is_first_bytecode_table.expr(), |cb| {
                    cb.opcode_lookup(opcode.expr(), 1.expr());
                });
                cb.condition(not::expr(is_first_bytecode_table.expr()), |cb| {
                    cb.opcode_lookup2(opcode.expr(), 1.expr());
                });
            }
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
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(1.expr()),
                end_tx: To(1.expr()),
                ..StepStateTransition::any()
            });
        });

        // When it's an internal call
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                true.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        Self {
            is_within_range,
            opcode,
            #[cfg(feature = "dual_bytecode")]
            is_first_bytecode_table,
            restore_context,
            code_len_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let code = block
            .bytecodes
            .get(&call.code_hash)
            .expect("could not find current environment's bytecode");

        self.code_len_gadget
            .assign(region, offset, block, call, code.bytes.len() as u64)?;

        self.is_within_range.assign(
            region,
            offset,
            F::from(step.program_counter),
            F::from(code.bytes.len() as u64),
        )?;

        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        #[cfg(feature = "dual_bytecode")]
        {
            let is_first_bytecode_table = block.is_first_bytecode(&call.code_hash);
            self.is_first_bytecode_table.assign(
                region,
                offset,
                Value::known(F::from(is_first_bytecode_table)),
            )?;
        }

        if !call.is_root {
            self.restore_context
                .assign(region, offset, block, call, step, 1)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{address, bytecode, Bytecode, Word};

    use itertools::Itertools;
    use mock::TestContext;

    fn test_ok(bytecode: Bytecode, is_root: bool) {
        if is_root {
            let ctx = TestContext::<2, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(address!("0x0000000000000000000000000000000000000123"))
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
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        } else {
            let ctx = TestContext::<3, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(address!("0x0000000000000000000000000000000000000123"))
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
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        };
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
