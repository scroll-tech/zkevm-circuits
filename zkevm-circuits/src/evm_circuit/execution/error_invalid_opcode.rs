use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::RestoreContextGadget;
use crate::evm_circuit::util::constraint_builder::Transition::{Delta, Same};
use crate::evm_circuit::util::constraint_builder::{ConstraintBuilder, StepStateTransition};
use crate::evm_circuit::util::math_gadget::LtGadget;
use crate::evm_circuit::util::{CachedRegion, Cell};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::table::CallContextFieldTag;
use eth_types::Field;
use gadgets::util::{and, or, Expr};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

const SEPARATE_INVALID_OPCODES: [u8; 17] = [
    0x0c, 0x0d, 0x0e, 0x0f, 0x1e, 0x1f, 0x5c, 0x5d, 0x5e, 0x5f, 0xf6, 0xf7, 0xf8, 0xf9, 0xfb, 0xfc,
    0xfe,
];

/// Gadget for invalid opcodes. It verifies invalid bytes in any condition of:
/// - `opcode > 0x20 && opcode < 0x30`
/// - `opcode > 0x48 && opcode < 0x50`
/// - `opcode > 0xa4 && opcode < 0xf0`
/// - one of [`SEPARATE_INVALID_OPCODES`]
#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidOpcodeGadget<F> {
    opcode: Cell<F>,
    op_gt_20: LtGadget<F, 1>,
    op_lt_30: LtGadget<F, 1>,
    op_gt_48: LtGadget<F, 1>,
    op_lt_50: LtGadget<F, 1>,
    op_gt_a4: LtGadget<F, 1>,
    op_lt_f0: LtGadget<F, 1>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidOpcodeGadget<F> {
    const NAME: &'static str = "ErrorInvalidOpcode";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidOpcode;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        let op_gt_20 = LtGadget::construct(cb, 0x20.expr(), opcode.expr());
        let op_lt_30 = LtGadget::construct(cb, opcode.expr(), 0x30.expr());
        let op_gt_48 = LtGadget::construct(cb, 0x48.expr(), opcode.expr());
        let op_lt_50 = LtGadget::construct(cb, opcode.expr(), 0x50.expr());
        let op_gt_a4 = LtGadget::construct(cb, 0xa4.expr(), opcode.expr());
        let op_lt_f0 = LtGadget::construct(cb, opcode.expr(), 0xf0.expr());

        let op_range_20_30 = and::expr([op_gt_20.expr(), op_lt_30.expr()]);
        let op_range_48_50 = and::expr([op_gt_48.expr(), op_lt_50.expr()]);
        let op_range_a4_f0 = and::expr([op_gt_a4.expr(), op_lt_f0.expr()]);

        // Check separate byte set if no above condition is met.
        cb.condition(
            1.expr() - or::expr([op_range_20_30, op_range_48_50, op_range_a4_f0]),
            |cb| {
                cb.require_in_set(
                    "Constrain separate invalid opcodes",
                    opcode.expr(),
                    SEPARATE_INVALID_OPCODES
                        .iter()
                        .map(|op| op.expr())
                        .collect(),
                );
            },
        );

        // Current call must be failed.
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 0.expr());

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
                rw_counter: Delta(1.expr() + cb.curr.state.reversible_write_counter.expr()),
                ..StepStateTransition::any()
            });
        });

        // When it is an internal call, need to restore caller's state as finishing this
        // call. Restore caller state to next StepState.
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                0.expr(),
                // rw_offset is handled in construct internally
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        Self {
            opcode,
            op_gt_20,
            op_lt_30,
            op_gt_48,
            op_lt_50,
            op_gt_a4,
            op_lt_f0,
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
        let opcode = F::from(step.opcode.unwrap().as_u64());

        self.opcode.assign(region, offset, Value::known(opcode))?;

        self.op_gt_20
            .assign(region, offset, F::from(0x20), opcode)?;
        self.op_lt_30
            .assign(region, offset, opcode, F::from(0x30))?;
        self.op_gt_48
            .assign(region, offset, F::from(0x48), opcode)?;
        self.op_lt_50
            .assign(region, offset, opcode, F::from(0x50))?;
        self.op_gt_a4
            .assign(region, offset, F::from(0xa4), opcode)?;
        self.op_lt_f0
            .assign(region, offset, opcode, F::from(0xf0))?;

        self.restore_context
            .assign(region, offset, block, call, step, 1)
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::run_test_circuits;
    use eth_types::bytecode::Bytecode;
    use eth_types::{bytecode, ToWord, Word};
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use mock::TestContext;

    const TESTING_CALL_DATA_PAIRS: [(usize, usize); 2] = [(0x20, 0x00), (0x1010, 0xff)];

    lazy_static! {
        static ref TESTING_INVALID_CODES: [Vec<u8>; 14] = [
            // Single invalid opcode
            vec![0x0e],
            vec![0x1f],
            vec![0x21],
            vec![0x4f],
            vec![0xa5],
            vec![0xb0],
            vec![0xc0],
            vec![0xd0],
            vec![0xe0],
            vec![0xf6],
            vec![0xfb],
            vec![0xfe],
            // Multiple invalid opcodes
            vec![0x5c, 0x5d, 0x5e, 0x5f],
            // Many duplicate invalid opcodes
            vec![0x22; 256],
        ];
    }

    #[test]
    fn invalid_opcode_root() {
        for invalid_code in TESTING_INVALID_CODES.iter() {
            test_root_ok(invalid_code);
        }
    }

    #[test]
    fn invalid_opcode_internal() {
        for ((call_data_offset, call_data_length), invalid_opcode) in TESTING_CALL_DATA_PAIRS
            .iter()
            .cartesian_product(TESTING_INVALID_CODES.iter())
        {
            test_internal_ok(*call_data_offset, *call_data_length, invalid_opcode);
        }
    }

    fn test_root_ok(invalid_code: &[u8]) {
        let mut code = Bytecode::default();
        invalid_code.iter().for_each(|b| {
            code.write(*b, true);
        });

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
                None
            ),
            Ok(())
        );
    }

    fn test_internal_ok(call_data_offset: usize, call_data_length: usize, invalid_code: &[u8]) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // Code B gets called by code A, so the call is an internal call.
        let mut code_b = Bytecode::default();
        invalid_code.iter().for_each(|b| {
            code_b.write(*b, true);
        });

        // code A calls code B.
        let pushdata = rand_bytes(8);
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[3])
                    .balance(Word::from(1_u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        assert_eq!(run_test_circuits(ctx, None), Ok(()));
    }
}
