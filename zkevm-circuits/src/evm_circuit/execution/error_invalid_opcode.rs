use crate::evm_circuit::{
    execution::ExecutionGadget,
    step::ExecutionState,
    table::{FixedTableTag, Lookup},
    util::{
        common_gadget::CommonErrorGadget, constraint_builder::EVMConstraintBuilder, CachedRegion,
        Cell,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget for invalid opcodes. It verifies by a fixed lookup for
/// ResponsibleOpcode.
#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidOpcodeGadget<F> {
    opcode: Cell<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidOpcodeGadget<F> {
    const NAME: &'static str = "ErrorInvalidOpcode";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidOpcode;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.add_lookup(
            "Responsible opcode lookup",
            Lookup::Fixed {
                tag: FixedTableTag::ResponsibleOpcode.expr(),
                values: [
                    Self::EXECUTION_STATE.as_u64().expr(),
                    opcode.expr(),
                    0.expr(),
                ],
            },
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 2.expr());

        Self {
            opcode,
            common_error_gadget,
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
        let opcode = step.opcode.unwrap().as_u64();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode)))?;

        log::debug!("ErrorInvalidOpcode - opcode = {}", opcode);

        self.common_error_gadget
            .assign(region, offset, block, call, step, 2)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{address, bytecode::Bytecode, Word};
    use lazy_static::lazy_static;
    use mock::{generate_mock_call_bytecode, MockCallBytecodeParams, TestContext};

    lazy_static! {
        static ref TESTING_INVALID_CODES: [Vec<u8>; 6] = [
            // Single invalid opcode
            vec![0x0e],
            vec![0x4f],
            vec![0xa5],
            vec![0xf6],
            vec![0xfe],
            // Multiple invalid opcodes
            vec![0x5c, 0x5e],
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
        for invalid_code in TESTING_INVALID_CODES.iter() {
            test_internal_ok(0x20, 0x00, invalid_code);
        }
    }

    #[cfg(feature = "scroll")]
    #[test]
    fn invalid_opcode_selfdestruct_for_scroll() {
        let selfdestruct_opcode = 0xff_u8;
        test_root_ok(&[selfdestruct_opcode]);
        test_internal_ok(0x20, 0x00, &[selfdestruct_opcode]);
    }

    // for scroll feature, treat BASEFEE as invalidcode. disabled in scroll l2geth
    #[cfg(feature = "scroll")]
    #[test]
    fn invalid_opcode_basefee_for_scroll() {
        let basefee_opcode = 0x48_u8;
        test_root_ok(&[basefee_opcode]);
        test_internal_ok(0x20, 0x00, &[basefee_opcode]);
    }

    #[cfg(not(feature = "shanghai"))]
    #[test]
    fn invalid_opcode_push0_for_not_shanghai() {
        // Should test with logs in `assign_exec_step`, otherwise it could also
        // pass (since PushGadget).
        let push0 = 0x5f;
        test_root_ok(&[push0]);
        test_internal_ok(0x20, 0x00, &[push0]);
    }

    // for scroll feature, treat selfdestruct_opcode as invalidcode. even this test construct oog
    // case for self_destruct, expected to meet invalid opcode error.
    #[cfg(feature = "scroll")]
    #[test]
    fn test_root_self_destruct() {
        let selfdestruct_opcode = 0xff_u8;
        let mut code = Bytecode::default();
        code.push(20, address!("0x000000000000000000000000000000000000cafe"));
        code.write(selfdestruct_opcode, true);

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(1_u64 << 20))
                    .code(code);

                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1_u64 << 20));

                accs[2]
                    .address(address!("0x0000000000000000000000000000000000000020"))
                    .balance(Word::from(1_u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[2].address)
                    .to(accs[0].address)
                    // gas just over tx baisc gas(21000) + push gas(3), so oog for
                    // selfdestruct_opcode in normal geth, but treat as
                    // invalidcode with scroll feature
                    .gas(21003.into());
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_root_ok(invalid_code: &[u8]) {
        let mut code = Bytecode::default();
        invalid_code.iter().for_each(|b: &u8| {
            code.write(*b, true);
        });

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
        .run();
    }

    fn test_internal_ok(call_data_offset: usize, call_data_length: usize, invalid_code: &[u8]) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // Code B gets called by code A, so the call is an internal call.
        let mut code_b = Bytecode::default();
        invalid_code.iter().for_each(|b| {
            code_b.write(*b, true);
        });

        // code A calls code B.
        let code_a = generate_mock_call_bytecode(MockCallBytecodeParams {
            address: addr_b,
            pushdata: rand_bytes(32),
            call_data_length,
            call_data_offset,
            ..MockCallBytecodeParams::default()
        });

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

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
