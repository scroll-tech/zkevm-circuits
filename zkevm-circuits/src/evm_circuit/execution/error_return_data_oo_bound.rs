use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_U64,
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes,
            math_gadget::{AddWordsGadget, IsZeroGadget, LtGadget},
            not, or, sum, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorReturnDataOutOfBoundGadget<F> {
    opcode: Cell<F>,
    memory_offset: Cell<F>,
    sum: AddWordsGadget<F, 2, false>,
    // Hold the size of the last callee return data.
    return_data_length: Cell<F>,
    is_data_offset_within_u64: IsZeroGadget<F>,
    // remainder_end = (data_offset + size) mod U256
    is_remainder_end_within_u64: IsZeroGadget<F>,
    // when remainder end is within Uint64, check if it exceeds return data size.
    is_remainder_end_exceed_len: LtGadget<F, N_BYTES_U64>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorReturnDataOutOfBoundGadget<F> {
    const NAME: &'static str = "ErrorReturnDataOutOfBoundGadget";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorReturnDataOutOfBound;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let memory_offset = cb.query_cell();
        let data_offset = cb.query_word_rlc();
        let size = cb.query_word_rlc();
        let remainder_end = cb.query_word_rlc();
        let return_data_length = cb.query_cell();

        cb.require_equal(
            "opcode is RETURNDATACOPY",
            opcode.expr(),
            OpcodeId::RETURNDATACOPY.expr(),
        );

        // Pop memory_offset, offset, size from stack
        cb.stack_pop(memory_offset.expr());
        cb.stack_pop(data_offset.expr());
        cb.stack_pop(size.expr());

        // Read last callee return data length
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::LastCalleeReturnDataLength,
            return_data_length.expr(),
        );

        // Check if `data_offset` is Uint64 overflow.
        let data_offset_larger_u64 = sum::expr(&data_offset.cells[N_BYTES_U64..]);
        let is_data_offset_within_u64 = IsZeroGadget::construct(cb, "", data_offset_larger_u64);

        // Check if `remainder_end` is Uint64 overflow.
        let sum = AddWordsGadget::construct(cb, [data_offset, size], remainder_end.clone());
        let is_end_u256_overflow = sum.carry().as_ref().unwrap();

        let remainder_end_larger_u64 = sum::expr(&remainder_end.cells[N_BYTES_U64..]);
        let is_remainder_end_within_u64 = IsZeroGadget::construct(cb, "", remainder_end_larger_u64);

        // check if `remainder_end` exceeds return data length.
        let is_remainder_end_exceed_len = LtGadget::construct(
            cb,
            return_data_length.expr(),
            from_bytes::expr(&remainder_end.cells[..N_BYTES_U64]),
        );

        // Need to check if `data_offset + size` is U256 overflow via `AddWordsGadget` carry. If
        // yes, it should be also an error of return data out of bound.
        cb.require_equal(
            "Any of [data_offset > u64::MAX, data_offset + size > U256::MAX, remainder_end > u64::MAX, remainder_end > return_data_length] occurs",
            or::expr([
                // data_offset > u64::MAX
                not::expr(is_data_offset_within_u64.expr()),
                // data_offset + size > U256::MAX
                is_end_u256_overflow.expr(),
                // remainder_end > u64::MAX
                not::expr(is_remainder_end_within_u64.expr()),
                // remainder_end > return_data_length
                is_remainder_end_exceed_len.expr(),
            ]),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 6.expr());

        Self {
            opcode,
            memory_offset,
            is_data_offset_within_u64,
            is_remainder_end_within_u64,
            is_remainder_end_exceed_len,
            sum,
            return_data_length,
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
        let opcode = step.opcode.unwrap();

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let [dest_offset, data_offset, size] =
            [0, 1, 2].map(|i| block.rws[step.rw_indices[i as usize]].stack_value());

        self.memory_offset
            .assign(region, offset, Value::known(F::from(dest_offset.as_u64())))?;

        let remainder_end = data_offset.overflowing_add(size).0;
        self.sum
            .assign(region, offset, [data_offset, size], remainder_end)?;

        let return_data_length = block.rws[step.rw_indices[3]].call_context_value();
        self.return_data_length.assign(
            region,
            offset,
            Value::known(
                return_data_length
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let data_offset_overflow = data_offset.to_le_bytes()[N_BYTES_U64..]
            .iter()
            .fold(0, |acc, val| acc + u64::from(*val));
        self.is_data_offset_within_u64
            .assign(region, offset, F::from(data_offset_overflow))?;

        let remainder_end_overflow = remainder_end.to_le_bytes()[N_BYTES_U64..]
            .iter()
            .fold(0, |acc, val| acc + u64::from(*val));
        self.is_remainder_end_within_u64
            .assign(region, offset, F::from(remainder_end_overflow))?;

        // check if it exceeds last callee return data length
        let remainder_end_u64 = remainder_end.low_u64();
        let return_length = return_data_length.to_scalar().unwrap();
        self.is_remainder_end_exceed_len.assign(
            region,
            offset,
            return_length,
            F::from(remainder_end_u64),
        )?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 6)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, ToWord, Word};
    use mock::test_ctx::TestContext;

    fn test_ok(
        return_data_offset: usize,
        return_data_size: usize,
        dest_offset: usize,
        offset: Word,
        size: usize,
        is_root: bool,
    ) {
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        let pushdata = rand_bytes(32);
        let return_offset =
            std::cmp::max((return_data_offset + return_data_size) as i64 - 32, 0) as usize;
        let mut code_b = bytecode! {
            PUSH32(Word::from_big_endian(&pushdata))
            PUSH32(return_offset)
            MSTORE
        };

        if is_root {
            code_b.append(&bytecode! {
                .op_return(return_data_offset, return_data_size)
                STOP
            });
        } else {
            code_b.append(&bytecode! {
                PUSH32(size) // size
                PUSH32(offset) // data offset
                PUSH32(dest_offset) // memory offset
                RETURNDATACOPY
                // end for internal
                .op_return(return_data_offset, return_data_size)
                STOP
            });
        }

        // code A calls code B.
        let mut code_a = bytecode! {
            // call ADDR_B.
            PUSH32(return_data_size) // retLength
            PUSH32(return_data_offset) // retOffset
            PUSH1(0x00) // argsLength
            PUSH1(0x00) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
        };

        if is_root {
            code_a.append(&bytecode! {
                PUSH32(size) // size
                PUSH32(offset) // offset
                PUSH32(dest_offset) // dest_offset
                RETURNDATACOPY
                STOP
            });
        } else {
            code_a.append(&bytecode! {
                .op_return(return_data_offset, return_data_size)
            });
        }

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_a).code(code_a);
                accs[1].address(addr_b).code(code_b);
                accs[2]
                    .address(mock::MOCK_ACCOUNTS[2])
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    // data_offset > u64::MAX
    #[test]
    fn test_return_data_oo_bound_data_offset_overflow() {
        test_ok(0, 0x10, 0x20, Word::from(u64::MAX) + 1, 0x10, false);
        test_ok(0, 0x10, 0x20, Word::MAX, 0, true);
    }

    // data_offset + size > U256::MAX
    #[test]
    fn test_return_data_oo_bound_data_offset_plus_size_word_overflow() {
        test_ok(0, 0x10, 0x20, Word::MAX, 1, false);
        test_ok(0, 0x10, 0x20, Word::MAX - 1000, 1001, true);
    }

    // data_offset + size > u64::MAX
    #[test]
    fn test_return_data_oo_bound_data_offset_plus_size_u64_overflow() {
        test_ok(0, 0x10, 0x20, Word::from(u64::MAX), 1, false);
        test_ok(0, 0x10, 0x20, Word::from(u64::MAX) - 100, 101, true);
    }

    // data_offset + size > return_data_length
    #[test]
    fn test_return_data_oo_bound_exceed_return_data_length() {
        test_ok(0, 0x10, 0x20, 0x10.into(), 0x10, false);
        test_ok(0, 0x10, 0x20, 1.into(), 0xff, true);
    }
}
