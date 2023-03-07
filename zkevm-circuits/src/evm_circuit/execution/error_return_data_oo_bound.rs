use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_U64,
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::ConstraintBuilder,
            from_bytes,
            math_gadget::{AddWordsGadget, IsZeroGadget, LtGadget},
            not, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToScalar, U256};

use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorReturnDataOutOfBoundGadget<F> {
    opcode: Cell<F>,
    memory_offset: Cell<F>,
    sum: AddWordsGadget<F, 2, true>,
    /// Holds the size of the last callee return data.
    return_data_length: Cell<F>,

    is_data_offset_within_range: IsZeroGadget<F>,
    // end = data_offset + length
    is_end_within_range: IsZeroGadget<F>,
    // when `end` not overflow, check if it exceeds return data size.
    is_end_exceed_length: LtGadget<F, N_BYTES_U64>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorReturnDataOutOfBoundGadget<F> {
    const NAME: &'static str = "ErrorReturnDataOutOfBoundGadget";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorReturnDataOutOfBound;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let memory_offset = cb.query_cell();
        let data_offset = cb.query_word_rlc();
        let length = cb.query_word_rlc();
        let end = cb.query_word_rlc();

        let return_data_length = cb.query_cell();

        cb.require_equal(
            "opcode is RETURNDATACOPY",
            opcode.expr(),
            OpcodeId::RETURNDATACOPY.expr(),
        );

        // Pop memory_offset, offset, length from stack
        cb.stack_pop(memory_offset.expr());
        cb.stack_pop(data_offset.expr());
        cb.stack_pop(length.expr());

        // read last callee return data length
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::LastCalleeReturnDataLength,
            return_data_length.expr(),
        );

        // check `data_offset` u64 overflow
        let data_offset_larger_u64 = from_bytes::expr(&data_offset.cells[8..]);
        let is_data_offset_within_range = IsZeroGadget::construct(cb, data_offset_larger_u64);

        // check if `end` u64  overflow or not.
        let sum = AddWordsGadget::construct(cb, [data_offset, length], end.clone());

        let end_larger_u64 = from_bytes::expr(&end.cells[8..]);
        let is_end_within_range = IsZeroGadget::construct(cb, end_larger_u64);

        // check if `end` exceeds return data length
        let is_end_exceed_length = LtGadget::construct(
            cb,
            return_data_length.expr(),
            from_bytes::expr(&end.cells[..N_BYTES_U64]),
        );
        // Any of [offset_out_of_range, end_out_of_range, end_exceed_length] occurs.
        cb.require_in_set(
            "Any of [offset_out_of_range, end_out_of_range, end_exceed_length] occurs",
            not::expr(is_data_offset_within_range.expr())
                + not::expr(is_end_within_range.expr())
                + is_end_exceed_length.expr(),
            vec![1.expr(), 2.expr(), 3.expr()],
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 6.expr());

        Self {
            opcode,
            memory_offset,
            is_data_offset_within_range,
            is_end_within_range,
            is_end_exceed_length,
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

        let end = data_offset + size;

        self.sum.assign(region, offset, [data_offset, size], end)?;
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

        // when u64::MAX < data_offset = true, not within u64 range.
        let data_offset_overflow = U256::from(u64::MAX) < data_offset;
        self.is_data_offset_within_range.assign(
            region,
            offset,
            F::from(data_offset_overflow as u64),
        )?;
        // check `end` if u64 overflow.
        let end_overflow = U256::from(u64::MAX) < end;

        self.is_end_within_range
            .assign(region, offset, F::from(end_overflow as u64))?;

        // check if it exceeds last callee return data length
        let end_u64 = end.low_u64();
        let return_length = return_data_length.to_scalar().unwrap();
        self.is_end_exceed_length
            .assign(region, offset, return_length, F::from(end_u64))?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 6)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, ToWord, Word};
    use mock::test_ctx::TestContext;

    fn test_ok(
        return_data_offset: usize,
        return_data_size: usize,
        dest_offset: usize,
        offset: u128,
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
                PUSH32(return_data_size)
                PUSH32(return_data_offset)
                RETURN
                STOP
            });
        } else {
            code_b.append(&bytecode! {
                PUSH32(size) // size
                PUSH32(offset) // data offset
                PUSH32(dest_offset) // memory offset
                RETURNDATACOPY
                // end for internal
                PUSH32(return_data_size)
                PUSH32(return_data_offset)
                RETURN
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
                PUSH32(return_data_size)
                PUSH32(return_data_offset)
                RETURN
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

    // test root & internal calls
    #[test]
    fn returndatacopy_out_of_bound_error() {
        // test root call cases: `end` exceed return data size
        test_ok(0x00, 0x10, 0x20, 0x10, 0x10, true);
        // test root call case: `end` exceed return data size
        test_ok(0x00, 0x10, 0x20, 0x10, 0x10, true);
        // test data offset u64 overflow
        test_ok(0x00, 0x10, 0x20, u128::from(u64::MAX) + 1, 0x10, false);
        // test end = data offset + length(size) overflow
        test_ok(0x00, 0x10, 0x20, 0x1, 0x10, false);
        // test end overflow with end > 0xff
        test_ok(0x00, 0x10, 0x20, 0x1, 0xff, false);
    }
}
