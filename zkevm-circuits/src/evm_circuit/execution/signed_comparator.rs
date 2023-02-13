use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes,
            math_gadget::{ComparisonGadget, IsEqualGadget, LtGadget},
            select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget that implements the ExecutionGadget trait to handle the Opcodes SLT
/// and SGT.
#[derive(Clone, Debug)]
pub(crate) struct SignedComparatorGadget<F> {
    same_context: SameContextGadget<F>,

    a: Word<F>,
    b: Word<F>,

    sign_check_a: LtGadget<F, 1>,
    sign_check_b: LtGadget<F, 1>,
    lt_lo: LtGadget<F, 16>,
    comparison_hi: ComparisonGadget<F, 16>,
    a_lt_b: Cell<F>,

    is_sgt: IsEqualGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for SignedComparatorGadget<F> {
    const NAME: &'static str = "SCMP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SCMP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word_rlc();
        let b = cb.query_word_rlc();

        // The Signed Comparator gadget is used for both opcodes SLT and SGT.
        // Depending on whether the opcode is SLT or SGT, we
        // swap the order in which the inputs are placed on the stack.
        let is_sgt = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::SGT.expr());

        // Both a and b are to be treated as two's complement signed 256-bit
        // (32 cells) integers. This means, the first bit denotes the sign
        // of the absolute value in the rest of the 255 bits. This means the
        // number is negative if the most significant cell >= 128
        // (0b10000000). a and b being in the little-endian notation, the
        // most-significant byte is the last byte.
        let sign_check_a = LtGadget::construct(cb, a.cells[31].expr(), 128.expr());
        let sign_check_b = LtGadget::construct(cb, b.cells[31].expr(), 128.expr());

        // sign_check_a_lt expression implies a is positive since its MSB < 2**7
        // sign_check_b_lt expression implies b is positive since its MSB < 2**7
        let a_pos = sign_check_a.expr();
        let b_pos = sign_check_b.expr();

        // We require the comparison check only for the cases where:
        // (a < 0 && b < 0) || (a >= 0 && b >= 0).
        // We ignore the equality expression since we only care about the LT
        // check.
        // By `lo` we mean the low bytes, and `hi` stands for the more
        // significant bytes. While only considering the absolute
        // values, we have: a < b == 1 iff ((a_hi < b_hi) || ((a_hi ==
        // b_hi) && (a_lo < b_lo)))
        let lt_lo = LtGadget::construct(
            cb,
            from_bytes::expr(&a.cells[0..16]),
            from_bytes::expr(&b.cells[0..16]),
        );
        let comparison_hi = ComparisonGadget::construct(
            cb,
            from_bytes::expr(&a.cells[16..32]),
            from_bytes::expr(&b.cells[16..32]),
        );
        let a_lt_b_lo = lt_lo.expr();
        let (a_lt_b_hi, a_eq_b_hi) = comparison_hi.expr();

        // Add selector only for the cases where both a and b are positive or
        // negative. This selector will be used after handling the cases
        // where either only a or only b are negative.
        //
        // if (a > 0 && b > 0) || (a < 0 && b < 0):
        //      a < b -> (a_hi < b_hi) ? 1 : (a_hi == b_hi) * (a_lo < b_lo)
        //
        // for e.g.: consider 8-bit signed integers -1 (0xff) and -2 (0xfe):
        //     -2 < -1 and 0xfe < 0xff
        //
        // Use copy to avoid degree too high for stack_push below.
        let a_lt_b = cb.copy(select::expr(a_lt_b_hi, 1.expr(), a_eq_b_hi * a_lt_b_lo));

        // Add a trivial selector: if only a or only b is negative we have the
        // result.
        // result = if a < 0 && b >= 0, slt = 1.
        // result = if b < 0 && a >= 0, slt = 0.
        let a_neg_b_pos = (1.expr() - a_pos.expr()) * b_pos.expr();
        let b_neg_a_pos = (1.expr() - b_pos.expr()) * a_pos.expr();

        // Only one of the following 3 condition can be true
        //   a_neg_b_pos => result = 1
        //   b_neg_a_pos => result = 0
        //   1 - a_neg_b_pos - b_neg_a_pos => result = a_lt_b
        let result = a_neg_b_pos.clone() + (1.expr() - a_neg_b_pos - b_neg_a_pos) * a_lt_b.expr();

        // Pop a and b from the stack, push the result on the stack.
        cb.stack_pop(select::expr(is_sgt.expr(), b.expr(), a.expr()));
        cb.stack_pop(select::expr(is_sgt.expr(), a.expr(), b.expr()));
        cb.stack_push(result);

        // The read-write counter changes by three since we're reading two words
        // from stack and writing one. The program counter shifts only by one
        // and the since the stack now has one less word, the stack pointer also
        // shifts by one.
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::SLT.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            a,
            b,
            sign_check_a,
            sign_check_b,
            lt_lo,
            comparison_hi,
            a_lt_b,
            is_sgt,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _transaction: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        // SLT opcode is the default check in the SCMP gadget. Swap rw for SGT.
        self.is_sgt.assign(
            region,
            offset,
            F::from(opcode.as_u8() as u64),
            F::from(OpcodeId::SGT.as_u8() as u64),
        )?;
        let indices = if opcode == OpcodeId::SGT {
            [step.rw_indices[1], step.rw_indices[0]]
        } else {
            [step.rw_indices[0], step.rw_indices[1]]
        };
        let [a, b] = indices.map(|idx| block.rws[idx].stack_value());
        let a_le_bytes = a.to_le_bytes();
        let b_le_bytes = b.to_le_bytes();

        // Assign to the sign check gadgets. Since both a and b are in the
        // little-endian form, the most significant byte is the last byte.
        self.sign_check_a.assign(
            region,
            offset,
            F::from(a_le_bytes[31] as u64),
            F::from(128u64),
        )?;
        self.sign_check_b.assign(
            region,
            offset,
            F::from(b_le_bytes[31] as u64),
            F::from(128u64),
        )?;

        // Assign to the comparison gadgets. The first 16 bytes are assigned to
        // the `lo` less-than gadget while the last 16 bytes are assigned to
        // the `hi` comparison.
        self.lt_lo.assign(
            region,
            offset,
            from_bytes::value(&a_le_bytes[0..16]),
            from_bytes::value(&b_le_bytes[0..16]),
        )?;
        self.comparison_hi.assign(
            region,
            offset,
            from_bytes::value(&a_le_bytes[16..32]),
            from_bytes::value(&b_le_bytes[16..32]),
        )?;

        // Assign to intermediate witness a_lt_b.
        self.a_lt_b.assign(
            region,
            offset,
            Value::known(if a < b { F::one() } else { F::zero() }),
        )?;

        self.a.assign(region, offset, Some(a_le_bytes))?;
        self.b.assign(region, offset, Some(b_le_bytes))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::bytecode;
    use eth_types::evm_types::OpcodeId;
    use eth_types::Word;
    use mock::TestContext;

    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};

    fn test_ok(pairs: Vec<(OpcodeId, Word, Word)>) {
        let mut bytecode = bytecode! {};
        for (opcode, a, b) in pairs {
            bytecode.push(32, b);
            bytecode.push(32, a);
            bytecode.write_op(opcode);
        }
        bytecode.write_op(OpcodeId::STOP);

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn signed_comparator_gadget_a_b_neg() {
        let minus_1 = Word::from_big_endian(&[255u8; 32]);
        let minus_2 = {
            let mut bytes = vec![255u8; 32];
            bytes[31] = 254u8;
            Word::from_big_endian(&bytes)
        };
        test_ok(vec![
            (OpcodeId::SLT, minus_2, minus_1),
            (OpcodeId::SGT, minus_2, minus_1),
            (OpcodeId::SLT, minus_1, minus_2),
            (OpcodeId::SGT, minus_1, minus_2),
        ]);
    }

    #[test]
    fn signed_comparator_gadget_a_b_pos() {
        let plus_1 = {
            let mut bytes = vec![0u8; 32];
            bytes[31] = 1u8;
            Word::from_big_endian(&bytes)
        };
        let plus_2 = plus_1 + 1;
        test_ok(vec![
            (OpcodeId::SLT, plus_1, plus_2),
            (OpcodeId::SGT, plus_1, plus_2),
            (OpcodeId::SLT, plus_2, plus_1),
            (OpcodeId::SGT, plus_2, plus_1),
        ]);
    }

    #[test]
    fn signed_comparator_gadget_a_b_eq_hi_pos() {
        let a = Word::from_big_endian(&[[1u8; 16], [2u8; 16]].concat());
        let b = Word::from_big_endian(&[[1u8; 16], [3u8; 16]].concat());
        test_ok(vec![
            (OpcodeId::SLT, a, b),
            (OpcodeId::SGT, a, b),
            (OpcodeId::SLT, b, a),
            (OpcodeId::SGT, b, a),
        ]);
    }

    #[test]
    fn signed_comparator_gadget_a_b_eq_hi_neg() {
        let a = Word::from_big_endian(&[[129u8; 16], [2u8; 16]].concat());
        let b = Word::from_big_endian(&[[129u8; 16], [3u8; 16]].concat());
        test_ok(vec![
            (OpcodeId::SLT, a, b),
            (OpcodeId::SGT, a, b),
            (OpcodeId::SLT, b, a),
            (OpcodeId::SGT, b, a),
        ]);
    }

    #[test]
    fn signed_comparator_gadget_a_eq_b() {
        let a = rand_word();
        test_ok(vec![(OpcodeId::SLT, a, a), (OpcodeId::SGT, a, a)]);
    }

    #[test]
    fn signed_comparator_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(vec![
            (OpcodeId::SLT, a, b),
            (OpcodeId::SGT, a, b),
            (OpcodeId::SLT, b, a),
            (OpcodeId::SGT, b, a),
        ]);
    }
}
