use crate::{
    evm_circuit::{
        execution::{
            bus_mapping_tmp::{Block, Call, ExecStep, Transaction},
            ExecutionGadget,
        },
        step::ExecutionResult,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            from_bytes,
            math_gadget::{ComparisonGadget, IsEqualGadget},
            select, Word,
        },
    },
    util::Expr,
};
use bus_mapping::{eth_types::ToLittleEndian, evm::OpcodeId};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

// ComparatorGadget verifies ADD and SUB at the same time by an extra swap flag,
// when it's ADD, we annotate stack as [a, b, ...] and [c, ...],
// when it's SUB, we annotate stack as [a, c, ...] and [b, ...].
// Then we verify if a + b is equal to c.
#[derive(Clone, Debug)]
pub(crate) struct ComparatorGadget<F> {
    same_context: SameContextGadget<F>,
    a: Word<F>,
    b: Word<F>,
    comparison_lo: ComparisonGadget<F, 16>,
    comparison_hi: ComparisonGadget<F, 16>,
    is_eq: IsEqualGadget<F>,
    is_gt: IsEqualGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for ComparatorGadget<F> {
    const NAME: &'static str = "LT";

    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::LT;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word();
        let b = cb.query_word();

        // Check if opcode is EQ
        let is_eq =
            IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::EQ.expr());
        // Check if opcode is GT. For GT we swap the stack inputs so that we
        // actually do greater than instead of smaller than.
        let is_gt =
            IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::GT.expr());

        // `a[0..16] <= b[0..16]`
        let comparison_lo = ComparisonGadget::construct(
            cb,
            from_bytes::expr(&a.cells[0..16]),
            from_bytes::expr(&b.cells[0..16]),
        );
        let (lt_lo, eq_lo) = comparison_lo.expr();

        // `a[16..32] <= b[16..32]`
        let comparison_hi = ComparisonGadget::construct(
            cb,
            from_bytes::expr(&a.cells[16..32]),
            from_bytes::expr(&b.cells[16..32]),
        );
        let (lt_hi, eq_hi) = comparison_hi.expr();

        // `a < b` when:
        // - `a[16..32] < b[16..32]` OR
        // - `a[16..32] == b[16..32]` AND `a[0..16] < b[0..16]`
        let lt = select::expr(lt_hi, 1.expr(), eq_hi.clone() * lt_lo);
        // `a == b` when both parts are equal
        let eq = eq_hi * eq_lo;

        // The result is:
        // - `lt` when LT or GT
        // - `eq` when EQ
        let result = select::expr(is_eq.expr(), eq, lt);

        // Pop a and b from the stack, push the result on the stack.
        // When swap is enabled we swap stack places between a and b.
        // We can push result here directly because
        // it only uses the LSB of a word.
        cb.stack_pop(select::expr(is_gt.expr(), b.expr(), a.expr()));
        cb.stack_pop(select::expr(is_gt.expr(), a.expr(), b.expr()));
        cb.stack_push(result);

        // State transition
        let state_transition = StateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            ..Default::default()
        };
        let same_context =
            SameContextGadget::construct(cb, opcode, state_transition, None);

        Self {
            same_context,
            a,
            b,
            comparison_lo,
            comparison_hi,
            is_eq,
            is_gt,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction<F>,
        _: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        // EQ op check
        self.is_eq.assign(
            region,
            offset,
            F::from_u64(opcode.as_u8() as u64),
            F::from_u64(OpcodeId::EQ.as_u8() as u64),
        )?;

        // swap when doing GT
        let is_gt = self.is_gt.assign(
            region,
            offset,
            F::from_u64(opcode.as_u8() as u64),
            F::from_u64(OpcodeId::GT.as_u8() as u64),
        )?;

        let indices = if is_gt == F::one() {
            [step.rw_indices[1], step.rw_indices[0]]
        } else {
            [step.rw_indices[0], step.rw_indices[1]]
        };
        let [a, b] =
            indices.map(|idx| block.rws[idx].stack_value().to_le_bytes());

        // `a[0..16] <= b[0..16]`
        self.comparison_lo.assign(
            region,
            offset,
            from_bytes::value(&a[0..16]),
            from_bytes::value(&b[0..16]),
        )?;

        // `a[16..32] <= b[16..32]`
        self.comparison_hi.assign(
            region,
            offset,
            from_bytes::value(&a[16..32]),
            from_bytes::value(&b[16..32]),
        )?;

        self.a.assign(region, offset, Some(a))?;
        self.b.assign(region, offset, Some(b))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{
            Block, Bytecode, Call, ExecStep, Rw, Transaction,
        },
        step::ExecutionResult,
        test::{rand_word, run_test_circuit_incomplete_fixed_table},
        util::RandomLinearCombination, bus_mapping_tmp_convert,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId, bytecode,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(opcode: OpcodeId, a: Word, b: Word, _c: Word) {
        let bytecode = bytecode!{
            PUSH32(b)
            PUSH32(a)
            #[start]
            .write_op(opcode)
            STOP
        };
        let block = bus_mapping_tmp_convert::build_block_from_trace_code_at_start(&bytecode);
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn comparator_gadget_simple() {
        let hi_lo = Word::from_big_endian(&[[255u8; 16], [0u8; 16]].concat());
        let lo_hi = Word::from_big_endian(&[[0u8; 16], [255u8; 16]].concat());

        // LT
        // hi_lo < lo_hi == 0
        test_ok(OpcodeId::LT, hi_lo, lo_hi, 0.into());
        // lo_hi < hi_lo == 1
        test_ok(OpcodeId::LT, lo_hi, hi_lo, 1.into());
        // hi_lo < hi_lo == 0
        test_ok(OpcodeId::LT, hi_lo, hi_lo, 0.into());
        // lo_hi < lo_hi == 0
        test_ok(OpcodeId::LT, lo_hi, lo_hi, 0.into());

        // GT
        // hi_lo > lo_hi == 1
        test_ok(OpcodeId::GT, hi_lo, lo_hi, 1.into());
        // lo_hi > hi_lo == 0
        test_ok(OpcodeId::GT, lo_hi, hi_lo, 0.into());
        // hi_lo > hi_lo == 0
        test_ok(OpcodeId::GT, hi_lo, hi_lo, 0.into());
        // lo_hi > lo_hi == 0
        test_ok(OpcodeId::GT, lo_hi, lo_hi, 0.into());

        // EQ
        // (hi_lo == lo_hi) == 0
        test_ok(OpcodeId::EQ, hi_lo, lo_hi, 0.into());
        // (lo_hi == hi_lo) == 0
        test_ok(OpcodeId::EQ, lo_hi, hi_lo, 0.into());
        // (hi_lo == hi_lo) == 1
        test_ok(OpcodeId::EQ, hi_lo, hi_lo, 1.into());
        // (lo_hi == lo_hi) == 1
        test_ok(OpcodeId::EQ, lo_hi, lo_hi, 1.into());
    }

    #[test]
    fn comparator_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(OpcodeId::LT, a, b, Word::from((a < b) as usize));
        test_ok(OpcodeId::GT, a, b, Word::from((a > b) as usize));
        test_ok(OpcodeId::EQ, a, b, Word::from((a == b) as usize));
    }
}
