use crate::{
    evm_circuit::{
        execution::{bus_mapping_tmp::ExecTrace, ExecutionGadget},
        step::ExecutionResult,
        util::{
            constraint_builder::{
                ConstraintBuilder, StateTransition, Transition::Delta,
            },
            from_bytes,
            math_gadget::{ComparisonGadget, IsEqualGadget, RangeCheckGadget},
            select, Cell, Word,
        },
    },
    util::Expr,
};
use bus_mapping::{
    eth_types::ToLittleEndian,
    evm::{GasCost, OpcodeId},
};
use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

// ComparatorGadget verifies ADD and SUB at the same time by an extra swap flag,
// when it's ADD, we annotate stack as [a, b, ...] and [c, ...],
// when it's SUB, we annotate stack as [a, c, ...] and [b, ...].
// Then we verify if a + b is equal to c.
#[derive(Clone)]
pub(crate) struct ComparatorGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, 8>,
    a: Word<F>,
    b: Word<F>,
    comparison_lo: ComparisonGadget<F, 16>,
    comparison_hi: ComparisonGadget<F, 16>,
    is_eq: IsEqualGadget<F>,
    is_gt: IsEqualGadget<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for ComparatorGadget<F> {
    const EXECUTION_RESULT: ExecutionResult = ExecutionResult::LT;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr());

        let sufficient_gas_left =
            cb.require_sufficient_gas_left(GasCost::FASTEST.expr());

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
            from_bytes::expr(a.cells[0..16].to_vec()),
            from_bytes::expr(b.cells[0..16].to_vec()),
        );
        let (lt_lo, eq_lo) = comparison_lo.expr();

        // `a[16..32] <= b[16..32]`
        let comparison_hi = ComparisonGadget::construct(
            cb,
            from_bytes::expr(a.cells[16..32].to_vec()),
            from_bytes::expr(b.cells[16..32].to_vec()),
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

        // State transitions
        let state_transition = StateTransition {
            rw_counter: Delta(cb.rw_counter_offset().expr()),
            program_counter: Delta(cb.program_counter_offset().expr()),
            stack_pointer: Delta(cb.stack_pointer_offset().expr()),
            gas_left: Delta(-GasCost::FASTEST.expr()),
            ..Default::default()
        };
        cb.require_state_transition(state_transition);

        Self {
            opcode,
            sufficient_gas_left,
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
        exec_trace: &ExecTrace<F>,
        step_idx: usize,
    ) -> Result<(), Error> {
        let step = &exec_trace.steps[step_idx];

        let opcode = step.opcode.unwrap();
        self.opcode.assign(
            region,
            offset,
            Some(F::from_u64(opcode.as_u64())),
        )?;

        self.sufficient_gas_left.assign(
            region,
            offset,
            F::from_u64((step.gas_left - step.gas_cost) as u64),
        )?;

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
            indices.map(|idx| exec_trace.rws[idx].stack_value().to_le_bytes());

        // `a[0..16] <= b[0..16]`
        self.comparison_lo.assign(
            region,
            offset,
            from_bytes::value(a[0..16].to_vec()),
            from_bytes::value(b[0..16].to_vec()),
        )?;

        // `a[16..32] <= b[16..32]`
        self.comparison_hi.assign(
            region,
            offset,
            from_bytes::value(a[16..32].to_vec()),
            from_bytes::value(b[16..32].to_vec()),
        )?;

        self.a.assign(region, offset, Some(a))?;
        self.b.assign(region, offset, Some(b))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::{
        execution::bus_mapping_tmp::{Bytecode, Call, ExecStep, ExecTrace, Rw},
        step::ExecutionResult,
        test::{rand_word, try_test_circuit},
        util::RandomLinearCombination,
    };
    use bus_mapping::{
        eth_types::{ToBigEndian, ToLittleEndian, Word},
        evm::OpcodeId,
    };
    use halo2::arithmetic::FieldExt;
    use pasta_curves::pallas::Base;

    fn test_ok(opcode: OpcodeId, a: Word, b: Word, result: Word) {
        let randomness = Base::rand();
        let bytecode = Bytecode::new(
            [
                vec![0x7f],
                b.to_be_bytes().to_vec(),
                vec![0x7f],
                a.to_be_bytes().to_vec(),
                vec![opcode.as_u8(), 0x00],
            ]
            .concat(),
        );
        let exec_trace = ExecTrace {
            randomness,
            steps: vec![
                ExecStep {
                    rw_indices: vec![0, 1, 2],
                    execution_result: ExecutionResult::LT,
                    rw_counter: 1,
                    program_counter: 66,
                    stack_pointer: 1022,
                    gas_left: 3,
                    gas_cost: 3,
                    opcode: Some(opcode),
                    ..Default::default()
                },
                ExecStep {
                    execution_result: ExecutionResult::STOP,
                    rw_counter: 4,
                    program_counter: 67,
                    stack_pointer: 1023,
                    gas_left: 0,
                    opcode: Some(OpcodeId::STOP),
                    ..Default::default()
                },
            ],
            txs: vec![],
            calls: vec![Call {
                id: 1,
                is_root: false,
                is_create: false,
                opcode_source: RandomLinearCombination::random_linear_combine(
                    bytecode.hash.to_le_bytes(),
                    randomness,
                ),
            }],
            rws: vec![
                Rw::Stack {
                    counter: 1,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1022,
                    value: a,
                },
                Rw::Stack {
                    counter: 2,
                    is_write: false,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: b,
                },
                Rw::Stack {
                    counter: 3,
                    is_write: true,
                    call_id: 1,
                    stack_pointer: 1023,
                    value: result,
                },
            ],
            bytecodes: vec![bytecode],
        };
        try_test_circuit(exec_trace, Ok(()));
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
