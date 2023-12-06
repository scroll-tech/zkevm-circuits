use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            },
            math_gadget::{
                AddWordsGadget, CmpWordsGadget, IsZeroWordGadget, MulAddWords512Gadget,
                MulAddWordsGadget,
            },
            not, CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{
        word::{Word, Word32Cell, WordExpr},
        Expr,
    },
};

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, U256, U512};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct AddModGadget<F> {
    same_context: SameContextGadget<F>,

    a: Word32Cell<F>,
    b: Word32Cell<F>,
    r: Word32Cell<F>,
    n: Word32Cell<F>,

    k: Word32Cell<F>,
    d: Word32Cell<F>,
    a_reduced: Word32Cell<F>,

    muladd_k_n_areduced: MulAddWordsGadget<F>,

    sum_areduced_b: AddWordsGadget<F, 2, false>,
    sum_areduced_b_overflow: Word32Cell<F>,
    muladd_d_n_r: MulAddWords512Gadget<F>,

    //n_is_zero: IsZeroGadget<F>,
    n_is_zero: IsZeroWordGadget<F, Word32Cell<F>>,
    //cmp_r_n: CmpWordsGadget<F>,
    cmp_r_n: CmpWordsGadget<F, Word32Cell<F>, Word32Cell<F>>,
    //cmp_areduced_n: CmpWordsGadget<F>,
    cmp_areduced_n: CmpWordsGadget<F, Word32Cell<F>, Word32Cell<F>>,
}

impl<F: Field> ExecutionGadget<F> for AddModGadget<F> {
    const NAME: &'static str = "ADDMOD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ADDMOD;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // values got from stack (original r is modified if n==0)
        let a = cb.query_word32();
        let b = cb.query_word32();
        let n = cb.query_word32();
        let r = cb.query_word32();

        // auxiliar witness
        let k = cb.query_word32();
        let a_reduced = cb.query_word32();
        let d = cb.query_word32();

        let n_is_zero = IsZeroWordGadget::construct(cb, &n);

        // 1. check k * N + a_reduced == a without overflow
        let muladd_k_n_areduced =
            MulAddWordsGadget::construct(cb, [&k, &n.clone(), &a_reduced, &a]);
        cb.require_zero(
            "k * N + a_reduced does not overflow",
            muladd_k_n_areduced.overflow(),
        );

        // 2. check d * N + r == a_reduced + b, only checking carry if n != 0
        let sum_areduced_b = {
            let sum = cb.query_word32();
            AddWordsGadget::construct(cb, [a_reduced.clone(), b.clone()], sum)
        };
        let sum_areduced_b_overflow = cb.query_word32();
        let muladd_d_n_r = MulAddWords512Gadget::construct(
            cb,
            [&d, &n, &sum_areduced_b_overflow, sum_areduced_b.sum()],
            Some(&r),
        );

        cb.require_equal_word(
            "check a_reduced + b 512 bit carry if n != 0",
            sum_areduced_b_overflow.to_word(),
            Word::from_lo_unchecked(sum_areduced_b.carry().clone().unwrap().expr())
                .mul_selector(not::expr(n_is_zero.expr())),
        );

        let cmp_r_n = CmpWordsGadget::construct(cb, r.clone(), n.clone());
        let cmp_areduced_n = CmpWordsGadget::construct(cb, a_reduced.clone(), n.clone());

        // 3. r < n and a_reduced < n if n > 0
        cb.require_zero(
            "{r<n, a_reduced<n} if n > 0",
            2.expr() - (cmp_r_n.lt.expr() + cmp_areduced_n.lt.expr() + 2.expr() * n_is_zero.expr()),
        );

        // pop/push values
        // take care that if n==0 pushed value for r should be zero also
        cb.stack_pop(a.to_word());
        cb.stack_pop(b.to_word());
        cb.stack_pop(n.clone().to_word());
        cb.stack_push(
            r.clone()
                .to_word()
                .mul_selector(not::expr(n_is_zero.expr())),
        );

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(4.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr()),
            gas_left: Delta(-OpcodeId::ADDMOD.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            a,
            b,
            r,
            n,
            k,
            d,
            a_reduced,
            muladd_d_n_r,
            muladd_k_n_areduced,
            same_context,
            cmp_r_n,
            cmp_areduced_n,
            n_is_zero,
            sum_areduced_b,
            sum_areduced_b_overflow,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // get stack values
        let [mut r, n, b, a] = [3, 2, 1, 0]
            .map(|idx| step.rw_indices[idx])
            .map(|idx| block.rws[idx].stack_value());

        // assing a,b & n stack values
        self.a.assign_u256(region, offset, a)?;
        self.b.assign_u256(region, offset, b)?;
        self.n.assign_u256(region, offset, n)?;

        // compute a_reduced,k,d,a_reduced_plus_b,a_reduced_plus_b_overflow,r values
        let a_reduced;
        let k;
        let d;
        let a_reduced_plus_b;
        let a_reduced_plus_b_overflow;

        if n.is_zero() {
            k = U256::zero();
            a_reduced = a;
            d = U256::zero();
            r = a.overflowing_add(b).0;

            a_reduced_plus_b = a_reduced.overflowing_add(b).0;
            a_reduced_plus_b_overflow = U256::zero();
        } else {
            let (a_div_n, a_mod_n) = a.div_mod(n);
            k = a_div_n;
            a_reduced = a_mod_n;
            d = ((U512::from(a_reduced) + U512::from(b)) / U512::from(n))
                .try_into()
                .unwrap();

            let (sum, overflow) = a_reduced.overflowing_add(b);
            a_reduced_plus_b = sum;
            a_reduced_plus_b_overflow = if overflow { U256::one() } else { U256::zero() };
        };

        // rest of values and gadgets

        self.r.assign_u256(region, offset, r)?;
        self.k.assign_u256(region, offset, k)?;
        self.d.assign_u256(region, offset, d)?;
        self.a_reduced.assign_u256(region, offset, a_reduced)?;

        self.muladd_k_n_areduced
            .assign(region, offset, [k, n, a_reduced, a])?;

        self.sum_areduced_b
            .assign(region, offset, [a_reduced, b], a_reduced_plus_b)?;

        self.sum_areduced_b_overflow
            .assign_u256(region, offset, a_reduced_plus_b_overflow)?;
        self.muladd_d_n_r.assign(
            region,
            offset,
            [d, n, a_reduced_plus_b_overflow, a_reduced_plus_b],
            Some(r),
        )?;

        self.cmp_r_n.assign(region, offset, r, n)?;
        self.cmp_areduced_n.assign(region, offset, a_reduced, n)?;

        self.n_is_zero
            .assign_value(region, offset, Value::known(Word::from(n)))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, evm_types::Stack, Word};
    use mock::TestContext;

    fn test(a: Word, b: Word, n: Word, r: Option<Word>, ok: bool) {
        let bytecode = bytecode! {
            PUSH32(n)
            PUSH32(b)
            PUSH32(a)
            ADDMOD
            STOP
        };

        let mut ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap();
        if let Some(r) = r {
            let last = ctx
                .geth_traces
                .first_mut()
                .unwrap()
                .struct_logs
                .last_mut()
                .unwrap();
            last.stack = Stack::from_vec(vec![r]);
        }
        let mut ctb = CircuitTestBuilder::new_from_test_ctx(ctx);
        if !ok {
            ctb = ctb.evm_checks(Some(Box::new(|prover, gate_rows, lookup_rows| {
                assert!(prover
                    .verify_at_rows_par(gate_rows.iter().cloned(), lookup_rows.iter().cloned())
                    .is_err())
            })));
        };
        ctb.run()
    }

    fn test_ok_u32(a: u32, b: u32, c: u32, r: Option<u32>) {
        test(a.into(), b.into(), c.into(), r.map(Word::from), true)
    }

    fn test_ko_u32(a: u32, b: u32, c: u32, r: Option<u32>) {
        test(a.into(), b.into(), c.into(), r.map(Word::from), false)
    }

    #[test]
    fn addmod_simple() {
        test_ok_u32(1, 1, 10, None);
        test_ok_u32(1, 1, 11, None);
    }

    #[test]
    fn addmod_limits() {
        test(Word::MAX, Word::MAX, 0.into(), None, true);
        test(Word::MAX, Word::MAX, 1.into(), None, true);
        test(Word::MAX - 1, Word::MAX, Word::MAX, None, true);
        test(Word::MAX, Word::MAX, Word::MAX, None, true);
        test(Word::MAX, 1.into(), 0.into(), None, true);
        test(Word::MAX, 1.into(), 1.into(), None, true);
        test(Word::MAX, 1.into(), Word::MAX, None, true);
        test(Word::MAX, 0.into(), 0.into(), None, true);
        test(Word::MAX, 0.into(), 1.into(), None, true);
        test(Word::MAX, 0.into(), Word::MAX, None, true);
        test(0.into(), 0.into(), 0.into(), None, true);
        test(0.into(), 0.into(), 1.into(), None, true);
        test(0.into(), 0.into(), Word::MAX, None, true);
    }

    #[test]
    fn addmod_bad_r_on_nonzero_n() {
        test_ok_u32(7, 18, 10, Some(5));
        test_ko_u32(7, 18, 10, Some(6))
    }

    #[test]
    fn addmod_bad_r_on_zero_n() {
        test_ok_u32(2, 3, 0, Some(0));
        test_ko_u32(2, 3, 0, Some(1))
    }

    #[test]
    fn addmod_bad_r_bigger_n() {
        test_ok_u32(2, 3, 4, Some(1));
        test_ko_u32(2, 3, 4, Some(5))
    }
}
