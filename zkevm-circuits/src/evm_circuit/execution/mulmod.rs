use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            self,
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{IsZeroGadget, LtWordGadget, ModGadget, MulAddWords512Gadget},
            sum, CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, U256};
use halo2_proofs::plonk::Error;

/// MulModGadget verifies opcode MULMOD
/// Verify a * b = r (mod n)
/// where a, b, n, r are 256-bit words
#[derive(Clone, Debug)]
pub(crate) struct MulModGadget<F> {
    same_context: SameContextGadget<F>,
    // a, b, n, r
    pub words: [util::Word<F>; 4],
    k: util::Word<F>,
    a_reduced: util::Word<F>,
    d: util::Word<F>,
    e: util::Word<F>,
    modword: ModGadget<F>,
    mul512_left: MulAddWords512Gadget<F>,
    mul512_right: MulAddWords512Gadget<F>,
    n_is_zero: IsZeroGadget<F>,
    lt: LtWordGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for MulModGadget<F> {
    const NAME: &'static str = "MULMOD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MULMOD;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word_rlc();
        let b = cb.query_word_rlc();
        let n = cb.query_word_rlc();
        let r = cb.query_word_rlc();

        let k = cb.query_word_rlc();

        let a_reduced = cb.query_word_rlc();
        let d = cb.query_word_rlc();
        let e = cb.query_word_rlc();

        // 1.  k1 * n + a_reduced  == a
        let modword = ModGadget::construct(cb, [&a, &n, &a_reduced]);

        // 2.  a_reduced * b + 0 == d * 2^256 + e
        let mul512_left = MulAddWords512Gadget::construct(cb, [&a_reduced, &b, &d, &e], None);

        // 3.  k2 * n + r == d * 2^256 + e
        let mul512_right = MulAddWords512Gadget::construct(cb, [&k, &n, &d, &e], Some(&r));

        // (r < n ) or n == 0
        let n_is_zero = IsZeroGadget::construct(cb, sum::expr(&n.cells));
        let lt = LtWordGadget::construct(cb, &r, &n);
        cb.add_constraint(
            " (1 - (r < n) - (n==0)) ",
            1.expr() - lt.expr() - n_is_zero.expr(),
        );

        cb.stack_pop(a.expr());
        cb.stack_pop(b.expr());
        cb.stack_pop(n.expr());
        cb.stack_push(r.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(4.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr()),
            gas_left: Delta(-OpcodeId::MULMOD.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            words: [a, b, n, r],
            same_context,
            k,
            a_reduced,
            d,
            e,
            modword,
            mul512_left,
            mul512_right,
            n_is_zero,
            lt,
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

        let [r, n, b, a] = [3, 2, 1, 0]
            .map(|idx| step.rw_indices[idx])
            .map(|idx| block.rws[idx].stack_value());
        self.words[0].assign(region, offset, Some(a.to_le_bytes()))?;
        self.words[1].assign(region, offset, Some(b.to_le_bytes()))?;
        self.words[2].assign(region, offset, Some(n.to_le_bytes()))?;
        self.words[3].assign(region, offset, Some(r.to_le_bytes()))?;
        // 1. quotient and reduction of a mod n
        let (k1, a_reduced) = if n.is_zero() {
            (U256::zero(), U256::zero())
        } else {
            a.div_mod(n)
        };

        // 2. Compute r = a*b mod n
        let prod = a_reduced.full_mul(b);
        let mut prod_bytes = [0u8; 64];
        prod.to_little_endian(&mut prod_bytes);
        let d = U256::from_little_endian(&prod_bytes[32..64]);
        let e = U256::from_little_endian(&prod_bytes[0..32]);

        let (r, k2) = if n.is_zero() {
            (U256::zero(), U256::zero())
        } else {
            // k2 <= b , always fits in U256
            (r, U256::try_from(prod / n).unwrap())
        };

        self.k.assign(region, offset, Some(k2.to_le_bytes()))?;
        self.a_reduced
            .assign(region, offset, Some(a_reduced.to_le_bytes()))?;
        self.d.assign(region, offset, Some(d.to_le_bytes()))?;
        self.e.assign(region, offset, Some(e.to_le_bytes()))?;

        self.modword.assign(region, offset, a, n, a_reduced, k1)?;
        self.mul512_left
            .assign(region, offset, [a_reduced, b, d, e], None)?;
        self.mul512_right
            .assign(region, offset, [k2, n, d, e], Some(r))?;

        self.lt.assign(region, offset, r, n)?;

        let n_sum = (0..32).fold(0, |acc, idx| acc + n.byte(idx) as u64);
        self.n_is_zero.assign(region, offset, F::from(n_sum))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::evm_types::Stack;
    use eth_types::{bytecode, Word, U256};
    use mock::TestContext;

    fn test(a: Word, b: Word, n: Word, r: Option<Word>, ok: bool) {
        let bytecode = bytecode! {
            PUSH32(n)
            PUSH32(b)
            PUSH32(a)
            MULMOD
            STOP
        };

        let mut ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap();
        if let Some(r) = r {
            let mut last = ctx
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
            ctb = ctb.evm_checks(Box::new(|prover, gate_rows, lookup_rows| {
                assert!(prover
                    .verify_at_rows_par(gate_rows.iter().cloned(), lookup_rows.iter().cloned())
                    .is_err())
            }));
        };
        ctb.run()
    }

    fn test_ok_u32(a: u32, b: u32, n: u32, r: Option<u32>) {
        test(a.into(), b.into(), n.into(), r.map(Word::from), true)
    }

    fn test_ko_u32(a: u32, b: u32, n: u32, r: Option<u32>) {
        test(a.into(), b.into(), n.into(), r.map(Word::from), false)
    }

    #[test]
    fn mulmod_simple() {
        test_ok_u32(7, 12, 10, None);
        test_ok_u32(7, 1, 10, None);
    }

    #[test]
    fn mulmod_edge() {
        test(
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            None,
            true,
        );
        test(
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            U256::from_str_radix("0x00000000000000000000000000000000000000000001", 16).unwrap(),
            None,
            true,
        );
        test(
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            U256::from_str_radix("0x00000000000000000000000000000000000000000000", 16).unwrap(),
            None,
            true,
        );
        test(
            U256::from_str_radix("0xfffffffffffffffffffffffffffffffffffffffffffe", 16).unwrap(),
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            U256::from_str_radix("0xffffffffffffffffffffffffffffffffffffffffffff", 16).unwrap(),
            None,
            true,
        );
    }

    #[test]
    fn mulmod_division_by_zero() {
        test_ok_u32(7, 1, 0, None);
    }

    #[test]
    fn mulmod_bad_r_on_nonzero_n() {
        test_ok_u32(7, 18, 10, Some(6));
        test_ko_u32(7, 18, 10, Some(7));
        test_ko_u32(7, 18, 10, Some(5));
    }

    #[test]
    fn mulmod_bad_r_on_zero_n() {
        test_ok_u32(2, 3, 0, Some(0));
        test_ko_u32(2, 3, 0, Some(1));
    }

    #[test]
    fn mulmod_bad_r_bigger_n() {
        test_ok_u32(2, 3, 5, Some(1));
        test_ko_u32(2, 3, 5, Some(5));
    }
}
