use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep, ExpEvent, ExpStep},
    Error,
};
use eth_types::{GethExecStep, U256};

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Exponentiation;

fn exp_by_squaring(base: U256, exponent: U256, steps: &mut Vec<ExpStep>) -> U256 {
    if exponent.is_zero() {
        return U256::one();
    }
    if exponent == U256::one() {
        return base;
    }
    let (exponent_div2, odd) = exponent.div_mod(U256::from(2));
    if odd.is_zero() {
        // exponent is even
        let (base2, _) = base.overflowing_mul(base);
        steps.push((base, base, base2).into());
        exp_by_squaring(base2, exponent_div2, steps)
    } else {
        // exponent is odd
        let (base2, _) = base.overflowing_mul(base);
        steps.push((base, base, base2).into());
        let exp1 = exp_by_squaring(base2, exponent_div2, steps);
        let (exp2, _) = base.overflowing_mul(exp1);
        steps.push((exp1, base, exp2).into());
        exp2
    }
}

impl Opcode for Exponentiation {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        let base = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), base)?;
        let exponent = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), exponent)?;

        let (exponentiation, _) = base.overflowing_pow(exponent);
        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.last_filled(),
            exponentiation,
        )?;

        let mut steps = Vec::new();
        let exponentiation_calc = exp_by_squaring(base, exponent, &mut steps);
        debug_assert_eq!(exponentiation, exponentiation_calc);
        state.push_exponentiation(ExpEvent {
            base,
            exponent,
            exponentiation,
            steps,
        });

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod tests {
    use eth_types::U256;

    use super::exp_by_squaring;

    #[test]
    fn test_exp_by_squaring() {
        let mut steps = Vec::new();
        let exp = exp_by_squaring(23u64.into(), 123u64.into(), &mut steps);
        assert_eq!(
            exp,
            U256::from_dec_str(
                "87180413255890732361416772728849128389641993872302935967571352892955279939527"
            )
            .unwrap()
        );

        let mut steps = Vec::new();
        let exp = exp_by_squaring(3u64.into(), 13u64.into(), &mut steps);
        assert_eq!(exp, 1594323u64.into());
        assert_eq!(
            steps,
            vec![
                (3.into(), 3.into(), 9.into()).into(),
                (9.into(), 9.into(), 81.into()).into(),
                (81.into(), 81.into(), 6561.into()).into(),
                (6561.into(), 81.into(), 531441.into()).into(),
                (531441.into(), 3.into(), 1594323.into()).into(),
            ]
        );
    }
}
