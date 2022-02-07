use crate::{
    evm_circuit::{
        param::N_BYTES_GAS,
        table::{AccountFieldTag, FixedTableTag, Lookup},
        util::{
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            math_gadget::{AddWordsGadget, RangeCheckGadget},
            Cell, Word,
        },
        witness::ExecStep,
    },
    util::Expr,
};
use eth_types::U256;
use halo2::{
    arithmetic::FieldExt,
    circuit::Region,
    plonk::{Error, Expression},
};

/// Construction of execution state that stays in the same call context, which
/// lookups the opcode and verifies the execution state is responsible for it,
/// then calculates the gas_cost and constrain the state transition.
#[derive(Clone, Debug)]
pub(crate) struct SameContextGadget<F> {
    opcode: Cell<F>,
    sufficient_gas_left: RangeCheckGadget<F, N_BYTES_GAS>,
}

impl<F: FieldExt> SameContextGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        opcode: Cell<F>,
        mut step_state_transition: StepStateTransition<F>,
        dynamic_gas_cost: Option<Expression<F>>,
    ) -> Self {
        cb.opcode_lookup(opcode.expr(), 1.expr());
        cb.add_lookup(
            "Responsible opcode lookup",
            Lookup::Fixed {
                tag: FixedTableTag::ResponsibleOpcode.expr(),
                values: [
                    cb.execution_state().as_u64().expr(),
                    opcode.expr(),
                    0.expr(),
                ],
            },
        );

        let mut gas_cost = cb
            .execution_state()
            .responsible_opcodes()
            .first()
            .expect("Execution state in SameContextGadget should be responsible to some opcodes")
            .constant_gas_cost()
            .as_u64()
            .expr();

        if let Some(dynamic_gas_cost) = dynamic_gas_cost {
            gas_cost = gas_cost + dynamic_gas_cost;
        }

        // Check gas_left is sufficient
        let sufficient_gas_left =
            RangeCheckGadget::construct(cb, cb.curr.state.gas_left.expr() - gas_cost.clone());

        // Set state transition of gas_left if it's default value
        if matches!(step_state_transition.gas_left, Transition::Same)
            && !matches!(gas_cost, Expression::Constant(constant) if constant.is_zero_vartime())
        {
            step_state_transition.gas_left = Transition::Delta(-gas_cost);
        }

        // State transition
        cb.require_step_state_transition(step_state_transition);

        Self {
            opcode,
            sufficient_gas_left,
        }
    }

    pub(crate) fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Some(F::from(opcode.as_u64())))?;

        self.sufficient_gas_left.assign(
            region,
            offset,
            F::from((step.gas_left - step.gas_cost) as u64),
        )?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TransferWithGasFeeGadget<F> {
    sub_sender_balance: AddWordsGadget<F, 3>,
    add_receiver_balance: AddWordsGadget<F, 2>,
}

impl<F: FieldExt> TransferWithGasFeeGadget<F> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        sender_address: Expression<F>,
        receiver_address: Expression<F>,
        value: Word<F>,
        gas_fee: Word<F>,
        is_persistent: Expression<F>,
        rw_counter_end_of_reversion: Expression<F>,
    ) -> Self {
        let sender_balance = cb.query_word();
        let receiver_balance_prev = cb.query_word();

        // Subtract sender balance by value and gas_fee
        let sub_sender_balance =
            AddWordsGadget::construct(cb, [sender_balance.clone(), value.clone(), gas_fee]);
        cb.require_zero(
            "Sender has sufficient balance",
            sub_sender_balance.carry().expr(),
        );

        // Add receiver balance by value
        let add_receiver_balance =
            AddWordsGadget::construct(cb, [receiver_balance_prev.clone(), value]);
        cb.require_zero(
            "Receiver has too much balance",
            add_receiver_balance.carry().expr(),
        );

        let sender_balance_prev = sub_sender_balance.sum();
        let receiver_balance = add_receiver_balance.sum();

        // Write with possible reversion
        for (address, balance, balance_prev) in [
            (sender_address, &sender_balance, sender_balance_prev),
            (receiver_address, receiver_balance, &receiver_balance_prev),
        ] {
            cb.account_write_with_reversion(
                address,
                AccountFieldTag::Balance,
                balance.expr(),
                balance_prev.expr(),
                is_persistent.clone(),
                rw_counter_end_of_reversion.clone(),
            );
        }

        Self {
            sub_sender_balance,
            add_receiver_balance,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        (sender_balance, sender_balance_prev): (U256, U256),
        (receiver_balance, receiver_balance_prev): (U256, U256),
        value: U256,
        gas_fee: U256,
    ) -> Result<(), Error> {
        self.sub_sender_balance.assign(
            region,
            offset,
            [sender_balance, value, gas_fee],
            sender_balance_prev,
        )?;
        self.add_receiver_balance.assign(
            region,
            offset,
            [receiver_balance_prev, value],
            receiver_balance,
        )?;
        Ok(())
    }
}
