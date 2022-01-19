use halo2::{arithmetic::FieldExt, circuit::Region, plonk::Error};

use crate::{
    evm_circuit::{
        step::ExecutionState,
        table::{CallContextFieldTag, TxContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition,
            },
            Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CallDataSizeGadget<F> {
    same_context: SameContextGadget<F>,
    tx_id: Cell<F>,
    call_data_size: Cell<F>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallDataSizeGadget<F> {
    const NAME: &'static str = "CALLDATASIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATASIZE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Setting the call_id to `None` looks up the current call id.
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        // Calldatasize can be looked up in the above tx_id's context.
        let call_data_size = cb.query_cell();

        // The calldatasize should be compared against tx calldata if the call
        // is the root call. If not the root call, it is an internal
        // call.
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            cb.tx_context_lookup(
                tx_id.expr(),
                TxContextFieldTag::CallDataLength.expr(),
                call_data_size.expr(),
            );
        });
        cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            cb.call_context_lookup(
                None,
                CallContextFieldTag::CallDataLength,
                call_data_size.expr(),
            );
        });

        // The calldatasize should be pushed to the top of the stack.
        cb.stack_push(call_data_size.expr());

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(1.expr()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta((-1).expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            tx_id,
            call_data_size,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        _block: &Block<F>,
        transaction: &Transaction<F>,
        call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        self.tx_id.assign(
            region,
            offset,
            Some(F::from(transaction.id as u64)),
        )?;

        self.call_data_size.assign(
            region,
            offset,
            Some(F::from(if call.is_root {
                transaction.call_data_length as u64
            } else {
                call.call_data_length as u64
            })),
        )?;

        Ok(())
    }
}
