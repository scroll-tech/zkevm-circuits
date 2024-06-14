use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition, Transition,
            },
            math_gadget::IsZeroGadget,
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{BlockContextFieldTag, TxFieldTag::BlockNumber},
    util::Field,
};
use gadgets::util::{not, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub(crate) struct EndInnerBlockGadget<F> {
    /// The transaction ID of the last transaction in this inner block. If this
    /// block was empty, i.e. it contained no transactions, then the tx ID
    /// will be 0.
    last_tx_id: Cell<F>,
    /// The number of transactions in this inner block.
    num_txs: Cell<F>,
    /// The number of transactions up until this block, including the txs in
    /// this block.
    cum_num_txs: Cell<F>,
    /// Gadget used to check if the inner block was empty.
    is_empty_block: IsZeroGadget<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for EndInnerBlockGadget<F> {
    const NAME: &'static str = "EndInnerBlock";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EndInnerBlock;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        // `cb.curr.state.block_number` is constrained inside execution.rs
        // The number of txs in the inner block is also the ID of the last tx in the
        // block.
        let last_tx_id = cb.query_cell();
        let num_txs = cb.query_cell();
        let cum_num_txs = cb.query_cell();
        cb.block_lookup(
            BlockContextFieldTag::NumTxs.expr(),
            cb.curr.state.block_number.expr(),
            num_txs.expr(),
        );
        cb.block_lookup(
            BlockContextFieldTag::CumNumTxs.expr(),
            cb.curr.state.block_number.expr(),
            cum_num_txs.expr(),
        );

        cb.require_equal(
            "last tx_id MUST equal the cumulative number of txs up until this block",
            last_tx_id.expr(),
            cum_num_txs.expr(),
        );

        // if the block had transactions, the last tx's block number is the current
        // step's block number.
        let is_empty_block = IsZeroGadget::construct(cb, num_txs.expr());
        cb.condition(not::expr(is_empty_block.expr()), |cb| {
            cb.tx_context_lookup(
                last_tx_id.expr(),
                BlockNumber,
                None,
                cb.curr.state.block_number.expr(),
            );
        });

        // Depending on whether or not this is the final inner block, we must constrain
        // the next step's block number.
        let next_step_padding = cb.next.execution_state_selector([ExecutionState::Padding]);
        cb.condition(next_step_padding.clone(), |cb| {
            cb.require_equal(
                "block number does not change if this is the last inner block",
                cb.next.state.block_number.expr(),
                cb.curr.state.block_number.expr(),
            );
        });
        cb.condition(not::expr(next_step_padding), |cb| {
            cb.require_equal(
                "block number increments if there are more inner blocks",
                cb.next.state.block_number.expr(),
                cb.curr.state.block_number.expr() + 1.expr(),
            );
        });

        cb.require_step_state_transition(StepStateTransition {
            rw_counter: Transition::Same,
            // We propagate call_id so that EndBlock can get the last tx_id
            // in order to count processed txs.
            // call_id: Transition::Same,
            ..StepStateTransition::any()
        });

        Self {
            last_tx_id,
            num_txs,
            cum_num_txs,
            is_empty_block,
            _marker: PhantomData,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block,
        tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let num_txs = block
            .txs
            .iter()
            .filter(|t| t.block_number == step.block_num)
            .count();
        let cum_num_txs = block
            .txs
            .iter()
            .filter(|t| t.block_number <= step.block_num)
            .count();

        self.last_tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.num_txs
            .assign(region, offset, Value::known(F::from(num_txs as u64)))?;
        self.cum_num_txs
            .assign(region, offset, Value::known(F::from(cum_num_txs as u64)))?;
        self.is_empty_block
            .assign(region, offset, F::from(num_txs as u64))?;

        Ok(())
    }
}
