use std::sync::Mutex;

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        table::{FixedTableTag, Lookup},
        util::{
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition, Transition::Same,
            },
            math_gadget::{IsEqualGadget, IsZeroGadget},
            not, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, BlockContextFieldTag, CallContextFieldTag, TxContextFieldTag},
    util::{Expr, Field},
};
use bus_mapping::l2_predeployed::message_queue::{
    ADDRESS as MESSAGE_QUEUE, WITHDRAW_TRIE_ROOT_SLOT,
};
use eth_types::{
    forks::HardforkId,
    utils::{hash_code, hash_code_keccak},
};
use gadgets::ToScalar;
use halo2_proofs::{
    circuit::{Cell as AssignedCell, Value},
    plonk::{Error, Expression},
};

#[derive(Debug)]
pub(crate) struct EndBlockGadget<F> {
    chain_id: Cell<F>,
    total_txs: Cell<F>,
    total_txs_is_max_txs: IsEqualGadget<F>,
    is_empty_block: IsZeroGadget<F>,
    max_rws: Cell<F>,
    max_txs: Cell<F>,
    phase2_withdraw_root: Cell<F>,
    phase2_withdraw_root_prev: Cell<F>,
    is_curie_fork_block: Cell<F>,
    pub withdraw_root_assigned: Mutex<Option<AssignedCell>>,
}

impl<F: Clone> Clone for EndBlockGadget<F> {
    fn clone(&self) -> Self {
        let withdraw_root_assigned: Option<AssignedCell> =
            *self.withdraw_root_assigned.lock().unwrap();
        Self {
            withdraw_root_assigned: Mutex::new(withdraw_root_assigned),
            chain_id: self.chain_id.clone(),
            total_txs: self.total_txs.clone(),
            total_txs_is_max_txs: self.total_txs_is_max_txs.clone(),
            is_empty_block: self.is_empty_block.clone(),
            max_rws: self.max_rws.clone(),
            max_txs: self.max_txs.clone(),
            phase2_withdraw_root: self.phase2_withdraw_root.clone(),
            phase2_withdraw_root_prev: self.phase2_withdraw_root_prev.clone(),
            is_curie_fork_block: self.is_curie_fork_block.clone(),
        }
    }
}

/*
The goal of EndBlockGadget is to:
    0. expose withdraw root. Then it can be copied into pi circuit.
    1. constrain rws of evm circuit is same to rws of state circuit.
        We use 2 StartOp rw lookup to do this.
    2. constrain all txs inside tx circuit are processed inside evm circuit.
        (We don't need to constrain txs in evm circuit are not in tx circuit,
        since there are tx lookups)
To achieve the above goal:
    We need to pass "rwc" and "call_id" all the way to EndBlock.
    Then "rwc" can be used for goal1.
    For goal2 this gadget can read tx_id from CallContext using call_id.
 */
impl<F: Field> ExecutionGadget<F> for EndBlockGadget<F> {
    const NAME: &'static str = "EndBlock";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EndBlock;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let chain_id = cb.query_cell();
        let max_txs = cb.query_copy_cell();
        let max_rws = cb.query_copy_cell();
        let total_txs = cb.query_cell();
        let total_txs_is_max_txs = IsEqualGadget::construct(cb, total_txs.expr(), max_txs.expr());
        let phase2_withdraw_root = cb.query_copy_cell_phase2();
        let phase2_withdraw_root_prev = cb.query_cell_phase2();

        // Lookup block table with chain_id
        cb.block_lookup(
            BlockContextFieldTag::ChainId.expr(),
            cb.curr.state.block_number.expr(),
            chain_id.expr(),
        );

        let is_curie_fork_block = cb.query_cell();
        // Sequencer is allowed to do a predefined state transition at the hardfork block.
        cb.condition(is_curie_fork_block.expr(), |cb| {
            cb.add_lookup(
                "Hardfork lookup",
                Lookup::Fixed {
                    tag: FixedTableTag::ChainFork.expr(),
                    values: [
                        (HardforkId::Curie as u64).expr(),
                        chain_id.expr(),
                        cb.curr.state.block_number.expr(),
                    ]},
            );
            // Ref: bus-mapping/src/circuit_input_builder/curie.rs
            // Bytecode changes
            use bus_mapping::l2_predeployed::l1_gas_price_oracle;
            let v1_codesize = l1_gas_price_oracle::V1_BYTECODE.len();
            let v1_codehash = hash_code(&l1_gas_price_oracle::V1_BYTECODE);
            let v1_keccak_codehash = hash_code_keccak(&l1_gas_price_oracle::V1_BYTECODE);
            log::debug!("l1_oracle poseidon codehash {:?}", v1_codehash);
            log::debug!("l1_oracle keccak codehash {:?}", v1_keccak_codehash);
            let v2_codesize = l1_gas_price_oracle::V2_BYTECODE.len();
            let v2_codehash = hash_code(&l1_gas_price_oracle::V2_BYTECODE);
            let v2_keccak_codehash = hash_code_keccak(&l1_gas_price_oracle::V2_BYTECODE);
            let l1_fee_address = Expression::Constant(l1_gas_price_oracle::ADDRESS.to_scalar().expect(
                "Unexpected address of l2 gasprice oracle contract -> Scalar conversion failure",
            ));
            cb.account_write(
                l1_fee_address.expr(),
                AccountFieldTag::CodeHash,
                cb.code_hash(v2_codehash),
                cb.code_hash(v1_codehash),
                None,
            );
            cb.account_write(
                l1_fee_address.expr(),
                AccountFieldTag::KeccakCodeHash,
                cb.keccak_code_hash(v2_keccak_codehash),
                cb.keccak_code_hash(v1_keccak_codehash),
                None,
            );
            cb.account_write(
                l1_fee_address.expr(),
                AccountFieldTag::CodeSize,
                Expression::Constant(F::from(v2_codesize as u64)),
                Expression::Constant(F::from(v1_codesize as u64)),
                None,
            );
            // State changes
            for (slot, value) in [
                (*l1_gas_price_oracle::IS_CURIE_SLOT, eth_types::Word::from(1u64)),
                (*l1_gas_price_oracle::L1_BLOB_BASEFEE_SLOT, eth_types::Word::from(1u64)),
                (
                    *l1_gas_price_oracle::COMMIT_SCALAR_SLOT,
                    *l1_gas_price_oracle::INITIAL_COMMIT_SCALAR,
                ),
                (
                    *l1_gas_price_oracle::BLOB_SCALAR_SLOT,
                    *l1_gas_price_oracle::INITIAL_BLOB_SCALAR,
                ),
            ] {
                cb.account_storage_write(
                    l1_fee_address.expr(),
                    cb.word_rlc_constant(slot),
                    cb.word_rlc_constant(value),
                    0.expr(),
                    0.expr(),
                    0.expr(),
                    None,
                );
            }
        });

        // Note that rw_counter starts at 1
        let is_empty_block =
            IsZeroGadget::construct(cb, cb.curr.state.rw_counter.clone().expr() - 1.expr());
        // If the block is empty, we do 0 rw_table lookups
        // If the block is not empty, we will do 1 call_context lookup
        // and add 1 withdraw_root lookup
        let total_rws = not::expr(is_empty_block.expr())
            * (cb.curr.state.rw_counter.clone().expr() - 1.expr() + 1.expr())
            + 1.expr()
            + is_curie_fork_block.expr() * 7.expr();

        // 1. Constraint total_rws and total_txs witness values depending on the empty
        // block case.
        cb.condition(is_empty_block.expr(), |cb| {
            // 1a.
            cb.require_equal("total_txs is 0 in empty block", total_txs.expr(), 0.expr());
        });
        cb.condition(not::expr(is_empty_block.expr()), |cb| {
            // 1b. total_txs matches the tx_id that corresponds to the final step.
            cb.call_context_lookup(0.expr(), None, CallContextFieldTag::TxId, total_txs.expr());
        });

        let mut withdraw_trie_root_slot_le = [0u8; 32];
        WITHDRAW_TRIE_ROOT_SLOT.to_little_endian(withdraw_trie_root_slot_le.as_mut_slice());

        // 1.1 constraint withdraw_root
        cb.account_storage_read(
            Expression::Constant(MESSAGE_QUEUE.to_scalar().expect(
                "unexpected Address for message_queue precompile -> Scalar conversion failure",
            )),
            cb.word_rlc(withdraw_trie_root_slot_le.map(|byte| byte.expr())),
            phase2_withdraw_root.expr(),
            total_txs.expr(),
            phase2_withdraw_root_prev.expr(),
        );

        // 2. If total_txs == max_txs, we know we have covered all txs from the
        // tx_table. If not, we need to check that the rest of txs in the
        // table are padding.
        cb.condition(not::expr(total_txs_is_max_txs.expr()), |cb| {
            // Verify that there are at most total_txs meaningful txs in the tx_table, by
            // showing that the Tx following the last processed one has
            // CallerAddress = 0x0 (which means padding tx).
            cb.tx_context_lookup(
                total_txs.expr() + 1.expr(),
                TxContextFieldTag::CallerAddress,
                None,
                0.expr(),
            );
            // Since every tx lookup done in the EVM circuit must succeed
            // and uses a unique tx_id, we know that at
            // least there are total_tx meaningful txs in
            // the tx_table. We conclude that the number of
            // meaningful txs in the tx_table is total_tx.
        });

        // 3. Verify rw_counter counts to the same number of meaningful rows in
        // rw_table to ensure there is no malicious insertion.
        // Verify that there are at most total_rws meaningful entries in the rw_table
        cb.rw_table_start_lookup(1.expr());
        cb.rw_table_start_lookup(max_rws.expr() - total_rws.expr());
        // Since every lookup done in the EVM circuit must succeed and uses
        // a unique rw_counter, we know that at least there are
        // total_rws meaningful entries in the rw_table.
        // We conclude that the number of meaningful entries in the rw_table
        // is total_rws.

        cb.not_step_last(|cb| {
            // Propagate rw_counter and call_id all the way down.
            cb.require_step_state_transition(StepStateTransition {
                rw_counter: Same,
                call_id: Same,
                ..StepStateTransition::any()
            });
        });

        Self {
            chain_id,
            max_txs,
            max_rws,
            phase2_withdraw_root,
            phase2_withdraw_root_prev,
            total_txs,
            total_txs_is_max_txs,
            is_empty_block,
            is_curie_fork_block,
            withdraw_root_assigned: Default::default(),
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.chain_id
            .assign(region, offset, Value::known(F::from(block.chain_id)))?;
        self.is_empty_block
            .assign(region, offset, F::from(step.rw_counter as u64 - 1))?;
        let max_rws = F::from(block.circuits_params.max_rws as u64);
        let max_rws_assigned = self.max_rws.assign(region, offset, Value::known(max_rws))?;

        let total_txs = F::from(block.txs.len() as u64);
        let max_txs = F::from(block.circuits_params.max_txs as u64);
        self.total_txs
            .assign(region, offset, Value::known(total_txs))?;
        self.total_txs_is_max_txs
            .assign(region, offset, total_txs, max_txs)?;
        let max_txs_assigned = self.max_txs.assign(region, offset, Value::known(max_txs))?;

        let last_block_number = block
            .context
            .ctxs
            .last_key_value()
            .map(|(_, b)| b.number)
            .unwrap_or_default();
        let is_curie = bus_mapping::circuit_input_builder::curie::is_curie_fork_block(
            block.chain_id,
            last_block_number.as_u64(),
        );
        self.is_curie_fork_block
            .assign(region, offset, Value::known(F::from(is_curie as u64)))?;

        let withdraw_root = self.phase2_withdraw_root.assign(
            region,
            offset,
            region.word_rlc(block.withdraw_root),
        )?;
        let _withdraw_root_prev = self.phase2_withdraw_root_prev.assign(
            region,
            offset,
            region.word_rlc(block.prev_withdraw_root),
        )?;
        if let Some(cell) = withdraw_root {
            *self.withdraw_root_assigned.lock().unwrap() = Some(cell.cell());
        }
        // TODO: now we do not export withdraw_root_prev for we have only one
        // phase2 cell which is enabled for copy constraint
        // self.withdraw_root_prev_assigned
        //     .borrow_mut()
        //     .replace(withdraw_root_prev.cell());

        // When rw_indices is not empty, we're at the last row (at a fixed offset),
        // where we need to access the max_rws and max_txs constant.
        if !step.rw_indices.is_empty() {
            region.constrain_constant(max_rws_assigned.unwrap(), max_rws)?;
            region.constrain_constant(max_txs_assigned.unwrap(), max_txs)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;

    use eth_types::bytecode;

    use mock::TestContext;

    fn test_circuit(evm_circuit_pad_to: usize) {
        let bytecode = bytecode! {
            PUSH1(0)
            STOP
        };

        let ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap();

        // finish required tests using this witness block
        CircuitTestBuilder::<2, 1>::new_from_test_ctx(ctx)
            .block_modifier(Box::new(move |block| {
                block.circuits_params.max_evm_rows = evm_circuit_pad_to
            }))
            .run();
    }

    // Test where the EVM circuit contains an exact number of rows corresponding to
    // the trace steps + 1 EndBlock
    #[test]
    fn end_block_exact() {
        test_circuit(0);
    }

    // Test where the EVM circuit has a fixed size and contains several padding
    // EndBlocks at the end after the trace steps
    #[test]
    fn end_block_padding() {
        test_circuit(100);
    }
}
