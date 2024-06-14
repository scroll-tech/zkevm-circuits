use crate::{
    evm_circuit::{
        param::N_BYTES_MEMORY_WORD_SIZE,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition, Transition,
            },
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryCopierGasGadget,
                MemoryExpansionGadget,
            },
            not, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::{Expr, Field},
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::evm_types::GasCost;
use gadgets::ToScalar;
// use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

use super::ExecutionGadget;

// Gadget for MCOPY opcode
#[derive(Clone, Debug)]
pub(crate) struct MCopyGadget<F> {
    same_context: SameContextGadget<F>,
    memory_src_address: MemoryAddressGadget<F>,
    memory_dest_address: MemoryAddressGadget<F>,
    copy_rwc_inc: Cell<F>,
    // two addresses(src and dest) expansion, then select greater one to calculate memory word size
    // and gas cost
    memory_expansion: MemoryExpansionGadget<F, 2, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
}

impl<F: Field> ExecutionGadget<F> for MCopyGadget<F> {
    const NAME: &'static str = "MCOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MCOPY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let src_offset = cb.query_cell_phase2();
        let dest_offset = cb.query_cell_phase2();
        let length = cb.query_word_rlc();

        cb.stack_pop(dest_offset.expr());
        cb.stack_pop(src_offset.clone().expr());
        cb.stack_pop(length.expr());

        let memory_src_address =
            MemoryAddressGadget::construct(cb, src_offset.clone(), length.clone());
        let memory_dest_address =
            MemoryAddressGadget::construct(cb, dest_offset.clone(), length.clone());

        // if no actual copy happens, memory_word_size doesn't change. MemoryExpansionGadget handle
        // memory_word_size with MemoryAddressGadget.
        // more detailed:
        // when copy length is zero ( `length` == 0), MemoryAddressGadget set address offset to
        // zero. in this context memory_src_address and memory_dest_address are both zeros.
        // then for `end_offset()` in MemoryExpansionGadget also return zero.
        // MemoryExpansionGadget compares current memory_word_size (cb.curr.state.memory_word_size)
        // to two new addresses( memory_src_address and memory_dest_address) required word
        // expansion, the max were selected as next memory_word_size. because of zeros of
        // new address word expansion not greater than current memory_word_size, so next
        // memory_word_size remains the same to current memory_word_size, which means
        // memory_word_size state in next step doesn't change.

        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            [
                memory_src_address.end_offset(),
                memory_dest_address.end_offset(),
            ],
        );
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_src_address.length(),
            memory_expansion.gas_cost(),
        );

        // dynamic cost + constant cost
        let gas_cost = memory_copier_gas.gas_cost() + OpcodeId::MCOPY.constant_gas_cost().expr();

        // copy_rwc_inc used in copy circuit lookup.
        let copy_rwc_inc = cb.query_cell();
        cb.condition(memory_src_address.has_length(), |cb| {
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                // src_addr
                memory_src_address.offset(),
                // src_addr_end
                memory_src_address.end_offset(),
                // dest_addr
                memory_dest_address.offset(),
                memory_dest_address.length(),
                // rlc_acc is 0 here.
                0.expr(),
                copy_rwc_inc.expr(),
            );
        });

        cb.condition(not::expr(memory_src_address.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(3.expr()),
            memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),

            gas_left: Transition::Delta(-gas_cost),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_src_address,
            memory_dest_address,
            copy_rwc_inc,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block,
        _transaction: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [dest_offset, src_offset, length] =
            [0, 1, 2].map(|idx| block.rws[step.rw_indices[idx]].stack_value());
        let src_addr = self
            .memory_src_address
            .assign(region, offset, src_offset, length)?;
        let dest_addr = self
            .memory_dest_address
            .assign(region, offset, dest_offset, length)?;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                step.copy_rw_counter_delta
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [src_addr, dest_addr],
        )?;

        self.memory_copier_gas.assign(
            region,
            offset,
            length.as_u64(),
            memory_expansion_gas_cost,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{address, bytecode, word, Address, Bytecode, Word};
    use mock::TestContext;
    use std::sync::LazyLock;

    static EXTERNAL_ADDRESS: LazyLock<Address> =
        LazyLock::new(|| address!("0xaabbccddee000000000000000000000000000000"));

    fn test_ok(src_offset: Word, dest_offset: Word, length: usize) {
        let mut code = Bytecode::default();
        code.append(&bytecode! {
            // prepare memory values(non zero values, zero value easily cause unpredictable fake pass) by mstore
            PUSH32(word!("0x0102030405060708090a0b0c0d0e0f000102030405060708090a"))
            PUSH2(0x20)
            MSTORE
            PUSH32(length)
            PUSH32(src_offset)
            PUSH32(dest_offset)
            #[start]
            MCOPY
            STOP
        });

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .code(code);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .gas(1_000_000.into());
            },
            |block, _tx| block.number(0x1111111),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_copy_rows: 1750,
                ..Default::default()
            })
            .run();
    }

    // tests for zero copy length
    #[test]
    fn mcopy_empty() {
        test_ok(Word::from("0x20"), Word::zero(), 0x0);
        test_ok(Word::from("0xa8"), Word::from("0x2f"), 0x0);
        test_ok(Word::from("0x0"), Word::from("0x600"), 0x0);
    }

    // tests for real copy
    #[test]
    fn mcopy_non_empty() {
        // copy within one slot
        test_ok(Word::from("0x20"), Word::from("0x39"), 0x01);
        // copy across multi slots
        test_ok(Word::from("0x30"), Word::from("0x30"), 0xA0);
        test_ok(Word::from("0x40"), Word::from("0x40"), 0xE4);
        test_ok(Word::from("0x0"), Word::from("0x100"), 0x20);

        // src and dest copy range overlap case, test tool found that case failed.
        // this test can repro issue: "non-first access reads don't change value"
        test_ok(Word::from("0x0"), Word::from("0x20"), 0x40);
    }

    // mcopy OOG cases added in ./execution/error_oog_memory_copy.rs
}
