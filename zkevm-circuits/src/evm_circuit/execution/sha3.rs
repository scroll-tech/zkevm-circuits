use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToScalar};
use gadgets::util::{not, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        param::N_BYTES_MEMORY_WORD_SIZE,
        step::ExecutionState,
        util::{
            common_gadget::{get_copy_bytes, SameContextGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition, Transition,
            },
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryCopierGasGadget,
                MemoryExpansionGadget,
            },
            rlc, CachedRegion, Cell, StepRws,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::word::{Word, Word32Cell, WordExpr},
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct Sha3Gadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddressGadget<F>,
    //sha3_digest: WordCell<F>,
    sha3_digest: Word32Cell<F>,
    copy_rwc_inc: Cell<F>,
    rlc_acc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY_SHA3 }>,
}

impl<F: Field> ExecutionGadget<F> for Sha3Gadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::SHA3;

    const NAME: &'static str = "SHA3";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let offset = cb.query_word_unchecked();
        let size = cb.query_memory_address();
        let sha3_digest = cb.query_word32();

        cb.stack_pop(offset.to_word());
        cb.stack_pop(size.to_word());
        cb.stack_push(sha3_digest.to_word());

        let memory_address = MemoryAddressGadget::construct(cb, offset, size);

        let copy_rwc_inc = cb.query_cell();
        let rlc_acc = cb.query_cell_phase2();

        cb.condition(memory_address.has_length(), |cb| {
            cb.copy_table_lookup(
                Word::from_lo_unchecked(cb.curr.state.call_id.expr()),
                CopyDataType::Memory.expr(),
                Word::from_lo_unchecked(cb.curr.state.call_id.expr()),
                CopyDataType::RlcAcc.expr(),
                memory_address.offset(),
                memory_address.address(),
                0.expr(), // dst_addr for CopyDataType::RlcAcc is 0.
                memory_address.length(),
                rlc_acc.expr(),
                copy_rwc_inc.expr(),
            );
        });

        cb.condition(not::expr(memory_address.has_length()), |cb| {
            cb.require_zero("copy_rwc_inc == 0 for size = 0", copy_rwc_inc.expr());
            cb.require_zero("rlc_acc == 0 for size = 0", rlc_acc.expr());
        });

        // let output_rlc = cb.word_rlc(sha3_digest.limbs.clone().map(|l| l.expr()));
        cb.keccak_table_lookup(
            rlc_acc.expr(),
            memory_address.length(),
            //output_rlc,
            sha3_digest.to_word(),
        );

        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(1.expr()),
            memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),
            gas_left: Transition::Delta(
                -(OpcodeId::SHA3.constant_gas_cost().expr() + memory_copier_gas.gas_cost()),
            ),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            sha3_digest,
            copy_rwc_inc,
            rlc_acc,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let mut rws = StepRws::new(block, step);

        self.same_context.assign_exec_step(region, offset, step)?;

        let [memory_offset, size, sha3_output] = [(); 3].map(|_| rws.next().stack_value());
        let memory_address = self
            .memory_address
            .assign(region, offset, memory_offset, size)?;
        self.sha3_digest.assign_u256(region, offset, sha3_output)?;

        let shift = memory_offset.low_u64() % 32;
        let copy_rwc_inc = step.copy_rw_counter_delta;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                copy_rwc_inc
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let values: Vec<u8> = get_copy_bytes(&mut rws, copy_rwc_inc as usize, shift, size.as_u64());

        let rlc_acc = region
            .challenges()
            .keccak_input()
            .map(|randomness| rlc::value(values.iter().rev(), randomness));
        self.rlc_acc.assign(region, offset, rlc_acc)?;

        // Memory expansion and dynamic gas cost for reading it.
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        self.memory_copier_gas
            .assign(region, offset, size.as_u64(), memory_expansion_gas_cost)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::{
        circuit_input_builder::CircuitsParams,
        evm::{gen_sha3_code, MemoryKind},
    };
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(offset: usize, size: usize, mem_kind: MemoryKind) {
        let (code, _) = gen_sha3_code(offset, size, mem_kind);
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
        .params(CircuitsParams {
            max_rws: 5500,
            max_copy_rows: 3000,
            ..Default::default()
        })
        .run();
    }

    #[test]
    fn sha3_gadget_zero_length() {
        test_ok(0x20, 0x00, MemoryKind::MoreThanSize);
    }

    #[test]
    fn sha3_gadget_simple() {
        test_ok(0x00, 0x08, MemoryKind::Empty);
        test_ok(0x10, 0x10, MemoryKind::LessThanSize);
        test_ok(0x24, 0x16, MemoryKind::EqualToSize);
        test_ok(0x32, 0x78, MemoryKind::MoreThanSize);
    }

    #[test]
    fn sha3_gadget_large() {
        test_ok(0x101, 0x202, MemoryKind::Empty);
        test_ok(0x202, 0x303, MemoryKind::LessThanSize);
        test_ok(0x303, 0x404, MemoryKind::EqualToSize);
        test_ok(0x404, 0x505, MemoryKind::MoreThanSize);
    }

    #[test]
    fn sha3_gadget_overflow_offset_and_zero_size() {
        let bytecode = bytecode! {
            PUSH1(0)
            PUSH32(Word::MAX)
            SHA3
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
