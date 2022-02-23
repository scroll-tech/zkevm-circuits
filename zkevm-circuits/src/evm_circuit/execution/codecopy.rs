use std::convert::TryInto;

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Region, plonk::Error};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag},
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            from_bytes,
            memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget, MemoryExpansionGadget},
            Cell, MemoryAddress,
        },
        witness::{Block, Call, CodeSource, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CodeCopyGadget<F> {
    same_context: SameContextGadget<F>,
    /// Holds the memory address for the offset in code from where we read.
    code_offset: MemoryAddress<F>,
    /// Holds the size of the current environment's bytecode.
    code_size: Cell<F>,
    /// Holds the current environment's address from where we wish to read code.
    account: Cell<F>,
    /// The code from current environment is copied to memory. To verify this
    /// copy operation we need the MemoryAddressGadget.
    dst_memory_addr: MemoryAddressGadget<F>,
    /// Opcode CODECOPY has a dynamic gas cost:
    /// gas_code = static_gas * minimum_word_size + memory_expansion_cost
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    /// Opcode CODECOPY needs to copy code bytes into memory. We account for
    /// the copying costs using the memory copier gas gadget.
    memory_copier_gas: MemoryCopierGasGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for CodeCopyGadget<F> {
    const NAME: &'static str = "CODECOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CODECOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        // Query elements to be popped from the stack.
        let dest_memory_offset = cb.query_cell();
        let code_offset = cb.query_rlc();
        let size = cb.query_rlc();

        // Pop items from stack.
        cb.stack_pop(dest_memory_offset.expr());
        cb.stack_pop(code_offset.expr());
        cb.stack_pop(size.expr());

        // Construct memory address in the destionation (memory) to which we copy code.
        let dst_memory_addr = MemoryAddressGadget::construct(cb, dest_memory_offset, size);

        // Query additional fields for the account's code.
        let account = cb.call_context(None, CallContextFieldTag::CalleeAddress);
        let code_size = cb.query_cell();
        let code_hash = cb.curr.state.code_source.clone();

        // Lookup the code hash and code size of the current environment's account.
        cb.account_read(account.expr(), AccountFieldTag::CodeSize, code_size.expr());
        cb.account_read(account.expr(), AccountFieldTag::CodeHash, code_hash.expr());

        // Calculate the next memory size and the gas cost for this memory
        // access. This also accounts for the dynamic gas required to copy bytes to
        // memory.
        let memory_expansion = MemoryExpansionGadget::construct(
            cb,
            cb.curr.state.memory_word_size.expr(),
            [dst_memory_addr.address()],
        );
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            dst_memory_addr.length(),
            memory_expansion.gas_cost(),
        );

        // Constrain the next step to be the internal `CopyCodeToMemory` step and add
        // some preliminary checks on its auxiliary data.
        cb.constrain_next_step(
            ExecutionState::CopyCodeToMemory,
            Some(dst_memory_addr.has_length()),
            |cb| {
                let next_src_addr = cb.query_cell();
                let next_dst_addr = cb.query_cell();
                let next_bytes_left = cb.query_cell();
                let next_src_addr_end = cb.query_cell();
                let next_code_hash = cb.query_word();

                cb.require_equal(
                    "next_src_addr == code_offset",
                    next_src_addr.expr(),
                    from_bytes::expr(&code_offset.cells),
                );
                cb.require_equal(
                    "next_dst_addr = memory_offset",
                    next_dst_addr.expr(),
                    dst_memory_addr.offset(),
                );
                cb.require_equal(
                    "next_bytes_left = length",
                    next_bytes_left.expr(),
                    dst_memory_addr.length(),
                );
                cb.require_equal(
                    "next_src_addr_end == code_size",
                    next_src_addr_end.expr(),
                    code_size.expr(),
                );
                cb.require_equal(
                    "next_code_hash == code_hash",
                    next_code_hash.expr(),
                    code_hash.expr(),
                );
            },
        );

        // Expected state transition.
        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(3.expr()),
            memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),
            gas_left: Transition::Delta(
                -OpcodeId::CODECOPY.constant_gas_cost().expr() - memory_copier_gas.gas_cost(),
            ),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            code_offset,
            code_size,
            account,
            dst_memory_addr,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // 1. `dest_offset` is the bytes offset in the memory where we start to
        // write.
        // 2. `code_offset` is the bytes offset in the current
        // context's code where we start to read.
        // 3. `size` is the number of
        // bytes to be read and written (0s to be copied for out of bounds).
        let [dest_offset, code_offset, size] =
            [0, 1, 2].map(|i| block.rws[step.rw_indices[i]].stack_value());

        // assign the code offset memory address.
        self.code_offset.assign(
            region,
            offset,
            Some(
                code_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        let account = if call.is_root {
            call.callee_address
        } else {
            unimplemented!("CODECOPY does not support internal calls yet");
        };
        println!("account = {:?}", account);
        self.account.assign(region, offset, account.to_scalar())?;

        let code = block
            .bytecodes
            .iter()
            .find(|b| {
                let CodeSource::Account(code_hash) = &call.code_source;
                b.hash == *code_hash
            })
            .expect("could not find current environment's bytecode");
        self.code_size
            .assign(region, offset, Some(F::from(code.bytes.len() as u64)))?;

        // assign the destination memory offset.
        let memory_address =
            self.dst_memory_addr
                .assign(region, offset, dest_offset, size, block.randomness)?;

        // assign to gadgets handling memory expansion cost and copying cost.
        let (_, memory_expansion_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        self.memory_copier_gas
            .assign(region, offset, size.as_u64(), memory_expansion_cost)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Sub;

    use bus_mapping::evm::OpcodeId;
    use eth_types::{bytecode, Address, ToWord, Word};
    use halo2_proofs::arithmetic::BaseExt;
    use num::Zero;
    use pairing::bn256::Fr;

    use crate::evm_circuit::{
        execution::copy_code_to_memory::test::make_copy_code_steps,
        step::ExecutionState,
        table::{AccountFieldTag, CallContextFieldTag, RwTableTag},
        test::{calc_memory_copier_gas_cost, run_test_circuit_incomplete_fixed_table},
        witness::{Block, Bytecode, Call, CodeSource, ExecStep, Rw, RwMap, Transaction},
    };

    fn test_ok(src_addr: u64, dst_addr: u64, size: usize) {
        let randomness = Fr::rand();
        let call_id = 1;
        let callee_addr = Address::random();

        let code = bytecode! {
            #[start]
            PUSH32(Word::from(size))
            PUSH32(Word::from(src_addr))
            PUSH32(Word::from(dst_addr))
            CODECOPY
            STOP
        };
        let code = Bytecode::new(code.to_vec());

        let mut rws_map = RwMap(
            [
                (
                    RwTableTag::Stack,
                    vec![
                        // Stack item written by PUSH32.
                        Rw::Stack {
                            rw_counter: 1,
                            is_write: true,
                            call_id,
                            stack_pointer: 1023,
                            value: Word::from(size),
                        },
                        // Stack item written by PUSH32.
                        Rw::Stack {
                            rw_counter: 2,
                            is_write: true,
                            call_id,
                            stack_pointer: 1022,
                            value: Word::from(src_addr),
                        },
                        // Stack item written by PUSH32.
                        Rw::Stack {
                            rw_counter: 3,
                            is_write: true,
                            call_id,
                            stack_pointer: 1021,
                            value: Word::from(dst_addr),
                        },
                        // First stack item read by CODECOPY.
                        Rw::Stack {
                            rw_counter: 4,
                            is_write: false,
                            call_id,
                            stack_pointer: 1021,
                            value: Word::from(dst_addr),
                        },
                        // Second stack item read by CODECOPY.
                        Rw::Stack {
                            rw_counter: 5,
                            is_write: false,
                            call_id,
                            stack_pointer: 1022,
                            value: Word::from(src_addr),
                        },
                        // Third stack item read by CODECOPY.
                        Rw::Stack {
                            rw_counter: 6,
                            is_write: false,
                            call_id,
                            stack_pointer: 1023,
                            value: Word::from(size),
                        },
                    ],
                ),
                (
                    RwTableTag::CallContext,
                    vec![
                        // Callee address lookup in CODECOPY.
                        Rw::CallContext {
                            rw_counter: 7,
                            call_id,
                            is_write: false,
                            field_tag: CallContextFieldTag::CalleeAddress,
                            value: callee_addr.to_word(),
                        },
                    ],
                ),
                (
                    RwTableTag::Account,
                    vec![
                        // Code size lookup in CODECOPY.
                        Rw::Account {
                            rw_counter: 8,
                            is_write: false,
                            account_address: callee_addr,
                            field_tag: AccountFieldTag::CodeSize,
                            value: Word::from(code.bytes.len()),
                            value_prev: Word::from(code.bytes.len()),
                        },
                        // Code hash lookup in CODECOPY.
                        Rw::Account {
                            rw_counter: 9,
                            is_write: false,
                            account_address: callee_addr,
                            field_tag: AccountFieldTag::CodeHash,
                            value: code.hash,
                            value_prev: code.hash,
                        },
                    ],
                ),
            ]
            .into(),
        );

        // After copying bytes from code to memory, we would end up having used this
        // much memory.
        let next_memory_word_size = if size.is_zero() {
            0
        } else {
            (dst_addr + size as u64 + 31) / 32
        };
        let gas_cost_push32 = OpcodeId::PUSH32.constant_gas_cost().as_u64();
        let gas_cost_codecopy = OpcodeId::CODECOPY.constant_gas_cost().as_u64()
            + calc_memory_copier_gas_cost(0, next_memory_word_size, size as u64);
        let total_gas_cost = (3 * gas_cost_push32) + gas_cost_codecopy;

        let mut steps = vec![
            ExecStep {
                rw_indices: vec![(RwTableTag::Stack, 0)],
                execution_state: ExecutionState::PUSH,
                rw_counter: 1,
                program_counter: 0,
                stack_pointer: 1024,
                gas_left: total_gas_cost,
                gas_cost: gas_cost_push32,
                opcode: Some(OpcodeId::PUSH32),
                ..Default::default()
            },
            ExecStep {
                rw_indices: vec![(RwTableTag::Stack, 1)],
                execution_state: ExecutionState::PUSH,
                rw_counter: 2,
                program_counter: 33,
                stack_pointer: 1023,
                gas_left: total_gas_cost.sub(gas_cost_push32),
                gas_cost: gas_cost_push32,
                opcode: Some(OpcodeId::PUSH32),
                ..Default::default()
            },
            ExecStep {
                rw_indices: vec![(RwTableTag::Stack, 2)],
                execution_state: ExecutionState::PUSH,
                rw_counter: 3,
                program_counter: 66,
                stack_pointer: 1022,
                gas_left: total_gas_cost.sub(2 * gas_cost_push32),
                gas_cost: gas_cost_push32,
                opcode: Some(OpcodeId::PUSH32),
                ..Default::default()
            },
            ExecStep {
                rw_indices: vec![
                    (RwTableTag::Stack, 3),
                    (RwTableTag::Stack, 4),
                    (RwTableTag::Stack, 5),
                    (RwTableTag::CallContext, 0),
                    (RwTableTag::Account, 0),
                    (RwTableTag::Account, 1),
                ],
                execution_state: ExecutionState::CODECOPY,
                rw_counter: 4,
                program_counter: 99,
                stack_pointer: 1021,
                gas_left: gas_cost_codecopy,
                gas_cost: gas_cost_codecopy,
                opcode: Some(OpcodeId::CODECOPY),
                ..Default::default()
            },
        ];

        let program_counter = 100;
        let stack_pointer = 1024;
        let mut rw_counter = 10;
        if !size.is_zero() {
            make_copy_code_steps(
                call_id,
                &code,
                src_addr,
                dst_addr,
                size,
                program_counter,
                stack_pointer,
                next_memory_word_size * 32,
                &mut rw_counter,
                &mut rws_map,
                &mut steps,
            );
        }
        steps.push(ExecStep {
            execution_state: ExecutionState::STOP,
            rw_counter,
            program_counter: 100,
            stack_pointer: 1024,
            opcode: Some(OpcodeId::STOP),
            memory_size: next_memory_word_size * 32,
            ..Default::default()
        });

        let block = Block {
            randomness,
            txs: vec![Transaction {
                id: 1,
                calls: vec![Call {
                    id: call_id,
                    is_root: true,
                    is_create: false,
                    code_source: CodeSource::Account(code.hash),
                    callee_address: callee_addr,
                    ..Default::default()
                }],
                steps,
                ..Default::default()
            }],
            rws: rws_map,
            bytecodes: vec![code],
            ..Default::default()
        };
        assert_eq!(run_test_circuit_incomplete_fixed_table(block), Ok(()));
    }

    #[test]
    fn codecopy_gadget_single_step() {
        test_ok(0x00, 0x00, 54);
    }

    #[test]
    fn codecopy_gadget_multi_step() {
        test_ok(0x00, 0x40, 123);
    }

    #[test]
    fn codecopy_gadget_oob() {
        test_ok(0x10, 0x20, 200);
    }
}
