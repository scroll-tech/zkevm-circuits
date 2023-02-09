use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{
            N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS, N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE,
            N_BYTES_U64,
        },
        step::ExecutionState,
        util::{
            common_gadget::TransferGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition::{Delta, To},
            },
            from_bytes,
            math_gadget::{ConstantDivisionGadget, IsZeroGadget},
            memory_gadget::{MemoryAddressGadget, MemoryExpansionGadget},
            not, rlc, select, sum, CachedRegion, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToBigEndian, ToLittleEndian, ToScalar, U256};
use ethers_core::utils::{keccak256, rlp};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use std::iter::once;

/// Gadget for CREATE and CREATE2 opcodes
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGCodeStoreGadget<F> {
    opcode: Cell<F>,
    //return_data_offset: Cell<F>,
    //return_data_length: Cell<F>,
    range: MemoryAddressGadget<F>,
   //restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGCodeStoreGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasCodeStore";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasCodeStore;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Use rw_counter of the step which triggers next call as its call_id.
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        let offset = cb.query_cell_phase2();
        let length = cb.query_word_rlc();
        cb.stack_pop(offset.expr());
        cb.stack_pop(length.expr());
        let range = MemoryAddressGadget::construct(cb, offset, length);

        //TODO: constrain code store gas > gas left
        //TODO: restore context

        Self {
            opcode,
            range,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        let is_create2 = opcode == OpcodeId::CREATE2;
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        
        let [memory_offset, length] = [0, 1].map(|i| block.rws[step.rw_indices[i]].stack_value());
        let range = self.range.assign(region, offset, memory_offset, length)?;

        Ok(())
    }
}


#[cfg(test)]
mod test {
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        address, bytecode, evm_types::OpcodeId, geth_types::Account, Address, Bytecode, Word,
    };

    use itertools::Itertools;
    use lazy_static::lazy_static;
    use mock::{eth, TestContext};

    use crate::test_util::CircuitTestBuilder;

    const CALLEE_ADDRESS: Address = Address::repeat_byte(0xff);
    lazy_static! {
        static ref CALLER_ADDRESS: Address = address!("0x00bbccddee000000000000000000000000002400");
    }

    fn run_test_circuits(ctx: TestContext<2, 1>) {
        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_rws: 4500,
                ..Default::default()
            })
            .run();
    }

    // RETURN or REVERT with data of [0x60; 5]
    fn initialization_bytecode(is_success: bool) -> Bytecode {
        let memory_bytes = [0x60; 10];
        let memory_address = 0;
        let memory_value = Word::from_big_endian(&memory_bytes);
        let mut code = bytecode! {
            PUSH10(memory_value)
            PUSH1(memory_address)
            MSTORE
            PUSH2(5) // length to copy
            PUSH2(32u64 - u64::try_from(memory_bytes.len()).unwrap())
        };
        code.write_op(if is_success {
            OpcodeId::RETURN
        } else {
            //OpcodeId::REVERT
            OpcodeId::RETURN
        });
        code
    }

    fn creater_bytecode(
        initialization_bytecode: Bytecode,
        is_create2: bool,
        is_persistent: bool,
    ) -> Bytecode {
        let initialization_bytes = initialization_bytecode.code();
        let mut code = bytecode! {
            PUSH32(Word::from_big_endian(&initialization_bytes))
            PUSH1(0)
            MSTORE
        };
        if is_create2 {
            code.append(&bytecode! {PUSH1(45)}); // salt;
        }
        code.append(&bytecode! {
            PUSH1(initialization_bytes.len()) // size
            PUSH1(32 - initialization_bytes.len()) // length
            PUSH2(23414) // value
        });
        code.write_op(if is_create2 {
            OpcodeId::CREATE2
        } else {
            OpcodeId::CREATE
        });
        if !is_persistent {
            code.append(&bytecode! {
                PUSH1(0)
                PUSH1(0)
                //REVERT
                RETURN
            });
        }
        code
    }

    fn test_context(caller: Account) -> TestContext<2, 1> {
        TestContext::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(eth(10));
                accs[1].account(&caller);
            },
            |mut txs, accs| {
                txs[0]
                    .from(accs[0].address)
                    .to(accs[1].address)
                    .gas(53800u64.into());
            },
            |block, _| block,
        )
        .unwrap()
    }

    #[test]
    fn test_create() {
        // for ((is_success, is_create2), is_persistent) in [true, false]
        //     .iter()
        //     .cartesian_product(&[true, false])
        //     .cartesian_product(&[true, false])
        // {
            let initialization_code = initialization_bytecode(false);
            let root_code = creater_bytecode(initialization_code, false, false);
            let caller = Account {
                address: *CALLER_ADDRESS,
                code: root_code.into(),
                nonce: Word::one(),
                balance: eth(10),
                ..Default::default()
            };
            run_test_circuits(test_context(caller));
       // }
    }

    #[test]
    fn test_create_empty_initialization_code() {
        for is_create2 in [true, false] {
            let caller = Account {
                address: *CALLER_ADDRESS,
                code: creater_bytecode(vec![].into(), is_create2, true).into(),
                nonce: 10.into(),
                balance: eth(10),
                ..Default::default()
            };
            run_test_circuits(test_context(caller));
        }
    }
}
