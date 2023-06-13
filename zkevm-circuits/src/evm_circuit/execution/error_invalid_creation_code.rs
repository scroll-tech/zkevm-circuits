use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::EVMConstraintBuilder,
            from_bytes,
            math_gadget::IsEqualGadget,
            memory_gadget::{CommonMemoryAddressGadget, MemoryAddressGadget, MemoryWordAddress},
            CachedRegion, Cell, RandomLinearCombination, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use eth_types::{Field, ToLittleEndian};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget for code store oog and max code size exceed
#[derive(Clone, Debug)]
pub(crate) struct ErrorInvalidCreationCodeGadget<F> {
    opcode: Cell<F>,
    memory_address: MemoryWordAddress<F>,
    length: RandomLinearCombination<F, N_BYTES_MEMORY_ADDRESS>,
    value_left: Word<F>,
    first_byte: Cell<F>,
    is_first_byte_invalid: IsEqualGadget<F>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorInvalidCreationCodeGadget<F> {
    const NAME: &'static str = "ErrorInvalidCreationCode";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorInvalidCreationCode;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let first_byte = cb.query_cell();

        //let address = cb.query_word_rlc();

        let offset = cb.query_word_rlc();
        let length = cb.query_word_rlc();
        let value_left = cb.query_word_rlc();

        cb.stack_pop(offset.expr());
        cb.stack_pop(length.expr());
        cb.require_true("is_create is true", cb.curr.state.is_create.expr());

        let address_word = MemoryWordAddress::construct(cb, offset.clone());
        // lookup memory for first word
        cb.memory_lookup_word(0.expr(), address_word.addr_left(), value_left.expr(), None);
        // let first_byte = value_left.cells[address_word.shift()];
        // constrain first byte is 0xef
        let is_first_byte_invalid = IsEqualGadget::construct(cb, first_byte.expr(), 0xef.expr());

        cb.require_true(
            "is_first_byte_invalid is true",
            is_first_byte_invalid.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct_with_lastcallee_return_data(
            cb,
            opcode.expr(),
            5.expr(),
            from_bytes::expr(&offset.cells[..N_BYTES_MEMORY_ADDRESS]),
            from_bytes::expr(&length.cells[..N_BYTES_MEMORY_ADDRESS]),
        );

        Self {
            opcode,
            is_first_byte_invalid,
            first_byte,
            memory_address: address_word,
            length,
            value_left,
            common_error_gadget,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let [memory_offset, length] = [0, 1].map(|i| block.rws[step.rw_indices[i]].stack_value());
        self.memory_address.assign(
            region,
            offset,
            Some(
                memory_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        self.length.assign(
            region,
            offset,
            Some(
                length.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

        let word_left = block.rws[step.rw_indices[2]].memory_word_value();
        self.value_left
            .assign(region, offset, Some(word_left.to_le_bytes()))?;

        let bytes = word_left.to_le_bytes();
        let first_byte: u8 = bytes[0];

        self.first_byte
            .assign(region, offset, Value::known(F::from(first_byte as u64)))?;
        self.is_first_byte_invalid.assign(
            region,
            offset,
            F::from(first_byte as u64),
            F::from(0xef_u64),
        )?;

        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        address, bytecode, evm_types::OpcodeId, geth_types::Account, Address, Bytecode, Word,
    };

    use lazy_static::lazy_static;
    use mock::{eth, TestContext, MOCK_ACCOUNTS};

    use crate::test_util::CircuitTestBuilder;

    const CALLEE_ADDRESS: Address = Address::repeat_byte(0xff);
    lazy_static! {
        static ref CALLER_ADDRESS: Address = address!("0x00bbccddee000000000000000000000000002400");
    }

    const MAXCODESIZE: u64 = 0x6000u64;

    fn run_test_circuits(ctx: TestContext<2, 1>) {
        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_rws: 4500,
                ..Default::default()
            })
            .run();
    }

    fn initialization_bytecode() -> Bytecode {
        let memory_bytes = [0xef; 10];
        let memory_value = Word::from_big_endian(&memory_bytes);

        let mut code = bytecode! {
            PUSH10(memory_value)
            PUSH32(0)
            MSTORE
            PUSH2( 5 ) // length to copy
            PUSH2(32u64 - u64::try_from(memory_bytes.len()).unwrap()) // offset
            //PUSH2(0x00) // offset

        };
        code.write_op(OpcodeId::RETURN);

        code
    }

    fn creator_bytecode(initialization_bytecode: Bytecode, is_create2: bool) -> Bytecode {
        let initialization_bytes = initialization_bytecode.code();
        let mut code = Bytecode::default();

        // construct maxcodesize + 1 memory bytes
        let code_creator: Vec<u8> = initialization_bytes
            .to_vec()
            .iter()
            .cloned()
            .chain(0u8..((32 - initialization_bytes.len() % 32) as u8))
            .collect();
        for (index, word) in code_creator.chunks(32).enumerate() {
            code.push(32, Word::from_big_endian(word));
            code.push(32, Word::from(index * 32));
            code.write_op(OpcodeId::MSTORE);
        }

        if is_create2 {
            code.append(&bytecode! {PUSH1(45)}); // salt;
        }
        code.append(&bytecode! {
            PUSH32(initialization_bytes.len()) // size
            PUSH2(0x00) // offset
            PUSH2(23414) // value
        });
        code.write_op(if is_create2 {
            OpcodeId::CREATE2
        } else {
            OpcodeId::CREATE
        });
        code.append(&bytecode! {
            PUSH1(0)
            PUSH1(0)
            RETURN
        });

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
                    .gas(103800u64.into());
            },
            |block, _| block,
        )
        .unwrap()
    }

    #[test]
    fn test_invalid_creation_code() {
        for is_create2 in [false, true] {
            let initialization_code = initialization_bytecode();
            let root_code = creator_bytecode(initialization_code, is_create2);
            let caller = Account {
                address: *CALLER_ADDRESS,
                code: root_code.into(),
                nonce: Word::one(),
                balance: eth(10),
                ..Default::default()
            };
            run_test_circuits(test_context(caller));
        }
    }

    // add tx deploy case for invalid creation code.
    #[test]
    fn test_tx_deploy_invalid_creation_code() {
        let code = initialization_bytecode();

        let ctx = TestContext::<1, 1>::new(
            None,
            |accs| {
                accs[0].address(MOCK_ACCOUNTS[0]).balance(eth(20));
            },
            |mut txs, _accs| {
                txs[0]
                    .from(MOCK_ACCOUNTS[0])
                    .gas(53446u64.into())
                    .value(eth(2))
                    .input(code.into());
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
