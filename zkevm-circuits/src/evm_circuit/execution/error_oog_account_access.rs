use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_GAS},
        step::ExecutionState,
        util::{
            common_gadget::CommonErrorGadget,
            constraint_builder::ConstraintBuilder,
            from_bytes,
            math_gadget::{ByteSizeGadget, LtGadget},
            select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{
    evm_types::{GasCost, OpcodeId},
    Field, ToLittleEndian,
};
use halo2_proofs::{circuit::Value, plonk::Error};

/// Gadget to implement the corresponding out of gas errors for
/// [`OpcodeId::EXP`].
#[derive(Clone, Debug)]
pub(crate) struct ErrorOOGAccountAccessGadget<F> {
    opcode: Cell<F>,
    address_word: Word<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    insufficient_gas_cost: LtGadget<F, N_BYTES_GAS>,
    common_error_gadget: CommonErrorGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorOOGAccountAccessGadget<F> {
    const NAME: &'static str = "ErrorOutOfGasAccountAccess";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorOutOfGasAccountAccess;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let address_word = cb.query_word_rlc();
        let address = from_bytes::expr(&address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);
        cb.stack_pop(address_word.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let is_warm = cb.query_bool();
        // TODO：change to read
        cb.account_access_list_read(tx_id.expr(), address.expr(), is_warm.expr());

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let insufficient_gas_cost = LtGadget::construct(
            cb,
            cb.curr.state.gas_left.expr(),
            // static_gas = 10
            // gas_cost = dynamic_gas + static_gas
            gas_cost,
        );

        cb.require_equal(
            "Gas left is less than gas cost",
            insufficient_gas_cost.expr(),
            1.expr(),
        );

        let common_error_gadget = CommonErrorGadget::construct(cb, opcode.expr(), 5.expr());
        Self {
            opcode,
            address_word,
            tx_id,
            is_warm,
            insufficient_gas_cost,
            common_error_gadget,
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
        let [base, exponent] = [0, 1].map(|idx| block.rws[step.rw_indices[idx]].stack_value());

        log::debug!(
            "ErrorOutOfGasEXP: gas_left = {}, gas_cost = {}",
            step.gas_left,
            step.gas_cost,
        );

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        let address = block.rws[step.rw_indices[0]].stack_value();
        self.address_word
            .assign(region, offset, Some(address.to_le_bytes()))?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;

        let (_, is_warm) = block.rws[step.rw_indices[2]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm)))?;

        self.insufficient_gas_cost.assign_value(
            region,
            offset,
            Value::known(F::from(step.gas_left)),
            Value::known(F::from(step.gas_cost)),
        )?;
        self.common_error_gadget
            .assign(region, offset, block, call, step, 5)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        evm_circuit::test::{rand_bytes, rand_word},
        test_util::CircuitTestBuilder,
    };
    use bus_mapping::{evm::Opcode, state_db::Account};
    use eth_types::{
        bytecode,
        evm_types::{GasCost, OpcodeId},
        Bytecode, ToWord, U256,
    };
    use mock::{
        eth, test_ctx::helpers::account_0_code_account_1_no_code, TestContext, MOCK_ACCOUNTS,
    };

    #[test]
    fn test_oog_exp() {
        [
            OpcodeId::BALANCE,
            //TODO: add extcodehash, extcodesize
        ]
        .into_iter()
        .for_each(|opcode| {
            let testing_data = TestingData::new(opcode);

            test_root(&testing_data);
            test_internal(&testing_data);
        })
    }

    struct TestingData {
        bytecode: Bytecode,
        gas_cost: u64,
    }

    impl TestingData {
        pub fn new(opcode: OpcodeId) -> Self {
            //let account = Account.
            let bytecode = bytecode! {
                PUSH32(rand_word()) // random address
                BALANCE
            };

            let gas_cost = OpcodeId::BALANCE.constant_gas_cost().0 * 2

            Self { bytecode, gas_cost }
        }
    }

    fn test_root(testing_data: &TestingData) {
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(testing_data.bytecode.clone()),
            |mut txs, accs| {
                // Decrease expected gas cost (by 1) to trigger out of gas error.
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas((GasCost::TX.0 + testing_data.gas_cost - 1).into());
            },
            |block, _tx| block.number(0xcafe_u64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_internal(testing_data: &TestingData) {
        let (addr_a, addr_b) = (MOCK_ACCOUNTS[0], MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let code_b = testing_data.bytecode.clone();
        let gas_cost_b = testing_data.gas_cost;

        // Code A calls code B.
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(U256::from_big_endian(&rand_bytes(8)))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(0x00) // argsLength
            PUSH32(0x20) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            // Decrease expected gas cost (by 1) to trigger out of gas error.
            PUSH32(gas_cost_b - 1) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                accs[2].address(MOCK_ACCOUNTS[2]).balance(eth(10));
            },
            |mut txs, accs| {
                txs[0].from(accs[2].address).to(accs[1].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
