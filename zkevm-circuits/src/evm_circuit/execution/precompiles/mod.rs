use eth_types::{Field, ToScalar};
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget, constraint_builder::EVMConstraintBuilder,
            CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

#[derive(Clone, Debug)]
pub struct BasePrecompileGadget<F, const S: ExecutionState> {
    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field, const S: ExecutionState> ExecutionGadget<F> for BasePrecompileGadget<F, S> {
    const EXECUTION_STATE: ExecutionState = S;

    const NAME: &'static str = "BASE_PRECOMPILE";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let [is_success, callee_address, caller_id, call_data_offset, call_data_length, return_data_offset, return_data_length] =
            [
                CallContextFieldTag::IsSuccess,
                CallContextFieldTag::CalleeAddress,
                CallContextFieldTag::CallerId,
                CallContextFieldTag::CallDataOffset,
                CallContextFieldTag::CallDataLength,
                CallContextFieldTag::ReturnDataOffset,
                CallContextFieldTag::ReturnDataLength,
            ]
            .map(|tag| cb.call_context(None, tag));

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        let restore_context = RestoreContextGadget::construct(
            cb,
            true.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
        );

        Self {
            is_success,
            callee_address,
            caller_id,
            call_data_offset,
            call_data_length,
            return_data_offset,
            return_data_length,
            restore_context,
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
        self.is_success.assign(
            region,
            offset,
            Value::known(F::from(u64::from(call.is_success))),
        )?;
        self.callee_address.assign(
            region,
            offset,
            Value::known(call.code_address.unwrap().to_scalar().unwrap()),
        )?;
        self.caller_id
            .assign(region, offset, Value::known(F::from(call.caller_id as u64)))?;
        self.call_data_offset.assign(
            region,
            offset,
            Value::known(F::from(call.call_data_offset)),
        )?;
        self.call_data_length.assign(
            region,
            offset,
            Value::known(F::from(call.call_data_length)),
        )?;
        self.return_data_offset.assign(
            region,
            offset,
            Value::known(F::from(call.return_data_offset)),
        )?;
        self.return_data_length.assign(
            region,
            offset,
            Value::known(F::from(call.return_data_length)),
        )?;

        self.restore_context
            .assign(region, offset, block, call, step, 7)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use bus_mapping::{
        evm::{OpcodeId, PrecompileCallArgs},
        precompile::PrecompileCalls,
    };
    use eth_types::{bytecode, word, ToWord};
    use itertools::Itertools;
    use mock::TestContext;

    use crate::test_util::CircuitTestBuilder;

    lazy_static::lazy_static! {
        static ref TEST_VECTOR: Vec<PrecompileCallArgs> = {
            vec![
                PrecompileCallArgs {
                    name: "single-byte success",
                    setup_code: bytecode! {
                        // place params in memory
                        PUSH1(0xff)
                        PUSH1(0x00)
                        MSTORE
                    },
                    call_data_offset: 0x1f.into(),
                    call_data_length: 0x01.into(),
                    ret_offset: 0x3f.into(),
                    ret_size: 0x01.into(),
                    address: PrecompileCalls::Identity.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "multi-bytes success (less than 32 bytes)",
                    setup_code: bytecode! {
                        // place params in memory
                        PUSH16(word!("0x0123456789abcdef0f1e2d3c4b5a6978"))
                        PUSH1(0x00)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x10.into(),
                    ret_offset: 0x20.into(),
                    ret_size: 0x10.into(),
                    address: PrecompileCalls::Identity.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "multi-bytes success (more than 32 bytes)",
                    setup_code: bytecode! {
                        // place params in memory
                        PUSH30(word!("0x0123456789abcdef0f1e2d3c4b5a6978"))
                        PUSH1(0x00) // place from 0x00 in memory
                        MSTORE
                        PUSH30(word!("0xaabbccdd001122331039abcdefefef84"))
                        PUSH1(0x20) // place from 0x20 in memory
                        MSTORE
                    },
                    // copy 63 bytes from memory addr 0
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x3f.into(),
                    // return only 35 bytes and write from memory addr 72
                    ret_offset: 0x48.into(),
                    ret_size: 0x23.into(),
                    address: PrecompileCalls::Identity.address().to_word(),
                    ..Default::default()
                },
                /* TODO(rohit): debug error cases
                PrecompileCallArgs {
                    name: "insufficient gas (precompile call should fail)",
                    setup_code: bytecode! {
                        // place params in memory
                        PUSH16(word!("0x0123456789abcdef0f1e2d3c4b5a6978"))
                        PUSH1(0x00)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x10.into(),
                    ret_offset: 0x20.into(),
                    ret_size: 0x10.into(),
                    address: PrecompileCalls::Identity.address().to_word(),
                    // set gas to be insufficient
                    gas: 1.into(),
                    ..Default::default()
                },
                */
            ]
        };
    }

    #[test]
    fn precompile_identity_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        for (test_vector, &call_kind) in TEST_VECTOR.iter().cartesian_product(&call_kinds) {
            let bytecode = test_vector.with_call_op(call_kind);

            CircuitTestBuilder::new_from_test_ctx(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
            )
            .run();
        }
    }
}
