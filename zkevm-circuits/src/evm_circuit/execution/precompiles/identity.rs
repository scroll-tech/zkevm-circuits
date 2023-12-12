use bus_mapping::precompile::PrecompileAuxData;
use eth_types::{evm_types::GasCost, Field, ToScalar};
use gadgets::util::{select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_WORD_SIZE, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::ConstantDivisionGadget,
            rlc, CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

#[derive(Clone, Debug)]
pub struct IdentityGadget<F> {
    input_bytes_rlc: Cell<F>,
    output_bytes_rlc: Cell<F>,
    return_bytes_rlc: Cell<F>,

    input_word_size: ConstantDivisionGadget<F, N_BYTES_MEMORY_WORD_SIZE>,
    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for IdentityGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileIdentity;

    const NAME: &'static str = "IDENTITY";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (input_bytes_rlc, output_bytes_rlc, return_bytes_rlc) = (
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
        );
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

        let input_word_size = ConstantDivisionGadget::construct(
            cb,
            call_data_length.expr() + (N_BYTES_WORD - 1).expr(),
            N_BYTES_WORD as u64,
        );

        let gas_cost = select::expr(
            is_success.expr(),
            GasCost::PRECOMPILE_IDENTITY_BASE.expr()
                + input_word_size.quotient() * GasCost::PRECOMPILE_IDENTITY_PER_WORD.expr(),
            cb.curr.state.gas_left.expr(),
        );

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        cb.require_equal(
            "input and output bytes are the same",
            input_bytes_rlc.expr(),
            output_bytes_rlc.expr(),
        );

        let restore_context = RestoreContextGadget::construct2(
            cb,
            is_success.expr(),
            gas_cost.expr(),
            0.expr(),
            0x00.expr(),             // ReturnDataOffset
            call_data_length.expr(), // ReturnDataLength
            0.expr(),
            0.expr(),
        );

        Self {
            input_bytes_rlc,
            output_bytes_rlc,
            return_bytes_rlc,

            input_word_size,
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
        if let Some(PrecompileAuxData::Identity {
            input_bytes,
            output_bytes,
            return_bytes,
        }) = &step.aux_data
        {
            self.input_bytes_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(input_bytes.iter().rev(), r)),
            )?;
            self.output_bytes_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(output_bytes.iter().rev(), r)),
            )?;
            self.return_bytes_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(return_bytes.iter().rev(), r)),
            )?;
        } else {
            log::error!("unexpected aux_data {:?} for identity", step.aux_data);
            return Err(Error::Synthesis);
        }
        self.input_word_size.assign(
            region,
            offset,
            (call.call_data_length + (N_BYTES_WORD as u64) - 1).into(),
        )?;
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
            .assign(region, offset, block, call, step, 7)
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::{
        evm::{OpcodeId, PrecompileCallArgs},
        precompile::PrecompileCalls,
    };
    use eth_types::{bytecode, word, ToWord};
    use itertools::Itertools;
    use mock::TestContext;
    use std::sync::LazyLock;

    static TEST_VECTOR: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
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
        ]
    });

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
