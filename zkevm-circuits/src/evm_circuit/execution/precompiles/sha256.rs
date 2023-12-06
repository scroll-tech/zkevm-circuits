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
            common_gadget::RestoreContextGadget, constraint_builder::EVMConstraintBuilder,
            math_gadget::ConstantDivisionGadget, rlc, CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

#[derive(Clone, Debug)]
pub struct SHA256Gadget<F> {
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

impl<F: Field> ExecutionGadget<F> for SHA256Gadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileSha256;

    const NAME: &'static str = "SHA256";

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
            GasCost::PRECOMPILE_SHA256_BASE.expr()
                + input_word_size.quotient() * GasCost::PRECOMPILE_SHA256_PER_WORD.expr(),
            cb.curr.state.gas_left.expr(),
        );

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        // sha256 verify lookup
        cb.condition(is_success.expr(), |cb| {
            cb.sha256_table_lookup(
                input_bytes_rlc.expr(),
                call_data_length.expr(),
                output_bytes_rlc.expr(),
            );
        });

        let restore_context = RestoreContextGadget::construct2(
            cb,
            is_success.expr(),
            gas_cost.expr(),
            0.expr(),
            0x00.expr(),                                               // ReturnDataOffset
            select::expr(is_success.expr(), 0x20.expr(), 0x00.expr()), // ReturnDataLength
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
        if let Some(PrecompileAuxData::SHA256 {
            input_bytes,
            output_bytes,
            return_bytes,
        }) = &step.aux_data
        {
            region
                .challenges()
                .keccak_input()
                .map(|r| rlc::value(input_bytes.iter().rev(), r));

            region
                .challenges()
                .keccak_input()
                .map(|r| rlc::value(output_bytes.iter().rev(), r));

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
            log::error!("unexpected aux_data {:?} for sha256", step.aux_data);
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
    use bus_mapping::{
        evm::{OpcodeId, PrecompileCallArgs},
        precompile::PrecompileCalls,
    };
    use eth_types::{bytecode, word, ToWord};
    use itertools::Itertools;
    use mock::TestContext;
    use std::sync::LazyLock;

    use crate::test_util::CircuitTestBuilder;

    static TEST_VECTOR: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
        vec![
            PrecompileCallArgs {
                name: "simple success",
                setup_code: bytecode! {
                    // place params in memory
                    PUSH3(0x616263)
                    PUSH1(0x00)
                    MSTORE
                },
                call_data_offset: 0x1d.into(),
                call_data_length: 0x03.into(),
                ret_offset: 0x20.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Sha256.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "nil success",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 0x00.into(),
                ret_offset: 0x20.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Sha256.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "block edge",
                setup_code: bytecode! {
                    // place params in memory
                    PUSH32(word!("0x6161616161616161616161616161616161616161616161616161616161616161"))
                    PUSH1(0x00)
                    MSTORE
                    PUSH32(word!("0x6161616161616161616161616161616161616161616161616161616161616161"))
                    PUSH1(0x20)
                    MSTORE
                },
                call_data_offset: 0x00.into(),
                call_data_length: 0x40.into(),
                ret_offset: 0x20.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Sha256.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "simple truncated return",
                setup_code: bytecode! {
                    // place params in memory
                    PUSH3(0x616263)
                    PUSH1(0x00)
                    MSTORE
                },
                call_data_offset: 0x1d.into(),
                call_data_length: 0x03.into(),
                ret_offset: 0x20.into(),
                ret_size: 0x10.into(),
                address: PrecompileCalls::Sha256.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "overlapped return",
                setup_code: bytecode! {
                    // place params in memory
                    PUSH3(0x616263)
                    PUSH1(0x00)
                    MSTORE
                },
                call_data_offset: 0x1d.into(),
                call_data_length: 0x03.into(),
                ret_offset: 0x00.into(),
                ret_size: 0x20.into(),
                address: PrecompileCalls::Sha256.address().to_word(),
                ..Default::default()
            },
        ]
    });

    static OOG_TEST_VECTOR: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
        vec![PrecompileCallArgs {
            name: "oog",
            setup_code: bytecode! {
                PUSH32(word!("0x6161616161616161616161616161616161616161616161616161616161616161"))
                PUSH1(0x00)
                MSTORE
                PUSH32(word!("0x6161616161616161616161616161616161616161616161616161616161616161"))
                PUSH1(0x20)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x40.into(),
            ret_offset: 0x20.into(),
            ret_size: 0x20.into(),
            address: PrecompileCalls::Sha256.address().to_word(),
            gas: 20.into(),
            ..Default::default()
        }]
    });

    #[test]
    fn precompile_sha256_common_test() {
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

    // verify nil case is corrected handled in SHA256 event
    #[test]
    fn precompile_sha256_nil_test() {
        let nil_vector = &TEST_VECTOR[1];
        let bytecode = nil_vector.with_call_op(OpcodeId::STATICCALL);

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .block_modifier(Box::new(|blk| {
            let evts = blk.get_sha256();
            assert_eq!(evts.len(), 1);
            assert_eq!(evts[0].input.len(), 0);
        }))
        .run();
    }

    // verify nil case is corrected handled in SHA256 event
    #[test]
    fn precompile_sha256_oog_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        for (test_vector, &call_kind) in OOG_TEST_VECTOR.iter().cartesian_product(&call_kinds) {
            let bytecode = test_vector.with_call_op(call_kind);
            CircuitTestBuilder::new_from_test_ctx(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
            )
            .block_modifier(Box::new(|blk| {
                assert_eq!(blk.get_sha256().len(), 0);
            }))
            .run();
        }
    }
}
