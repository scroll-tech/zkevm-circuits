use bus_mapping::precompile::{PrecompileAuxData, PrecompileCalls};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::{not, select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_MEMORY_ADDRESS,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::LtGadget,
            padding_gadget::PaddingGadget,
            rlc, CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

#[derive(Clone, Debug)]
pub struct EcAddGadget<F> {
    // input bytes RLC.
    input_bytes_rlc: Cell<F>,
    // output bytes RLC.
    output_bytes_rlc: Cell<F>,
    // return bytes RLC.
    return_bytes_rlc: Cell<F>,

    // utility gadgets for right-padding the input bytes.
    pad_right: LtGadget<F, N_BYTES_MEMORY_ADDRESS>,
    padding: PaddingGadget<F>,

    // EC points: P, Q, R
    point_p_x_rlc: Cell<F>,
    point_p_y_rlc: Cell<F>,
    point_q_x_rlc: Cell<F>,
    point_q_y_rlc: Cell<F>,
    point_r_x_rlc: Cell<F>,
    point_r_y_rlc: Cell<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    is_root: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for EcAddGadget<F> {
    const NAME: &'static str = "EC_ADD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileBn256Add;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (
            input_bytes_rlc,
            output_bytes_rlc,
            return_bytes_rlc,
            point_p_x_rlc,
            point_p_y_rlc,
            point_q_x_rlc,
            point_q_y_rlc,
            point_r_x_rlc,
            point_r_y_rlc,
        ) = (
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
        );

        let [is_success, callee_address, is_root, call_data_offset, call_data_length, return_data_offset, return_data_length] =
            [
                CallContextFieldTag::IsSuccess,
                CallContextFieldTag::CalleeAddress,
                CallContextFieldTag::IsRoot,
                CallContextFieldTag::CallDataOffset,
                CallContextFieldTag::CallDataLength,
                CallContextFieldTag::ReturnDataOffset,
                CallContextFieldTag::ReturnDataLength,
            ]
            .map(|tag| cb.call_context(None, tag));

        // all gas sent to this call will be consumed if `is_success == false`.
        let gas_cost = select::expr(
            is_success.expr(),
            GasCost::PRECOMPILE_BN256ADD.expr(),
            cb.curr.state.gas_left.expr(),
        );

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        cb.ecc_table_lookup(
            u64::from(PrecompileCalls::Bn128Add).expr(),
            is_success.expr(),
            point_p_x_rlc.expr(),
            point_p_y_rlc.expr(),
            point_q_x_rlc.expr(),
            point_q_y_rlc.expr(),
            0.expr(), // input_rlc
            point_r_x_rlc.expr(),
            point_r_y_rlc.expr(),
        );
        cb.condition(not::expr(is_success.expr()), |cb| {
            cb.require_zero("R_x == 0", point_r_x_rlc.expr());
            cb.require_zero("R_y == 0", point_r_y_rlc.expr());
        });

        let required_input_len = 128.expr();
        let pad_right = LtGadget::construct(cb, call_data_length.expr(), required_input_len.expr());
        let padding = cb.condition(pad_right.expr(), |cb| {
            PaddingGadget::construct(
                cb,
                input_bytes_rlc.expr(),
                call_data_length.expr(),
                required_input_len,
            )
        });
        cb.condition(not::expr(pad_right.expr()), |cb| {
            cb.require_equal(
                "no padding implies padded bytes == input bytes",
                padding.padded_rlc(),
                input_bytes_rlc.expr(),
            );
        });
        let (r_pow_32, r_pow_64, r_pow_96) = {
            let challenges = cb.challenges().keccak_powers_of_randomness::<16>();
            let r_pow_16 = challenges[15].clone();
            let r_pow_32 = r_pow_16.square();
            let r_pow_64 = r_pow_32.expr().square();
            let r_pow_96 = r_pow_64.expr() * r_pow_32.expr();
            (r_pow_32, r_pow_64, r_pow_96)
        };
        cb.require_equal(
            "input bytes (RLC) = [ p_x | p_y | q_x | q_y ]",
            padding.padded_rlc(),
            (point_p_x_rlc.expr() * r_pow_96)
                + (point_p_y_rlc.expr() * r_pow_64)
                + (point_q_x_rlc.expr() * r_pow_32.expr())
                + point_q_y_rlc.expr(),
        );
        // RLC of output bytes always equals RLC of result elliptic curve point R.
        cb.require_equal(
            "output bytes (RLC) = [ r_x | r_y ]",
            output_bytes_rlc.expr(),
            point_r_x_rlc.expr() * r_pow_32 + point_r_y_rlc.expr(),
        );

        let restore_context = super::gen_restore_context(
            cb,
            is_root.expr(),
            is_success.expr(),
            gas_cost.expr(),
            select::expr(is_success.expr(), 0x40.expr(), 0x00.expr()), // ReturnDataLength
        );

        Self {
            input_bytes_rlc,
            output_bytes_rlc,
            return_bytes_rlc,

            pad_right,
            padding,

            point_p_x_rlc,
            point_p_y_rlc,
            point_q_x_rlc,
            point_q_y_rlc,
            point_r_x_rlc,
            point_r_y_rlc,

            is_success,
            callee_address,
            is_root,
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
        if let Some(PrecompileAuxData::EcAdd(aux_data)) = &step.aux_data {
            let keccak_rand = region.challenges().keccak_input();
            for (col, bytes) in [
                (&self.input_bytes_rlc, &aux_data.input_bytes),
                (&self.output_bytes_rlc, &aux_data.output_bytes),
                (&self.return_bytes_rlc, &aux_data.return_bytes),
            ] {
                col.assign(
                    region,
                    offset,
                    keccak_rand.map(|r| rlc::value(bytes.iter().rev(), r)),
                )?;
            }
            for (col, word_value) in [
                (&self.point_p_x_rlc, aux_data.p_x),
                (&self.point_p_y_rlc, aux_data.p_y),
                (&self.point_q_x_rlc, aux_data.q_x),
                (&self.point_q_y_rlc, aux_data.q_y),
                (&self.point_r_x_rlc, aux_data.r_x),
                (&self.point_r_y_rlc, aux_data.r_y),
            ] {
                col.assign(
                    region,
                    offset,
                    keccak_rand.map(|r| rlc::value(&word_value.to_le_bytes(), r)),
                )?;
            }
            self.pad_right
                .assign(region, offset, call.call_data_length.into(), 128.into())?;
            self.padding.assign(
                region,
                offset,
                PrecompileCalls::Bn128Add,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(aux_data.input_bytes.iter().rev(), r)),
                call.call_data_length,
                region.challenges().keccak_input(),
            )?;
        } else {
            log::error!("unexpected aux_data {:?} for ecAdd", step.aux_data);
            return Err(Error::Synthesis);
        }

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
        self.is_root
            .assign(region, offset, Value::known(F::from(call.is_root as u64)))?;
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
    use rayon::iter::{ParallelBridge, ParallelIterator};
    use std::sync::LazyLock;

    use crate::test_util::CircuitTestBuilder;

    static TEST_VECTOR: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
        vec![
            PrecompileCallArgs {
                name: "ecAdd (valid inputs)",
                // P = (1, 2)
                // Q = (1, 2)
                setup_code: bytecode! {
                        // p_x = 1
                        PUSH1(0x01)
                        PUSH1(0x00)
                        MSTORE
                        // p_y = 2
                        PUSH1(0x02)
                        PUSH1(0x20)
                        MSTORE
                        // q_x = 1
                        PUSH1(0x01)
                        PUSH1(0x40)
                        MSTORE
                        // q_y = 2
                        PUSH1(0x02)
                        PUSH1(0x60)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                call_data_length: 0x80.into(),
                ret_offset: 0x80.into(),
                ret_size: 0x40.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (invalid input: point not on curve)",
                // P = (2, 3)
                // Q = (1, 2)
                setup_code: bytecode! {
                        // p_x = 2
                        PUSH1(0x02)
                        PUSH1(0x00)
                        MSTORE
                        // p_y = 3
                        PUSH1(0x03)
                        PUSH1(0x20)
                        MSTORE
                        // q_x = 1
                        PUSH1(0x01)
                        PUSH1(0x40)
                        MSTORE
                        // q_y = 2
                        PUSH1(0x02)
                        PUSH1(0x60)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                call_data_length: 0x80.into(),
                ret_offset: 0x80.into(),
                ret_size: 0x40.into(),
                gas: 1000.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (valid inputs: truncated byte, input resulting in valid curve point)",
                // P = (1, 2)
                // Q = (q_x, q_y)
                setup_code: bytecode! {
                        // p_x = 1
                        PUSH1(0x01)
                        PUSH1(0x00)
                        MSTORE
                        // p_y = 2
                        PUSH1(0x02)
                        PUSH1(0x20)
                        MSTORE
                        // q_x = 0x0878b7f04b21d2b67978160da1f2740ff4ab143c6193ef0a8ca0f757c0a2c7ad
                        PUSH32(word!("0x0878b7f04b21d2b67978160da1f2740ff4ab143c6193ef0a8ca0f757c0a2c7ad"))
                        PUSH1(0x40)
                        MSTORE
                        // q_y = 0x00a5ad7b42f91a99b266c8a657b5c237b95831904a448e9ae8f5b6ce6a2a1b00
                        PUSH32(word!("0x00a5ad7b42f91a99b266c8a657b5c237b95831904a448e9ae8f5b6ce6a2a1b00"))
                        PUSH1(0x60)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                call_data_length: 0x7f.into(), // the last byte is 0x00 so should be valid.
                ret_offset: 0x80.into(),
                ret_size: 0x40.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (invalid inputs: truncated bytes, input resulting in invalid curve point)",
                // P = (1, 2)
                // Q = (q_x, q_y)
                setup_code: bytecode! {
                        // p_x = 1
                        PUSH1(0x01)
                        PUSH1(0x00)
                        MSTORE
                        // p_y = 2
                        PUSH1(0x02)
                        PUSH1(0x20)
                        MSTORE
                        // q_x = 0x0878b7f04b21d2b67978160da1f2740ff4ab143c6193ef0a8ca0f757c0a2c7ad
                        PUSH32(word!("0x0878b7f04b21d2b67978160da1f2740ff4ab143c6193ef0a8ca0f757c0a2c7ad"))
                        PUSH1(0x40)
                        MSTORE
                        // q_y = 0x00a5ad7b42f91a99b266c8a657b5c237b95831904a448e9ae8f5b6ce6a2a1b00
                        PUSH32(word!("0x00a5ad7b42f91a99b266c8a657b5c237b95831904a448e9ae8f5b6ce6a2a1b00"))
                        PUSH1(0x60)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                // only the last byte is 0x00, so ignoring 2 bytes does not give us point on curve.
                call_data_length: 0x7e.into(),
                ret_offset: 0x80.into(),
                ret_size: 0x40.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (valid inputs: truncated bytes, input resulting in valid curve point)",
                // P = (1, 2)
                // Q = (0, 0) truncated
                setup_code: bytecode! {
                        // p_x = 1
                        PUSH1(0x01)
                        PUSH1(0x00)
                        MSTORE
                        // p_y = 2
                        PUSH1(0x02)
                        PUSH1(0x20)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                call_data_length: 0x40.into(), // q is (0, 0)
                ret_offset: 0x40.into(),
                ret_size: 0x40.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (should succeed on empty inputs)",
                setup_code: bytecode! {},
                call_data_offset: 0x00.into(),
                call_data_length: 0x00.into(),
                ret_offset: 0x00.into(),
                ret_size: 0x40.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (valid inputs > 128 bytes)",
                // P = (1, 2)
                // Q = (1, 2)
                setup_code: bytecode! {
                        // p_x = 1
                        PUSH1(0x01)
                        PUSH1(0x00)
                        MSTORE
                        // p_y = 2
                        PUSH1(0x02)
                        PUSH1(0x20)
                        MSTORE
                        // q_x = 1
                        PUSH1(0x01)
                        PUSH1(0x40)
                        MSTORE
                        // q_y = 2
                        PUSH1(0x02)
                        PUSH1(0x60)
                        MSTORE
                        // junk bytes, will be truncated
                        PUSH32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128)
                        PUSH1(0x80)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                call_data_length: 0x80.into(),
                ret_offset: 0x80.into(),
                ret_size: 0x40.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (invalid input: must mod p to be valid)",
                // P = (p + 1, p + 2)
                // Q = (1, 2)
                setup_code: bytecode! {
                        // p_x
                        PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD48"))
                        PUSH1(0x00)
                        MSTORE
                        // p_y
                        PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49"))
                        PUSH1(0x20)
                        MSTORE
                        // q_x = 1
                        PUSH1(0x01)
                        PUSH1(0x40)
                        MSTORE
                        // q_y = 2
                        PUSH1(0x02)
                        PUSH1(0x60)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                call_data_length: 0x80.into(),
                ret_offset: 0x80.into(),
                ret_size: 0x00.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (valid inputs: P == -Q)",
                // P = (1, 2)
                // Q = -P
                setup_code: bytecode! {
                        // p_x
                        PUSH1(0x01)
                        PUSH1(0x00)
                        MSTORE
                        // p_y
                        PUSH1(0x02)
                        PUSH1(0x20)
                        MSTORE
                        // q_x = 1
                        PUSH1(0x01)
                        PUSH1(0x40)
                        MSTORE
                        // q_y = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
                        PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                        PUSH1(0x60)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                call_data_length: 0x80.into(),
                ret_offset: 0x80.into(),
                ret_size: 0x40.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
            PrecompileCallArgs {
                name: "ecAdd (valid inputs: P == -Q), return size == 0",
                // P = (1, 2)
                // Q = -P
                setup_code: bytecode! {
                        // p_x
                        PUSH1(0x01)
                        PUSH1(0x00)
                        MSTORE
                        // p_y
                        PUSH1(0x02)
                        PUSH1(0x20)
                        MSTORE
                        // q_x = 1
                        PUSH1(0x01)
                        PUSH1(0x40)
                        MSTORE
                        // q_y = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
                        PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                        PUSH1(0x60)
                        MSTORE
                    },
                call_data_offset: 0x00.into(),
                call_data_length: 0x80.into(),
                ret_offset: 0x80.into(),
                ret_size: 0x00.into(),
                address: PrecompileCalls::Bn128Add.address().to_word(),
                ..Default::default()
            },
        ]
    });

    static OOG_TEST_VECTOR: LazyLock<Vec<PrecompileCallArgs>> = LazyLock::new(|| {
        vec![PrecompileCallArgs {
            name: "ecAdd OOG (valid inputs: P == -Q), return size == 0",
            // P = (1, 2)
            // Q = -P
            setup_code: bytecode! {
                // p_x
                PUSH1(0x01)
                PUSH1(0x00)
                MSTORE
                // p_y
                PUSH1(0x02)
                PUSH1(0x20)
                MSTORE
                // q_x = 1
                PUSH1(0x01)
                PUSH1(0x40)
                MSTORE
                // q_y = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45
                PUSH32(word!("0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"))
                PUSH1(0x60)
                MSTORE
            },
            call_data_offset: 0x00.into(),
            call_data_length: 0x80.into(),
            ret_offset: 0x80.into(),
            ret_size: 0x00.into(),
            address: PrecompileCalls::Bn128Add.address().to_word(),
            gas: 149.into(),
            ..Default::default()
        }]
    });

    #[test]
    fn precompile_ec_add_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        TEST_VECTOR
            .iter()
            .cartesian_product(&call_kinds)
            //.par_bridge()
            .for_each(|(test_vector, &call_kind)| {
                let bytecode = test_vector.with_call_op(call_kind);
                log::info!("TESTING {}", test_vector.name);

                CircuitTestBuilder::new_from_test_ctx(
                    TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                )
                .run();
            })
    }

    #[test]
    fn precompile_ec_add_oog_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        OOG_TEST_VECTOR
            .iter()
            .cartesian_product(&call_kinds)
            .par_bridge()
            .for_each(|(test_vector, &call_kind)| {
                let bytecode = test_vector.with_call_op(call_kind);

                CircuitTestBuilder::new_from_test_ctx(
                    TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                )
                .run();
            })
    }
}
