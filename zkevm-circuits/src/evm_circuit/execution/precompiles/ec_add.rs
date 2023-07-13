use bus_mapping::precompile::{PrecompileAuxData, PrecompileCalls};
use eth_types::{Field, ToLittleEndian, ToScalar};
use gadgets::util::{and, not, or, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::IsZeroGadget,
            rlc, CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

#[derive(Clone, Debug)]
pub struct EcAddGadget<F> {
    point_p_x_rlc: Cell<F>,
    point_p_y_rlc: Cell<F>,
    point_q_x_rlc: Cell<F>,
    point_q_y_rlc: Cell<F>,
    point_r_x_rlc: Cell<F>,
    point_r_y_rlc: Cell<F>,

    p_x_is_zero: IsZeroGadget<F>,
    p_y_is_zero: IsZeroGadget<F>,
    q_x_is_zero: IsZeroGadget<F>,
    q_y_is_zero: IsZeroGadget<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
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
        );

        let p_x_is_zero = IsZeroGadget::construct(cb, "ecAdd(P_x)", point_p_x_rlc.expr());
        let p_y_is_zero = IsZeroGadget::construct(cb, "ecAdd(P_y)", point_p_y_rlc.expr());
        let q_x_is_zero = IsZeroGadget::construct(cb, "ecAdd(Q_x)", point_q_x_rlc.expr());
        let q_y_is_zero = IsZeroGadget::construct(cb, "ecAdd(Q_y)", point_q_y_rlc.expr());

        let p_is_zero = and::expr([p_x_is_zero.expr(), p_y_is_zero.expr()]);
        let q_is_zero = and::expr([q_x_is_zero.expr(), q_y_is_zero.expr()]);

        cb.condition(and::expr([p_is_zero.expr(), q_is_zero.expr()]), |cb| {
            cb.require_zero("if P == 0 && Q == 0 then R_x == 0", point_r_x_rlc.expr());
            cb.require_zero("if P == 0 && Q == 0 then R_y == 0", point_r_y_rlc.expr());
        });
        cb.condition(
            and::expr([p_is_zero.expr(), not::expr(q_is_zero.expr())]),
            |cb| {
                cb.require_equal(
                    "if P == 0 then R_x == Q_x",
                    point_r_x_rlc.expr(),
                    point_q_x_rlc.expr(),
                );
                cb.require_equal(
                    "if P == 0 then R_y == Q_y",
                    point_r_y_rlc.expr(),
                    point_q_y_rlc.expr(),
                );
            },
        );
        cb.condition(
            and::expr([q_is_zero.expr(), not::expr(p_is_zero.expr())]),
            |cb| {
                cb.require_equal(
                    "if Q == 0 then R_x == P_x",
                    point_r_x_rlc.expr(),
                    point_p_x_rlc.expr(),
                );
                cb.require_equal(
                    "if Q == 0 then R_y == P_y",
                    point_r_y_rlc.expr(),
                    point_p_y_rlc.expr(),
                );
            },
        );

        cb.condition(
            not::expr(or::expr([p_is_zero.expr(), q_is_zero.expr()])),
            |cb| {
                cb.ecc_table_lookup(
                    u64::from(PrecompileCalls::Bn128Add).expr(),
                    point_p_x_rlc.expr(),
                    point_p_y_rlc.expr(),
                    point_q_x_rlc.expr(),
                    point_q_y_rlc.expr(),
                    0.expr(), // input_rlc
                    point_r_x_rlc.expr(),
                    point_r_y_rlc.expr(),
                );
            },
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

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        let restore_context = RestoreContextGadget::construct(
            cb,
            is_success.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
            0.expr(),
        );

        Self {
            point_p_x_rlc,
            point_p_y_rlc,
            point_q_x_rlc,
            point_q_y_rlc,
            point_r_x_rlc,
            point_r_y_rlc,

            p_x_is_zero,
            p_y_is_zero,
            q_x_is_zero,
            q_y_is_zero,

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
        if let Some(PrecompileAuxData::EcAdd(aux_data)) = &step.aux_data {
            let keccak_rand = region.challenges().keccak_input();
            for (col, is_zero_gadget, word_value) in [
                (&self.point_p_x_rlc, &self.p_x_is_zero, aux_data.p_x),
                (&self.point_p_y_rlc, &self.p_y_is_zero, aux_data.p_y),
                (&self.point_q_x_rlc, &self.q_x_is_zero, aux_data.q_x),
                (&self.point_q_y_rlc, &self.q_y_is_zero, aux_data.q_y),
            ] {
                let rlc_val = keccak_rand.map(|r| rlc::value(&word_value.to_le_bytes(), r));
                col.assign(region, offset, rlc_val)?;
                is_zero_gadget.assign_value(region, offset, rlc_val)?;
            }
            for (col, word_value) in [
                (&self.point_r_x_rlc, aux_data.r_x),
                (&self.point_r_y_rlc, aux_data.r_y),
            ] {
                col.assign(
                    region,
                    offset,
                    keccak_rand.map(|r| rlc::value(&word_value.to_le_bytes(), r)),
                )?;
            }
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
    use rayon::iter::{ParallelBridge, ParallelIterator};

    use crate::test_util::CircuitTestBuilder;

    lazy_static::lazy_static! {
        static ref TEST_VECTOR: Vec<PrecompileCallArgs> = {
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
            ]
        };
    }

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
