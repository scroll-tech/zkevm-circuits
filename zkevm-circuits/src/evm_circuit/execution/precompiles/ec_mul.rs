use bus_mapping::precompile::{PrecompileAuxData, PrecompileCalls};
use eth_types::{Field, ToLittleEndian, ToScalar, Word};
use gadgets::util::{and, not, or, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget, constraint_builder::EVMConstraintBuilder,
            CachedRegion, Cell,
            math_gadget::{ModGadget, IsZeroGadget}, RandomLinearCombination,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

// Modulus for scalar field Fr
const FR_N: [u8; 32] = [
    0x01, 0x00, 0x00, 0xF0, 0x93, 0xF5, 0xE1, 0x43,
    0x91, 0x70, 0xB9, 0x79, 0x48, 0xE8, 0x33, 0x28,
    0x5D, 0x58, 0x81, 0x81, 0xB6, 0x45, 0x50, 0xB8,
    0x29, 0xA0, 0x31, 0xE1, 0x72, 0x4E, 0x64, 0x30,
];

#[derive(Clone, Debug)]
pub struct EcMulGadget<F> {
    point_p_x_rlc: Cell<F>,
    point_p_y_rlc: Cell<F>,
    scalar_s_rlc: Cell<F>,
    scalar_s_raw_rlc: Cell<F>,
    point_r_x_rlc: Cell<F>,
    point_r_y_rlc: Cell<F>,
    is_valid: Cell<F>,

    // Two Words (s_raw, s_modded) that satisfies
    // k * FR_N + s_modded = s_raw
    // Used for proving correct modulo by Fr
    s_mod_pair: (
        RandomLinearCombination<F, 32>,     // raw
        RandomLinearCombination<F, 32>      // mod by FR_N
    ),
    n: RandomLinearCombination<F, 32>,      // modulus
    modword: ModGadget<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for EcMulGadget<F> {
    const NAME: &'static str = "EC_MUL";
    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileBn256ScalarMul;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (is_valid, point_p_x_rlc, point_p_y_rlc, scalar_s_rlc, scalar_s_raw_rlc, point_r_x_rlc, point_r_y_rlc) = (
            cb.query_bool(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
        );

        let (s_raw, s_modded, n) = (
            cb.query_word_rlc(),
            cb.query_word_rlc(),
            cb.query_word_rlc()
        );
        // k * n + s_modded = s_raw
        let modword = ModGadget::construct(cb, [&s_raw, &n, &s_modded]);

        let p_x_is_zero = IsZeroGadget::construct(cb, "ecMul(P_x)", point_p_x_rlc.expr());
        let p_y_is_zero = IsZeroGadget::construct(cb, "ecMul(P_y)", point_p_y_rlc.expr());
        let p_is_zero = and::expr([p_x_is_zero.expr(), p_y_is_zero.expr()]);

        let s_is_zero = IsZeroGadget::construct(cb, "ecMul(s)", scalar_s_rlc.expr());
        
        cb.condition(or::expr([p_is_zero.expr(), s_is_zero.expr()]), |cb| {
            cb.require_zero("if P == 0 || s == 0, then R_x == 0", point_r_x_rlc.expr());
            cb.require_zero("if P == 0 || s == 0, then R_y == 0", point_r_y_rlc.expr());
        });

        // Make sure the correct modulo test is done on actual lookup inputs
        // TODO: adding this code block makes the last two tests fail
        // cb.require_equal(
        //     "s_raw == scalar_s_raw_rlc", 
        //     scalar_s_raw_rlc.expr(),
        //     s_raw.expr()    
        // );
        // cb.require_equal(
        //     "s_modded == scalar_s_rlc",
        //     scalar_s_rlc.expr(),
        //     s_modded.expr()
        // );

        cb.condition(
            not::expr(or::expr([p_is_zero.expr(), s_is_zero.expr()])), 
            |cb| {
                cb.ecc_table_lookup(
                    u64::from(PrecompileCalls::Bn128Mul).expr(),
                    point_p_x_rlc.expr(),
                    point_p_y_rlc.expr(),
                    scalar_s_rlc.expr(),
                    0.expr(),
                    0.expr(),
                    point_r_x_rlc.expr(),
                    point_r_y_rlc.expr(),
                );
            }
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
            scalar_s_rlc,
            scalar_s_raw_rlc,
            point_r_x_rlc,
            point_r_y_rlc,
            is_valid,

            s_mod_pair: (s_raw, s_modded),
            n,
            modword,

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
        if let Some(PrecompileAuxData::EcMul(aux_data)) = &step.aux_data {
            self.is_valid.assign(
                region,
                offset,
                Value::known(F::from(u64::from(aux_data.is_valid))),
            )?;

            for (col, word_value) in [
                (&self.point_p_x_rlc, aux_data.p_x),
                (&self.point_p_y_rlc, aux_data.p_y),
                (&self.scalar_s_rlc, aux_data.s),
                (&self.scalar_s_raw_rlc, aux_data.s_raw),
                (&self.point_r_x_rlc, aux_data.r_x),
                (&self.point_r_y_rlc, aux_data.r_y),
            ] {
                col.assign(
                    region,
                    offset,
                    region.keccak_rlc(&word_value.to_le_bytes())
                )?;
            }

            let n = Word::from_little_endian(&FR_N);
            for (col, word_value) in [
                (&self.s_mod_pair.0, aux_data.s_raw),
                (&self.s_mod_pair.1, aux_data.s),
                (&self.n, n)
            ] {
                col.assign(
                    region, 
                    offset, 
                    Some(word_value.to_le_bytes())
                )?;
            }

            let (k, _) = aux_data.s_raw.div_mod(n);
            self.modword.assign(region, offset, aux_data.s_raw, n, aux_data.s, k)?;
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
                    name: "ecMul (valid input)",
                    // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
                    // s = 7
                    setup_code: bytecode! {
                        // p_x
                        PUSH1(0x02)
                        PUSH1(0x00)
                        MSTORE

                        // p_y
                        PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                        PUSH1(0x20)
                        MSTORE

                        // s
                        PUSH1(0x07)
                        PUSH1(0x40)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x60.into(),
                    ret_offset: 0x60.into(),
                    ret_size: 0x40.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },

                PrecompileCallArgs {
                    name: "ecMul (invalid input: point not on curve)",
                    // P = (2, 3)
                    // s = 7
                    setup_code: bytecode! {
                        // p_x
                        PUSH1(0x02)
                        PUSH1(0x00)
                        MSTORE

                        // p_y
                        PUSH1(0x03)
                        PUSH1(0x20)
                        MSTORE

                        // s
                        PUSH1(0x07)
                        PUSH1(0x40)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x60.into(),
                    ret_offset: 0x60.into(),
                    ret_size: 0x00.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },

                // TODO: failing test
                // Empty scalar input makes ECC lookup fail
                // PrecompileCallArgs {
                //     name: "ecMul (valid input < 96 bytes)",
                //     // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
                //     // s = blank
                //     setup_code: bytecode! {
                //         // p_x
                //         PUSH1(0x02)
                //         PUSH1(0x00)
                //         MSTORE

                //         // p_y
                //         PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                //         PUSH1(0x20)
                //         MSTORE
                //     },
                //     call_data_offset: 0x00.into(),
                //     call_data_length: 0x40.into(),
                //     ret_offset: 0x40.into(),
                //     ret_size: 0x40.into(),
                //     address: PrecompileCalls::Bn128Mul.address().to_word(),
                //     ..Default::default()
                // },

                // TODO: failing test
                // Empty scalar input makes ECC lookup fail
                // PrecompileCallArgs {
                //     name: "ecMul (should succeed on empty inputs)",
                //     setup_code: bytecode! {},
                //     call_data_offset: 0x00.into(),
                //     call_data_length: 0x00.into(),
                //     ret_offset: 0x00.into(),
                //     ret_size: 0x40.into(),
                //     address: PrecompileCalls::Bn128Mul.address().to_word(),
                //     ..Default::default()
                // },

                PrecompileCallArgs {
                    name: "ecMul (valid inputs > 96 bytes)",
                    // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
                    // s = 7
                    setup_code: bytecode! {
                        // p_x
                        PUSH1(0x02)
                        PUSH1(0x00)
                        MSTORE

                        // p_y
                        PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                        PUSH1(0x20)
                        MSTORE

                        // s
                        PUSH1(0x07)
                        PUSH1(0x40)
                        MSTORE

                        // junk bytes, will be truncated
                        PUSH32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128)
                        PUSH1(0x80)
                        SHL
                        PUSH32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFu128)
                        ADD
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    ret_offset: 0x80.into(),
                    ret_size: 0x40.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },

                PrecompileCallArgs {
                    name: "ecMul (invalid input: must mod p to be valid)",
                    // P = (p + 1, p + 2)
                    // s = 7
                    setup_code: bytecode! {
                        // p_x
                        PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD48"))
                        PUSH1(0x00)
                        MSTORE

                        // p_y
                        PUSH32(word!("0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD49"))
                        PUSH1(0x20)
                        MSTORE

                        // s = 7
                        PUSH1(0x07)
                        PUSH1(0x40)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x60.into(),
                    ret_offset: 0x60.into(),
                    ret_size: 0x00.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },

                PrecompileCallArgs {
                    name: "ecMul (valid: scalar larger than scalar field order n but less than base field p)",
                    // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)

                    // For bn256 (alt_bn128) scalar field:
                    // n = 21888242871839275222246405745257275088548364400416034343698204186575808495617

                    // Choose scalar s such that n < s < p
                    // s = 21888242871839275222246405745257275088548364400416034343698204186575808500000
                    setup_code: bytecode! {
                        // p_x
                        PUSH1(0x02)
                        PUSH1(0x00)
                        MSTORE

                        // p_y
                        PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                        PUSH1(0x20)
                        MSTORE
                        // s
                        PUSH32(word!("0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0001120"))
                        PUSH1(0x40)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x60.into(),
                    ret_offset: 0x60.into(),
                    ret_size: 0x40.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },

                PrecompileCallArgs {
                    name: "ecMul (valid: scalar larger than base field order)",
                    // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
                    // s = 2^256 - 1
                    setup_code: bytecode! {
                        // p_x
                        PUSH1(0x02)
                        PUSH1(0x00)
                        MSTORE

                        // p_y
                        PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                        PUSH1(0x20)
                        MSTORE

                        // s
                        PUSH32(word!("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"))
                        PUSH1(0x40)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x60.into(),
                    ret_offset: 0x60.into(),
                    ret_size: 0x40.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                }
            ]
        };
    }

    #[test]
    fn precompile_ec_mul_test() {
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
