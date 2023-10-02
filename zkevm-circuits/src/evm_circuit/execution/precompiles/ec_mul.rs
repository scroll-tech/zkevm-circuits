use std::ops::{Add, Sub};

use bus_mapping::precompile::{PrecompileAuxData, PrecompileCalls};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar, U256};
use gadgets::util::{and, not, or, select, split_u256, sum, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            math_gadget::{AddWordsGadget, IsEqualWordGadget, IsZeroWordGadget, ModGadget},
            rlc, CachedRegion, Cell,
        },
    },
    util::word::{Word, WordCell, WordExpr, Word32Cell},
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

lazy_static::lazy_static! {
    // r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    static ref FR_MODULUS: U256 = {
        U256::from_dec_str("21888242871839275222246405745257275088548364400416034343698204186575808495617")
            .expect("Fr::MODULUS")
    };
    // q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
    static ref FQ_MODULUS: U256 = {
        U256::from_dec_str("21888242871839275222246405745257275088696311157297823662689037894645226208583")
            .expect("Fq::MODULUS")
    };
}

#[derive(Clone, Debug)]
pub struct EcMulGadget<F> {
    point_p_x: WordCell<F>,
    point_p_y: WordCell<F>,
    scalar_s_raw: Word32Cell<F>,
    point_r_x: WordCell<F>,
    point_r_y: WordCell<F>,

    p_x_is_zero: IsZeroWordGadget<F, WordCell<F>>,
    p_y_is_zero: IsZeroWordGadget<F, WordCell<F>>,
    s_is_zero: IsZeroWordGadget<F, Word32Cell<F>>,

    // Two Words (s_raw, scalar_s) that satisfies
    // k * Fr::MODULUS + scalar_s = s_raw
    // Used for proving correct modulo by Fr
    scalar_s: Word32Cell<F>,
    fr_modulus: Word32Cell<F>,   // Fr::MODULUS
    modword: ModGadget<F>,

    point_p_y_raw: Word32Cell<F>,
    point_r_y_raw: Word32Cell<F>,
    fr_modulus_minus_1: Word32Cell<F>,
    s_is_fr_mod_minus_1: IsEqualWordGadget<F, Word32Cell<F>, Word32Cell<F>>,
    fq_modulus: Word32Cell<F>,
    p_y_plus_r_y: AddWordsGadget<F, 2, false>,

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
        let (point_p_x, point_p_y, point_r_x, point_r_y) = (
            cb.query_word_unchecked(),
            cb.query_word_unchecked(),
            cb.query_word_unchecked(),
            cb.query_word_unchecked(),
        );

        let (scalar_s_raw, scalar_s, fr_modulus) = (
            cb.query_word32(),
            cb.query_word32(),
            cb.query_word32(),
        );

        // k * n + scalar_s = s_raw
        let modword = ModGadget::construct(cb, [&scalar_s_raw, &fr_modulus, &scalar_s]);

        // Conditions for dealing with infinity/empty points and zero/empty scalar
        let p_x_is_zero = cb.annotation("ecMul(P_x)", |cb| {
            IsZeroWordGadget::construct(cb, &point_p_x)
        });
        let p_y_is_zero = cb.annotation("ecMul(P_y)", |cb| {
            IsZeroWordGadget::construct(cb, &point_p_y)
        });
        let p_is_zero = and::expr([p_x_is_zero.expr(), p_y_is_zero.expr()]);
        let s_is_zero = cb.annotation("ecMul(s == 0)", |cb| {
            IsZeroWordGadget::construct(cb, &scalar_s_raw)
        });
        let fr_modulus_minus_1 = cb.query_word32();
        let s_is_fr_mod_minus_1 = cb.annotation("ecMul(s == Fr::MODULUS - 1)", |cb| {
            IsEqualWordGadget::construct(cb, &scalar_s, &fr_modulus_minus_1)
                
        });

        let (point_p_y_raw, point_r_y_raw, fq_modulus) = (
            cb.query_word32(),
            cb.query_word32(),
            cb.query_word32(),
        );
        cb.require_equal_word(
            "ecMul(P_y): equality",
            point_p_y.to_word(),
            point_p_y_raw.to_word(),
        );
        cb.require_equal_word(
            "ecMul(R_y): equality",
            point_r_y.to_word(),
            point_r_y_raw.to_word(),
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

        // all gas sent to this call will be consumed if `is_success == false`.
        let gas_cost = select::expr(
            is_success.expr(),
            GasCost::PRECOMPILE_BN256MUL.expr(),
            cb.curr.state.gas_left.expr(),
        );

        cb.condition(
            // skip ECC table lookup if:
            // - P == (0, 0)
            // - s == Fr::zero()
            // - s == Fr::MODULUS - 1
            not::expr(or::expr([
                p_is_zero.expr(),
                s_is_zero.expr(),
                s_is_fr_mod_minus_1.expr(),
            ])),
            |cb| {
                cb.ecc_table_lookup(
                    u64::from(PrecompileCalls::Bn128Mul).expr(),
                    is_success.expr(),
                    point_p_x.to_word(),
                    point_p_y.to_word(),
                    scalar_s.to_word(),
                    Word::zero(),
                    Word::zero(),
                    point_r_x.to_word(),
                    point_r_y.to_word(),
                );
            },
        );
        cb.condition(not::expr(is_success.expr()), |cb| {
            cb.require_zero_word("R_x == 0", point_r_x.to_word());
            cb.require_zero_word("R_y == 0", point_r_y.to_word());
        });

        cb.condition(or::expr([p_is_zero.expr(), s_is_zero.expr()]), |cb| {
            cb.require_zero_word(
                "if P == (0, 0) || s == 0, then R_x == 0",
                point_r_x.to_word(),
            );
            cb.require_zero_word(
                "if P == (0, 0) || s == 0, then R_y == 0",
                point_r_y.to_word(),
            );
        });
        // If s == Fr::MODULUS - 1 then P == -R:
        // - P_x == R_x
        // - P_y + R_y == Fq::MODULUS
        let p_y_plus_r_y = cb.condition(
            and::expr([
                is_success.expr(),
                s_is_fr_mod_minus_1.expr(),
                not::expr(p_is_zero.expr()),
            ]),
            |cb| {
                cb.require_equal_word(
                    "ecMul(s == Fr::MODULUS - 1): P_x == R_x",
                    point_p_x.to_word(),
                    point_r_x.to_word(),
                );
                AddWordsGadget::construct(
                    cb,
                    [point_p_y_raw.clone(), point_r_y_raw.clone()],
                    fq_modulus.clone(),
                )
            },
        );

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        let restore_context = RestoreContextGadget::construct2(
            cb,
            is_success.expr(),
            gas_cost.expr(),
            0.expr(),
            0x00.expr(),                                               // ReturnDataOffset
            select::expr(is_success.expr(), 0x40.expr(), 0x00.expr()), // ReturnDataLength
            0.expr(),
            0.expr(),
        );

        Self {
            point_p_x,
            point_p_y,
            scalar_s_raw,
            point_r_x,
            point_r_y,

            p_x_is_zero,
            p_y_is_zero,
            s_is_zero,

            scalar_s,
            fr_modulus,
            modword,
            
            point_p_y_raw,
            point_r_y_raw,
            fr_modulus_minus_1,
            s_is_fr_mod_minus_1,
            fq_modulus,
            p_y_plus_r_y,

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
            for (col, is_zero_gadget, word_value) in [
                (&self.point_p_x, &self.p_x_is_zero, aux_data.p_x),
                (&self.point_p_y, &self.p_y_is_zero, aux_data.p_y),
            ] {
                col.assign_u256(region, offset, word_value)?;
                is_zero_gadget.assign_u256(region, offset, word_value)?;
            }

            &self.scalar_s_raw.assign_u256(region, offset, aux_data.s_raw)?;

            for (col, word_value) in [
                (&self.point_r_x, aux_data.r_x),
                (&self.point_r_y, aux_data.r_y),
            ] {
                col.assign_u256(region, offset, word_value)?;
            }

            for (col, word_value) in [
                (&self.scalar_s_raw, aux_data.s_raw),
                (&self.fr_modulus, *FR_MODULUS),
            ] {
                col.assign_u256(region, offset, word_value)?;
            }
            self.scalar_s
                .assign_u256(region, offset, aux_data.s)?;
            self.s_is_zero.assign_u256(
                region,
                offset,
                aux_data.s,
            )?;

            for (col, word_value) in [
                (&self.point_p_y_raw, aux_data.p_y),
                (&self.point_r_y_raw, aux_data.r_y),
                (&self.fq_modulus, U256::from_little_endian(&FQ_MODULUS.to_le_bytes())),
                (&self.fr_modulus, U256::from_little_endian(&FR_MODULUS.to_le_bytes())),
                (&self.fr_modulus_minus_1, U256::from_little_endian(&FR_MODULUS.sub(&U256::one()).to_le_bytes()))
            ] {
                col.assign_u256(region, offset, word_value)?;
            }

            self.s_is_fr_mod_minus_1.assign_u256(
                region,
                offset,
                aux_data.s,
                FR_MODULUS.sub(&U256::one())
            )?;

            self.p_y_plus_r_y.assign(
                region,
                offset,
                [aux_data.p_y, aux_data.r_y],
                aux_data.p_y.add(&aux_data.r_y),
            )?;

            let (k, _) = aux_data.s_raw.div_mod(*FR_MODULUS);
            self.modword
                .assign(region, offset, aux_data.s_raw, *FR_MODULUS, aux_data.s, k)?;
        } else {
            log::error!("unexpected aux_data {:?} for ecMul", step.aux_data);
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
                PrecompileCallArgs {
                    name: "ecMul (valid input < 96 bytes)",
                    // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
                    // s = blank
                    setup_code: bytecode! {
                        // p_x
                        PUSH1(0x02)
                        PUSH1(0x00)
                        MSTORE

                        // p_y
                        PUSH32(word!("0x23818CDE28CF4EA953FE59B1C377FAFD461039C17251FF4377313DA64AD07E13"))
                        PUSH1(0x20)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x40.into(),
                    ret_offset: 0x40.into(),
                    ret_size: 0x40.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecMul (should succeed on empty inputs)",
                    setup_code: bytecode! {},
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x00.into(),
                    ret_offset: 0x00.into(),
                    ret_size: 0x40.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },
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
                },
                PrecompileCallArgs {
                    name: "ecMul (valid input): s == Fr::MODULUS - 1, i.e. P == -R",
                    // P = (2, 16059845205665218889595687631975406613746683471807856151558479858750240882195)
                    // s = Fr::MODULUS - 1
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
                        PUSH32(word!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"))
                        PUSH1(0x40)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x60.into(),
                    ret_offset: 0x60.into(),
                    ret_size: 0x40.into(),
                    value: 1.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecMul (invalid input): s == Fr::MODULUS - 1, but P not on curve",
                    // P = (3, 4), i.e. not on curve
                    // s = Fr::MODULUS - 1
                    setup_code: bytecode! {
                        // p_x
                        PUSH1(0x03)
                        PUSH1(0x00)
                        MSTORE
                        // p_y
                        PUSH1(0x04)
                        PUSH1(0x20)
                        MSTORE
                        // s
                        PUSH32(word!("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"))
                        PUSH1(0x40)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x60.into(),
                    ret_offset: 0x60.into(),
                    ret_size: 0x40.into(),
                    value: 1.into(),
                    address: PrecompileCalls::Bn128Mul.address().to_word(),
                    ..Default::default()
                },
            ]
        };

        static ref OOG_TEST_VECTOR: Vec<PrecompileCallArgs> = {
            vec![
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
                    gas: (PrecompileCalls::Bn128Mul.base_gas_cost().as_u64() - 1).to_word(),
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

    #[test]
    fn precompile_ec_mul_oog_test() {
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
