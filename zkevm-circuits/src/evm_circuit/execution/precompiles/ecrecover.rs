use bus_mapping::precompile::PrecompileAuxData;
use eth_types::{evm_types::GasCost, word, Field, ToLittleEndian, ToScalar, U256};
use gadgets::util::{and, not, or, select, sum, Expr};
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_WORD,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes,
            math_gadget::{IsEqualGadget, IsZeroGadget, LtWordGadget, ModGadget},
            rlc, CachedRegion, Cell,
        },
    },
    util::word::{Word, Word32Cell, WordExpr},
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

lazy_static::lazy_static! {
    static ref FQ_MODULUS: U256 = {
        word!("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
    };
}

#[derive(Clone, Debug)]
pub struct EcrecoverGadget<F> {
    recovered: Cell<F>,
    msg_hash_keccak_rlc: Cell<F>,
    sig_v_keccak_rlc: Cell<F>,
    sig_r_keccak_rlc: Cell<F>,
    sig_s_keccak_rlc: Cell<F>,
    recovered_addr_keccak_rlc: Word32Cell<F>,

    msg_hash_raw: Word32Cell<F>,
    msg_hash: Word32Cell<F>,
    fq_modulus: Word32Cell<F>,
    msg_hash_mod: ModGadget<F>,

    sig_r: Word32Cell<F>,
    sig_r_canonical: LtWordGadget<F>,
    sig_s: Word32Cell<F>,
    sig_s_canonical: LtWordGadget<F>,

    sig_v: Word32Cell<F>,
    sig_v_one_byte: IsZeroGadget<F>,
    sig_v_eq27: IsEqualGadget<F>,
    sig_v_eq28: IsEqualGadget<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for EcrecoverGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileEcrecover;

    const NAME: &'static str = "ECRECOVER";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (
            recovered,
            msg_hash_keccak_rlc,
            sig_v_keccak_rlc,
            sig_r_keccak_rlc,
            sig_s_keccak_rlc,
            recovered_addr_keccak_rlc,
        ) = (
            cb.query_bool(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_word32(),
        );

        let msg_hash_raw = cb.query_word32();
        let msg_hash = cb.query_word32();
        let fq_modulus = cb.query_word32();
        let msg_hash_mod = ModGadget::construct(cb, [&msg_hash_raw, &fq_modulus, &msg_hash]);

        let sig_r = cb.query_word32();
        let sig_r_canonical = LtWordGadget::construct(cb, &sig_r, &fq_modulus);
        let sig_s = cb.query_word32();
        let sig_s_canonical = LtWordGadget::construct(cb, &sig_s, &fq_modulus);
        let r_s_canonical = and::expr([sig_r_canonical.expr(), sig_s_canonical.expr()]);

        // sig_v is valid if sig_v == 27 || sig_v == 28
        let sig_v = cb.query_word32();
        let sig_v_rest_bytes = sum::expr(&sig_v.limbs[1..]);
        let sig_v_one_byte = IsZeroGadget::construct(cb, sig_v_rest_bytes);
        let sig_v_eq27 = IsEqualGadget::construct(cb, sig_v.limbs[0].expr(), 27.expr());
        let sig_v_eq28 = IsEqualGadget::construct(cb, sig_v.limbs[0].expr(), 28.expr());
        let sig_v_valid = and::expr([
            or::expr([sig_v_eq27.expr(), sig_v_eq28.expr()]),
            sig_v_one_byte.expr(),
        ]);

        cb.require_equal(
            "msg hash cells assigned incorrectly",
            msg_hash_keccak_rlc.expr(),
            cb.keccak_rlc::<N_BYTES_WORD>(
                msg_hash_raw
                    .limbs
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<Expression<F>>>()
                    .try_into()
                    .expect("msg hash is 32 bytes"),
            ),
        );
        cb.require_equal(
            "sig_r cells assigned incorrectly",
            sig_r_keccak_rlc.expr(),
            cb.keccak_rlc::<N_BYTES_WORD>(
                sig_r
                    .limbs
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<Expression<F>>>()
                    .try_into()
                    .expect("msg hash is 32 bytes"),
            ),
        );
        cb.require_equal(
            "sig_s cells assigned incorrectly",
            sig_s_keccak_rlc.expr(),
            cb.keccak_rlc::<N_BYTES_WORD>(
                sig_s
                    .limbs
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<Expression<F>>>()
                    .try_into()
                    .expect("msg hash is 32 bytes"),
            ),
        );
        cb.require_equal(
            "sig_v cells assigned incorrectly",
            sig_v_keccak_rlc.expr(),
            cb.keccak_rlc::<N_BYTES_WORD>(
                sig_v
                    .limbs
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<Expression<F>>>()
                    .try_into()
                    .expect("sig_v is 32 bytes"),
            ),
        );
        // cb.require_equal(
        //     "Secp256k1::Fq modulus assigned correctly",
        //     fq_modulus.expr(),
        //     cb.word_rlc::<N_BYTES_WORD>(FQ_MODULUS.to_le_bytes().map(|b| b.expr())),
        // );
        cb.require_equal_word(
            "Secp256k1::Fq modulus assigned correctly",
            fq_modulus.to_word(),
            Word::from(*FQ_MODULUS).to_word()
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

        let gas_cost = select::expr(
            is_success.expr(),
            GasCost::PRECOMPILE_ECRECOVER_BASE.expr(),
            cb.curr.state.gas_left.expr(),
        );

        // lookup to the sign_verify table:
        //
        // || msg_hash | v | r | s | recovered_addr | recovered ||
        cb.condition(
            and::expr([r_s_canonical.expr(), sig_v_valid.expr()]),
            |cb| {
                cb.sig_table_lookup(
                    cb.word_rlc(msg_hash.limbs.map(|cell| cell.expr())),
                    sig_v.limbs[0].expr() - 27.expr(),
                    cb.word_rlc(sig_r.limbs.map(|cell| cell.expr())),
                    cb.word_rlc(sig_s.limbs.map(|cell| cell.expr())),
                    select::expr(
                        recovered.expr(),
                        from_bytes::expr(&recovered_addr_keccak_rlc.limbs),
                        0.expr(),
                    ),
                    recovered.expr(),
                );
            },
        );
        cb.condition(not::expr(r_s_canonical.expr()), |cb| {
            cb.require_zero(
                "recovered == false if r or s not canonical",
                recovered.expr(),
            );
        });
        cb.condition(not::expr(sig_v_valid.expr()), |cb| {
            cb.require_zero("recovered == false if sig_v != 27 or 28", recovered.expr());
        });
        cb.condition(not::expr(recovered.expr()), |cb| {
            cb.require_zero_word(
                "address == 0 if address could not be recovered",
                recovered_addr_keccak_rlc.to_word()
            );
        });

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
            0x00.expr(),                                              // ReturnDataOffset
            select::expr(recovered.expr(), 0x20.expr(), 0x00.expr()), // ReturnDataLength
            0.expr(),
            0.expr(),
        );

        Self {
            recovered,
            msg_hash_keccak_rlc,
            sig_v_keccak_rlc,
            sig_r_keccak_rlc,
            sig_s_keccak_rlc,
            recovered_addr_keccak_rlc,

            msg_hash_raw,
            msg_hash,
            fq_modulus,
            msg_hash_mod,

            sig_r,
            sig_r_canonical,
            sig_s,
            sig_s_canonical,

            sig_v,
            sig_v_one_byte,
            sig_v_eq27,
            sig_v_eq28,

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
        if let Some(PrecompileAuxData::Ecrecover(aux_data)) = &step.aux_data {
            let recovered = !aux_data.recovered_addr.is_zero();
            self.recovered
                .assign(region, offset, Value::known(F::from(recovered as u64)))?;
            self.msg_hash_keccak_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.msg_hash.to_le_bytes(), r)),
            )?;
            self.sig_v_keccak_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.sig_v.to_le_bytes(), r)),
            )?;
            self.sig_r_keccak_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.sig_r.to_le_bytes(), r)),
            )?;
            self.sig_s_keccak_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.sig_s.to_le_bytes(), r)),
            )?;
            for (word_rlc, value) in [
                (&self.msg_hash_raw, aux_data.msg_hash),
                (&self.sig_r, aux_data.sig_r),
                (&self.sig_s, aux_data.sig_s),
                (&self.sig_v, aux_data.sig_v),
            ] {
                word_rlc.assign_u256(region, offset, value)?;
            }
            let (quotient, remainder) = aux_data.msg_hash.div_mod(*FQ_MODULUS);
            self.msg_hash
                .assign_u256(region, offset, remainder)?;
            self.fq_modulus
                .assign_u256(region, offset, *FQ_MODULUS)?;
            self.msg_hash_mod.assign(
                region,
                offset,
                aux_data.msg_hash,
                *FQ_MODULUS,
                remainder,
                quotient,
            )?;
            self.sig_r_canonical
                .assign(region, offset, aux_data.sig_r, *FQ_MODULUS)?;
            self.sig_s_canonical
                .assign(region, offset, aux_data.sig_s, *FQ_MODULUS)?;
            self.sig_v_one_byte.assign(
                region,
                offset,
                F::from(
                    aux_data
                        .sig_v
                        .to_le_bytes()
                        .into_iter()
                        .skip(1)
                        .map(|b| b as u64)
                        .sum::<u64>(),
                ),
            )?;
            self.sig_v_eq27.assign(
                region,
                offset,
                F::from(aux_data.sig_v.to_le_bytes()[0] as u64),
                F::from(27),
            )?;
            self.sig_v_eq28.assign(
                region,
                offset,
                F::from(aux_data.sig_v.to_le_bytes()[0] as u64),
                F::from(28),
            )?;
            self.recovered_addr_keccak_rlc.assign_u256(
                region,
                offset,
                U256::from_little_endian({
                    let mut recovered_addr = aux_data.recovered_addr.to_fixed_bytes();
                    recovered_addr.reverse();
                    &recovered_addr
                })
            )?;
        } else {
            log::error!("unexpected aux_data {:?} for ecrecover", step.aux_data);
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
    use mock::TestContext;
    use rayon::{iter::ParallelIterator, prelude::IntoParallelRefIterator};

    use crate::test_util::CircuitTestBuilder;

    lazy_static::lazy_static! {
        static ref TEST_VECTOR: Vec<PrecompileCallArgs> = {
            vec![
                PrecompileCallArgs {
                    name: "ecrecover (padded bytes, addr recovered)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    // copy 101 bytes from memory addr 0. This should be sufficient to recover an
                    // address, but the signature is invalid (ecrecover does not care about this
                    // though)
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x65.into(),
                    // return 32 bytes and write from memory addr 128
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (valid sig, addr recovered)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    // copy 128 bytes from memory addr 0. Address is recovered and the signature is
                    // valid.
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    // return 32 bytes and write from memory addr 128
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (valid sig, addr recovered, extra input bytes)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    // copy 133 bytes from memory addr 0. Address is recovered and the signature is
                    // valid. The 5 bytes after the first 128 bytes are ignored.
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x85.into(),
                    // return 32 bytes and write from memory addr 128
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (overflowing msg_hash)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (overflowing sig_r)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (overflowing sig_s)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffee"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (invalid v > 28, single byte)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(29)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (invalid v < 27, single byte)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(26)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (invalid v, multi-byte, last byte == 28)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20, 1c == 28 (but not single byte)
                        PUSH32(word!("0x010000000000000000000000000000000000000000000000000000000000001c"))
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
                PrecompileCallArgs {
                    name: "ecrecover (v == 1)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(0x01)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
            ]
        };

        static ref OOG_TEST_VECTOR: Vec<PrecompileCallArgs> = {
            vec![
                PrecompileCallArgs {
                    name: "ecrecover (oog)",
                    setup_code: bytecode! {
                        // msg hash from 0x00
                        PUSH32(word!("0x456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3"))
                        PUSH1(0x00)
                        MSTORE
                        // signature v from 0x20
                        PUSH1(28)
                        PUSH1(0x20)
                        MSTORE
                        // signature r from 0x40
                        PUSH32(word!("0x9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608"))
                        PUSH1(0x40)
                        MSTORE
                        // signature s from 0x60
                        PUSH32(word!("0x4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"))
                        PUSH1(0x60)
                        MSTORE
                    },
                    // copy 128 bytes from memory addr 0. Address is recovered and the signature is
                    // valid.
                    call_data_offset: 0x00.into(),
                    call_data_length: 0x80.into(),
                    // return 32 bytes and write from memory addr 128
                    ret_offset: 0x80.into(),
                    ret_size: 0x20.into(),
                    gas: 0.into(),
                    value: 2.into(),
                    address: PrecompileCalls::Ecrecover.address().to_word(),
                    ..Default::default()
                },
            ]
        };
    }

    #[test]
    fn precompile_ecrecover_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        TEST_VECTOR.par_iter().for_each(|test_vector| {
            for &call_kind in &call_kinds {
                let bytecode = test_vector.with_call_op(call_kind);

                CircuitTestBuilder::new_from_test_ctx(
                    TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                )
                .run();
            }
        });
    }

    #[test]
    fn precompile_ecrecover_oog_test() {
        let call_kinds = vec![
            OpcodeId::CALL,
            OpcodeId::STATICCALL,
            OpcodeId::DELEGATECALL,
            OpcodeId::CALLCODE,
        ];

        OOG_TEST_VECTOR.par_iter().for_each(|test_vector| {
            for &call_kind in &call_kinds {
                let bytecode = test_vector.with_call_op(call_kind);

                CircuitTestBuilder::new_from_test_ctx(
                    TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                )
                .run();
            }
        })
    }
}
