use crate::util::Field;
use bus_mapping::precompile::{PrecompileAuxData, PrecompileCalls};
use eth_types::{evm_types::GasCost, sign_types::verify_r1_bytes, word, ToLittleEndian, U256};
use gadgets::util::{and, not, or, select, sum, Expr};
use gadgets::ToScalar;
use halo2_proofs::{
    circuit::Value,
    plonk::{Error, Expression},
};
use std::sync::LazyLock;

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_MEMORY_ADDRESS, N_BYTES_WORD},
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            from_bytes,
            math_gadget::{IsEqualGadget, IsZeroGadget, LtGadget, LtWordGadget, ModGadget},
            padding_gadget::PaddingGadget,
            rlc, CachedRegion, Cell, RandomLinearCombination, Word,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

// secp256r1 Fq
static FQ_MODULUS: LazyLock<U256> =
    LazyLock::new(|| word!("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));

// secp256r1 Fp
static FP_MODULUS: LazyLock<U256> =
    LazyLock::new(|| word!("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"));

#[derive(Clone, Debug)]
pub struct P256VerifyGadget<F> {
    input_bytes_rlc: Cell<F>,
    output_bytes_rlc: Cell<F>,
    return_bytes_rlc: Cell<F>,

    pad_right: LtGadget<F, N_BYTES_MEMORY_ADDRESS>,
    padding: PaddingGadget<F>,

    msg_hash_keccak_rlc: Cell<F>,
    sig_r_keccak_rlc: Cell<F>,
    sig_s_keccak_rlc: Cell<F>,
    // pubkey_x_keccak_rlc: Cell<F>,
    // pubkey_y_keccak_rlc: Cell<F>,
    msg_hash_raw: Word<F>,
    msg_hash: Word<F>,
    fq_modulus: Word<F>,
    msg_hash_mod: ModGadget<F, true>,

    fp_modulus: Word<F>,

    sig_r: Word<F>,
    sig_r_canonical: LtWordGadget<F>,
    sig_s: Word<F>,
    sig_s_canonical: LtWordGadget<F>,

    pk_x: Word<F>,
    pk_x_canonical: LtWordGadget<F>,
    pk_y: Word<F>,
    pk_y_canonical: LtWordGadget<F>,
    is_valid: Cell<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    is_root: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for P256VerifyGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileP256Verify;

    const NAME: &'static str = "P256VERIFY";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (input_bytes_rlc, output_bytes_rlc, return_bytes_rlc) = (
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
        );
        let (
            is_valid,
            msg_hash_keccak_rlc,
            sig_r_keccak_rlc,
            sig_s_keccak_rlc,
            //recovered_addr_keccak_rlc,
        ) = (
            cb.query_bool(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            //cb.query_keccak_rlc(),
        );

        let msg_hash_raw = cb.query_word_rlc();
        let msg_hash = cb.query_word_rlc();
        let fq_modulus = cb.query_word_rlc();
        let fp_modulus = cb.query_word_rlc();

        let msg_hash_mod = ModGadget::construct(cb, [&msg_hash_raw, &fq_modulus, &msg_hash]);

        let sig_r = cb.query_word_rlc();
        let sig_r_canonical = LtWordGadget::construct(cb, &sig_r, &fq_modulus);
        let sig_s = cb.query_word_rlc();
        let sig_s_canonical = LtWordGadget::construct(cb, &sig_s, &fq_modulus);
        let r_s_canonical = and::expr([sig_r_canonical.expr(), sig_s_canonical.expr()]);

        let pk_x = cb.query_word_rlc();
        let pk_y = cb.query_word_rlc();
        let pk_x_canonical = LtWordGadget::construct(cb, &pk_x, &fp_modulus);
        let pk_y_canonical = LtWordGadget::construct(cb, &pk_y, &fp_modulus);

        let x_y_canonical = and::expr([pk_x_canonical.expr(), pk_y_canonical.expr()]);

        cb.require_equal(
            "msg hash cells assigned incorrectly",
            msg_hash_keccak_rlc.expr(),
            cb.keccak_rlc::<N_BYTES_WORD>(
                msg_hash_raw
                    .cells
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
                    .cells
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
                    .cells
                    .iter()
                    .map(Expr::expr)
                    .collect::<Vec<Expression<F>>>()
                    .try_into()
                    .expect("msg hash is 32 bytes"),
            ),
        );

        cb.require_equal(
            "Secp256r1::Fq modulus assigned correctly",
            fq_modulus.expr(),
            cb.word_rlc::<N_BYTES_WORD>(FQ_MODULUS.to_le_bytes().map(|b| b.expr())),
        );
        cb.require_equal(
            "Secp256r1::Fp modulus assigned correctly",
            fp_modulus.expr(),
            cb.word_rlc::<N_BYTES_WORD>(FP_MODULUS.to_le_bytes().map(|b| b.expr())),
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

        let gas_cost = select::expr(
            is_success.expr(),
            GasCost::PRECOMPILE_P256VERIFY.expr(),
            cb.curr.state.gas_left.expr(),
        );

        // lookup to the sign_verify table:
        //
        // || msg_hash | v(0) | r | s | recovered_addr(0) | is_valid ||
        cb.condition(r_s_canonical.expr(), |cb| {
            cb.sig_table_lookup(
                msg_hash.expr(),
                // v set to zero
                0.expr(),
                sig_r.expr(),
                sig_s.expr(),
                // recovered addr set to 0.
                0.expr(),
                is_valid.expr(),
            );
        });
        // check r, s is canonical
        cb.condition(not::expr(r_s_canonical.expr()), |cb| {
            cb.require_zero("is_valid == false if r or s not canonical", is_valid.expr());
        });

        // check x, y is canonical
        cb.condition(not::expr(x_y_canonical.expr()), |cb| {
            cb.require_zero("is_valid == false if x or y not canonical", is_valid.expr());
        });
        // cb.condition(not::expr(recovered.expr()), |cb| {
        //     cb.require_zero(
        //         "address == 0 if address could not be recovered",
        //         recovered_addr_keccak_rlc.expr(),
        //     );
        // });

        cb.precompile_info_lookup(
            cb.execution_state().as_u64().expr(),
            callee_address.expr(),
            cb.execution_state().precompile_base_gas_cost().expr(),
        );

        let required_input_len = 160.expr();
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
            "input bytes (RLC) = [msg_hash | sig_v_rlc | sig_r | sig_s]",
            padding.padded_rlc(),
            (msg_hash_keccak_rlc.expr() * r_pow_96)
                + (0.expr() * r_pow_64)
                + (sig_r_keccak_rlc.expr() * r_pow_32)
                + sig_s_keccak_rlc.expr(),
        );
        // constrain output first byte is bool .
        cb.require_boolean("output first byte is bool", output_bytes_rlc.expr());

        let restore_context = super::gen_restore_context(
            cb,
            is_root.expr(),
            is_success.expr(),
            gas_cost.expr(),
            // ReturnDataLength
            select::expr(is_valid.expr(), 0x20.expr(), 0x00.expr()),
        );

        Self {
            input_bytes_rlc,
            output_bytes_rlc,
            return_bytes_rlc,

            pad_right,
            padding,
            msg_hash_keccak_rlc,
            sig_r_keccak_rlc,
            sig_s_keccak_rlc,
            //recovered_addr_keccak_rlc,
            msg_hash_raw,
            msg_hash,
            fq_modulus,
            msg_hash_mod,
            fp_modulus,

            sig_r,
            sig_r_canonical,
            sig_s,
            sig_s_canonical,

            pk_x,
            pk_x_canonical,
            pk_y,
            pk_y_canonical,
            is_valid,
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
        block: &Block,
        _tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        if let Some(PrecompileAuxData::P256Verify(aux_data)) = &step.aux_data {
            self.input_bytes_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(aux_data.input_bytes.iter().rev(), r)),
            )?;
            self.output_bytes_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(aux_data.output_bytes.iter().rev(), r)),
            )?;
            self.return_bytes_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(aux_data.return_bytes.iter().rev(), r)),
            )?;
            self.msg_hash_keccak_rlc.assign(
                region,
                offset,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(&aux_data.msg_hash.to_le_bytes(), r)),
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
                (&self.pk_x, aux_data.pubkey_x),
                (&self.pk_y, aux_data.pubkey_y),
            ] {
                word_rlc.assign(region, offset, Some(value.to_le_bytes()))?;
            }
            let (quotient, remainder) = aux_data.msg_hash.div_mod(*FQ_MODULUS);
            self.msg_hash
                .assign(region, offset, Some(remainder.to_le_bytes()))?;
            self.fq_modulus
                .assign(region, offset, Some(FQ_MODULUS.to_le_bytes()))?;
            self.fp_modulus
                .assign(region, offset, Some(FP_MODULUS.to_le_bytes()))?;
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
            // assign pk_x_canonical, pk_y_canonical
            self.pk_x_canonical
                .assign(region, offset, aux_data.pubkey_x, *FP_MODULUS)?;
            self.pk_y_canonical
                .assign(region, offset, aux_data.pubkey_y, *FP_MODULUS)?;
            // TODO: assign is_valid correctly
            let pub_key_bytes = (
                &aux_data.pubkey_x.to_le_bytes(),
                &aux_data.pubkey_y.to_le_bytes(),
            );
            let r_bytes = aux_data.sig_r.to_le_bytes();
            let s_bytes = aux_data.sig_s.to_le_bytes();
            let msg_hash_bytes = aux_data.msg_hash.to_le_bytes();

            let is_sig_valid =
                verify_r1_bytes(pub_key_bytes, &r_bytes, &s_bytes, &msg_hash_bytes, None);
            self.is_valid
                .assign(region, offset, Value::known(F::from(is_sig_valid)))?;
            // self.recovered_addr_keccak_rlc.assign(
            //     region,
            //     offset,
            //     Some({
            //         let mut recovered_addr = aux_data.recovered_addr.to_fixed_bytes();
            //         recovered_addr.reverse();
            //         recovered_addr
            //     }),
            // )?;
            self.pad_right
                .assign(region, offset, call.call_data_length.into(), 128.into())?;
            self.padding.assign(
                region,
                offset,
                PrecompileCalls::P256Verify,
                region
                    .challenges()
                    .keccak_input()
                    .map(|r| rlc::value(aux_data.input_bytes.iter().rev(), r)),
                call.call_data_length,
                region.challenges().keccak_input(),
            )?;
        } else {
            log::error!("unexpected aux_data {:?} for p256verify", step.aux_data);
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
