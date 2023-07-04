use bus_mapping::precompile::PrecompileCalls;
use eth_types::Field;
use gadgets::util::{not, or, select, Expr};
use halo2_proofs::{circuit::Value, plonk::Expression};

use crate::evm_circuit::{
    param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_U64},
    step::ExecutionState,
};

use super::{
    constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
    math_gadget::{BinaryNumberGadget, LtGadget},
    CachedRegion, Cell,
};

#[derive(Clone, Debug)]
pub struct PrecompileGadget<F> {
    address: BinaryNumberGadget<F, 4>,
    pad_right: LtGadget<F, N_BYTES_U64>,
    padding_gadget: PaddingGadget<F>,
}

impl<F: Field> PrecompileGadget<F> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        is_success: Expression<F>,
        callee_address: Expression<F>,
        _caller_id: Expression<F>,
        _cd_offset: Expression<F>,
        cd_length: Expression<F>,
        _rd_offset: Expression<F>,
        _rd_length: Expression<F>,
        precompile_return_length: Expression<F>,
        // input bytes to precompile call.
        input_bytes_rlc: Expression<F>,
        // output result from precompile call.
        output_bytes_rlc: Expression<F>,
        // returned bytes back to caller.
        _return_bytes_rlc: Expression<F>,
    ) -> Self {
        let address = BinaryNumberGadget::construct(cb, callee_address.expr());

        // input length represents:
        // - 128 bytes for ecrecover/ecAdd
        // - 96 bytes for ecMul
        // - calldata length for all other cases
        let input_len = {
            let len_128 = or::expr([
                address.value_equals(PrecompileCalls::Ecrecover),
                address.value_equals(PrecompileCalls::Bn128Add),
            ]);
            let len_96 = address.value_equals(PrecompileCalls::Bn128Mul);
            select::expr(
                len_128,
                128.expr(),
                select::expr(len_96, 96.expr(), cd_length.expr()),
            )
        };
        let pad_right = LtGadget::construct(cb, cd_length.expr(), input_len.expr());

        // we right-pad zeroes only if calldata length provided was less than the expected/required
        // input length for that precompile call.
        let padding_gadget = cb.condition(pad_right.expr(), |cb| {
            PaddingGadget::construct(
                cb,
                input_bytes_rlc.expr(),
                cd_length.expr(),
                input_len.expr(),
            )
        });
        cb.condition(not::expr(pad_right.expr()), |cb| {
            cb.require_equal(
                "no padding implies both equal",
                padding_gadget.padded_rlc(),
                input_bytes_rlc.expr(),
            );
        });

        cb.condition(address.value_equals(PrecompileCalls::Ecrecover), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileEcrecover, None, |cb| {
                let (recovered, msg_hash_rlc, sig_v_rlc, sig_r_rlc, sig_s_rlc, recovered_addr_rlc) = (
                    cb.query_bool(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_cell_phase2(),
                    cb.query_keccak_rlc::<N_BYTES_ACCOUNT_ADDRESS>(),
                );
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
                    padding_gadget.padded_rlc(),
                    (msg_hash_rlc.expr() * r_pow_96)
                        + (sig_v_rlc.expr() * r_pow_64)
                        + (sig_r_rlc.expr() * r_pow_32)
                        + sig_s_rlc.expr(),
                );
                // RLC of output bytes always equals RLC of the recovered address.
                cb.require_equal(
                    "output bytes (RLC) = recovered address",
                    output_bytes_rlc.expr(),
                    recovered_addr_rlc.expr(),
                );
                // If the address was not recovered, RLC(address) == RLC(output) == 0.
                cb.condition(not::expr(recovered.expr()), |cb| {
                    cb.require_zero("output bytes == 0", output_bytes_rlc.expr());
                });
            });
        });

        cb.condition(address.value_equals(PrecompileCalls::Sha256), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileSha256, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Ripemd160), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileRipemd160, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Identity), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileIdentity, None, |_cb| {});
            cb.condition(is_success, |cb| {
                cb.require_equal(
                    "input and output bytes are the same",
                    input_bytes_rlc,
                    output_bytes_rlc,
                );
                cb.require_equal(
                    "input length and precompile return length are the same",
                    cd_length,
                    precompile_return_length,
                );
            });
        });

        cb.condition(address.value_equals(PrecompileCalls::Modexp), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileBigModExp, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Bn128Add), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileBn256Add, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Bn128Mul), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileBn256ScalarMul, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Bn128Pairing), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileBn256Pairing, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Blake2F), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileBlake2f, None, |_cb| {});
        });

        Self {
            address,
            pad_right,
            padding_gadget,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        address: PrecompileCalls,
        input_rlc: Value<F>,
        cd_len: u64,
        keccak_rand: Value<F>,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        self.address.assign(region, offset, address)?;
        let input_len =
            self.padding_gadget
                .assign(region, offset, address, input_rlc, cd_len, keccak_rand)?;
        self.pad_right
            .assign(region, offset, F::from(cd_len), F::from(input_len))?;

        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct PaddingGadget<F> {
    padded_rlc: Cell<F>,
    power_of_rand: Cell<F>,
}

impl<F: Field> PaddingGadget<F> {
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        input_rlc: Expression<F>,
        input_len: Expression<F>,
        required_input_len: Expression<F>,
    ) -> Self {
        // No. of right padded zeroes is the difference between the required input length and the
        // length of the provided input bytes. We only support right-padding by up to 127 bytes, as
        // that's the maximum we ever require considering all cases (ecrecover, ecAdd, ecMul).
        let n_padded_zeroes = required_input_len.expr() - input_len.expr();
        cb.range_lookup(n_padded_zeroes.expr(), 128);

        // Phase2 cell that contains the RLC of the padded-bytes.
        let padded_rlc = cb.query_cell_phase2();

        // Power of randomness we are interested in, i.e. r ^ n_padded_zeroes.
        let power_of_rand = cb.query_cell_phase2();
        cb.pow_of_rand_lookup(n_padded_zeroes.expr(), power_of_rand.expr());

        // Validate value of padded RLC.
        cb.require_equal(
            "padded RLC == input RLC * pow_of_r",
            padded_rlc.expr(),
            input_rlc * power_of_rand.expr(),
        );

        Self {
            padded_rlc,
            power_of_rand,
        }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        precompile: PrecompileCalls,
        input_rlc: Value<F>,
        cd_len: u64,
        keccak_rand: Value<F>,
    ) -> Result<u64, halo2_proofs::plonk::Error> {
        let (input_len, padded_rlc, power_of_rand) =
            if let Some(required_input_len) = precompile.input_len() {
                // pad only if calldata length is less than the required input length.
                let n_padded_zeroes = if cd_len < required_input_len as u64 {
                    (required_input_len as u64) - cd_len
                } else {
                    0
                };
                assert!(n_padded_zeroes < 128);
                let power_of_rand = keccak_rand.map(|r| r.pow(&[n_padded_zeroes, 0, 0, 0]));
                (
                    required_input_len as u64,
                    input_rlc * power_of_rand,
                    power_of_rand,
                )
            } else {
                (cd_len, input_rlc, Value::known(F::one()))
            };

        self.padded_rlc.assign(region, offset, padded_rlc)?;
        self.power_of_rand.assign(region, offset, power_of_rand)?;

        Ok(input_len)
    }

    pub(crate) fn padded_rlc(&self) -> Expression<F> {
        self.padded_rlc.expr()
    }
}
