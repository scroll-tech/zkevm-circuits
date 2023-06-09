use bus_mapping::precompile::PrecompileCalls;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::Expression;

use crate::evm_circuit::{param::N_BYTES_ACCOUNT_ADDRESS, step::ExecutionState};

use super::{
    constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
    math_gadget::BinaryNumberGadget,
    CachedRegion,
};

#[derive(Clone, Debug)]
pub struct PrecompileGadget<F> {
    address: BinaryNumberGadget<F, 4>,
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

        cb.condition(address.value_equals(PrecompileCalls::Ecrecover), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileEcrecover, None, |cb| {
                let (_recovered, msg_hash, sig_v, sig_r, sig_s, recovered_addr) = (
                    cb.query_bool(),
                    cb.query_cell_phase2(),
                    cb.query_byte(),
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
                    "input bytes (RLC) = [msg_hash | sig_v | sig_r | sig_s]",
                    input_bytes_rlc.expr(),
                    (msg_hash.expr() * r_pow_96)
                        + (sig_v.expr() * r_pow_64)
                        + (sig_r.expr() * r_pow_32)
                        + sig_s.expr(),
                );
                cb.require_equal(
                    "output bytes (RLC) = recovered address",
                    output_bytes_rlc.expr(),
                    recovered_addr.expr(),
                );
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

        Self { address }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        address: PrecompileCalls,
    ) -> Result<(), halo2_proofs::plonk::Error> {
        self.address.assign(region, offset, address)
    }
}
