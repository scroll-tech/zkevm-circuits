use bus_mapping::precompile::PrecompileCalls;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::Expression;

use crate::evm_circuit::step::ExecutionState;

use super::{
    constraint_builder::EVMConstraintBuilder, math_gadget::BinaryNumberGadget, CachedRegion,
};

#[derive(Clone, Debug)]
pub struct PrecompileGadget<F> {
    address: BinaryNumberGadget<F, 4>,
}

impl<F: Field> PrecompileGadget<F> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        _is_success: Expression<F>,
        callee_address: Expression<F>,
        _caller_id: Expression<F>,
        _cd_offset: Expression<F>,
        _cd_length: Expression<F>,
        _rd_offset: Expression<F>,
        _rd_length: Expression<F>,
    ) -> Self {
        let address = BinaryNumberGadget::construct(cb, callee_address.expr());

        cb.condition(address.value_equals(PrecompileCalls::ECRecover), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileEcRecover, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Sha256), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileSha256, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Ripemd160), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileRipemd160, None, |_cb| {});
        });

        cb.condition(address.value_equals(PrecompileCalls::Identity), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileIdentity, None, |_cb| {});
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
