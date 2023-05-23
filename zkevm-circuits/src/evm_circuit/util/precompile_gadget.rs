use bus_mapping::precompile::PrecompileCalls;
use eth_types::Field;
use gadgets::util::Expr;
use halo2_proofs::plonk::Expression;

use crate::evm_circuit::step::ExecutionState;

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
        caller_id: Expression<F>,
        cd_offset: Expression<F>,
        cd_length: Expression<F>,
        rd_offset: Expression<F>,
        rd_length: Expression<F>,
    ) -> Self {
        let address = BinaryNumberGadget::construct(cb, callee_address.expr());

        cb.condition(address.value_equals(PrecompileCalls::Identity), |cb| {
            cb.constrain_next_step(ExecutionState::PrecompileIdentity, None, |cb| {
                let precomp_is_success = cb.query_cell();
                let precomp_callee_address = cb.query_cell();
                let precomp_caller_id = cb.query_cell();
                let precomp_cd_offset = cb.query_cell();
                let precomp_cd_length = cb.query_cell();
                let precomp_rd_offset = cb.query_cell();
                let precomp_rd_length = cb.query_cell();
                cb.require_equal(
                    "precompile call is_success check",
                    is_success,
                    precomp_is_success.expr(),
                );
                cb.require_equal(
                    "precompile call callee_address check",
                    callee_address,
                    precomp_callee_address.expr(),
                );
                cb.require_equal(
                    "precompile call caller_id check",
                    caller_id,
                    precomp_caller_id.expr(),
                );
                cb.require_equal(
                    "precompile call call_data_offset check",
                    cd_offset,
                    precomp_cd_offset.expr(),
                );
                cb.require_equal(
                    "precompile call call_data_length check",
                    cd_length,
                    precomp_cd_length.expr(),
                );
                cb.require_equal(
                    "precompile call return_data_offset check",
                    rd_offset,
                    precomp_rd_offset.expr(),
                );
                cb.require_equal(
                    "precompile call return_data_length check",
                    rd_length,
                    precomp_rd_length.expr(),
                );
            });
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
