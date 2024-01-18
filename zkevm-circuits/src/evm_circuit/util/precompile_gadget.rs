use bus_mapping::precompile::PrecompileCalls;
use eth_types::Field;
use gadgets::util::{and, not, Expr};
use halo2_proofs::plonk::Expression;

use crate::evm_circuit::step::{ExecutionState, ExecutionState::ErrorOutOfGasPrecompile};

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
    pub(crate) fn construct(
        cb: &mut EVMConstraintBuilder<F>,
        callee_address: Expression<F>,
        input_bytes_rlc: Expression<F>,
        // for root call we do not need to constraint output and return
        output_bytes_rlc: Option<Expression<F>>,
        return_bytes_rlc: Option<Expression<F>>,
    ) -> Self {
        let address = BinaryNumberGadget::construct(cb, callee_address.expr());

        macro_rules! constrain_next_state {
            ($cb:ident, $precompile_call_type:ident, $precompile_exec_state:ident) => {
                $cb.condition(
                    and::expr([
                        address.value_equals(PrecompileCalls::$precompile_call_type),
                        not::expr($cb.next.execution_state_selector([ErrorOutOfGasPrecompile])),
                    ]),
                    |cb| {
                        cb.require_next_state(ExecutionState::$precompile_exec_state);
                    },
                );
            };
        }
        constrain_next_state!(cb, Ecrecover, PrecompileEcrecover);
        constrain_next_state!(cb, Sha256, PrecompileSha256);
        constrain_next_state!(cb, Ripemd160, PrecompileRipemd160);
        constrain_next_state!(cb, Identity, PrecompileIdentity);
        constrain_next_state!(cb, Modexp, PrecompileBigModExp);
        constrain_next_state!(cb, Bn128Add, PrecompileBn256Add);
        constrain_next_state!(cb, Bn128Mul, PrecompileBn256ScalarMul);
        constrain_next_state!(cb, Bn128Pairing, PrecompileBn256Pairing);
        constrain_next_state!(cb, Blake2F, PrecompileBlake2f);

        // Without constraining the next step's state, only constrain the first two Phase2 cells,
        // i.e. RLC(input_bytes) and RLC(return_bytes)
        // We only check these constraints if there was no OOG error in the precompile call.
        let is_oog_err = cb
            .next
            .execution_state_selector([ExecutionState::ErrorOutOfGasPrecompile]);
        cb.constrain_next_step(None, Some(not::expr(is_oog_err)), |cb| {
            let (next_input_bytes_rlc, next_output_bytes_rlc, next_return_bytes_rlc) = (
                cb.query_cell_phase2(),
                cb.query_cell_phase2(),
                cb.query_cell_phase2(),
            );
            cb.require_equal(
                "equality: RLC(input_bytes)",
                next_input_bytes_rlc.expr(),
                input_bytes_rlc.expr(),
            );
            if let Some(output_bytes_rlc) = output_bytes_rlc {
                cb.require_equal(
                    "equality: RLC(output_bytes)",
                    next_output_bytes_rlc.expr(),
                    output_bytes_rlc.expr(),
                );
            }
            if let Some(return_bytes_rlc) = return_bytes_rlc {
                cb.require_equal(
                    "equality: RLC(return_bytes)",
                    next_return_bytes_rlc.expr(),
                    return_bytes_rlc.expr(),
                );
            }
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
