use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget, constraint_builder::EVMConstraintBuilder, rlc,
            CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};
use bus_mapping::precompile::PrecompileAuxData;
use eth_types::{Field, ToScalar};
use gadgets::util::{select, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};

mod ec_add;
pub use ec_add::EcAddGadget;

mod ecrecover;
pub use ecrecover::EcrecoverGadget;

mod modexp;
pub use modexp::ModExpGadget;
mod ec_mul;
pub use ec_mul::EcMulGadget;

mod ec_pairing;
pub use ec_pairing::EcPairingGadget;

mod identity;
pub use identity::IdentityGadget;

mod sha256;
pub use sha256::SHA256Gadget;

#[derive(Clone, Debug)]
pub struct BasePrecompileGadget<F, const S: ExecutionState> {
    input_bytes_rlc: Cell<F>,
    output_bytes_rlc: Cell<F>,
    return_bytes_rlc: Cell<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
    gas_cost: Cell<F>,
}

impl<F: Field, const S: ExecutionState> ExecutionGadget<F> for BasePrecompileGadget<F, S> {
    const EXECUTION_STATE: ExecutionState = S;

    const NAME: &'static str = "BASE_PRECOMPILE";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (input_bytes_rlc, output_bytes_rlc, return_bytes_rlc) = (
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
        );
        let gas_cost = cb.query_cell();
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

        let last_callee_return_data_length = match Self::EXECUTION_STATE {
            ExecutionState::PrecompileSha256 | ExecutionState::PrecompileRipemd160 => 0x20,
            ExecutionState::PrecompileBlake2f => 0x40,
            _ => unreachable!("{} should not use the base gadget", Self::EXECUTION_STATE),
        };
        let restore_context = RestoreContextGadget::construct2(
            cb,
            is_success.expr(),
            gas_cost.expr(),
            0.expr(),
            0.expr(), // ReturnDataOffset
            select::expr(
                is_success.expr(),
                last_callee_return_data_length.expr(),
                0x00.expr(),
            ), // ReturnDataLength
            0.expr(),
            0.expr(),
        );

        Self {
            input_bytes_rlc,
            output_bytes_rlc,
            return_bytes_rlc,

            is_success,
            callee_address,
            caller_id,
            call_data_offset,
            call_data_length,
            return_data_offset,
            return_data_length,
            restore_context,
            gas_cost,
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
        if let Some(PrecompileAuxData::Base {
            input_bytes,
            output_bytes,
            return_bytes,
        }) = &step.aux_data
        {
            for (col, bytes) in [
                (&self.input_bytes_rlc, input_bytes),
                (&self.output_bytes_rlc, output_bytes),
                (&self.return_bytes_rlc, return_bytes),
            ] {
                col.assign(
                    region,
                    offset,
                    region
                        .challenges()
                        .keccak_input()
                        .map(|r| rlc::value(bytes.iter().rev(), r)),
                )?;
            }
        } else {
            log::error!("unexpected aux_data {:?} for basePrecompile", step.aux_data);
            return Err(Error::Synthesis);
        }

        self.gas_cost
            .assign(region, offset, Value::known(F::from(step.gas_cost)))?;
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
