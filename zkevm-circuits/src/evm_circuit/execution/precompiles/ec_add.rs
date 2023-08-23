use bus_mapping::precompile::{PrecompileAuxData, PrecompileCalls};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{ConstrainBuilderCommon, EVMConstraintBuilder},
            rlc, CachedRegion, Cell,
        },
    },
    table::CallContextFieldTag,
    witness::{Block, Call, ExecStep, Transaction},
};

#[derive(Clone, Debug)]
pub struct EcAddGadget<F> {
    // EC points: P, Q, R
    point_p_x_rlc: Cell<F>,
    point_p_y_rlc: Cell<F>,
    point_q_x_rlc: Cell<F>,
    point_q_y_rlc: Cell<F>,
    point_r_x_rlc: Cell<F>,
    point_r_y_rlc: Cell<F>,
    gas_cost: Cell<F>,

    is_success: Cell<F>,
    callee_address: Cell<F>,
    caller_id: Cell<F>,
    call_data_offset: Cell<F>,
    call_data_length: Cell<F>,
    return_data_offset: Cell<F>,
    return_data_length: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for EcAddGadget<F> {
    const NAME: &'static str = "EC_ADD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PrecompileBn256Add;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let (
            point_p_x_rlc,
            point_p_y_rlc,
            point_q_x_rlc,
            point_q_y_rlc,
            point_r_x_rlc,
            point_r_y_rlc,
        ) = (
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
            cb.query_cell_phase2(),
        );
        let gas_cost = cb.query_cell();
        cb.require_equal(
            "ecAdd: gas cost",
            gas_cost.expr(),
            GasCost::PRECOMPILE_BN256ADD.expr(),
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

        cb.condition(is_success.expr(), |cb| {
            cb.ecc_table_lookup(
                u64::from(PrecompileCalls::Bn128Add).expr(),
                point_p_x_rlc.expr(),
                point_p_y_rlc.expr(),
                point_q_x_rlc.expr(),
                point_q_y_rlc.expr(),
                0.expr(), // input_rlc
                point_r_x_rlc.expr(),
                point_r_y_rlc.expr(),
            );
        });

        let restore_context = RestoreContextGadget::construct2(
            cb,
            is_success.expr(),
            gas_cost.expr(),
            0.expr(),
            0x00.expr(), // ReturnDataOffset
            0x40.expr(), // ReturnDataLength
            0.expr(),
            0.expr(),
        );

        Self {
            point_p_x_rlc,
            point_p_y_rlc,
            point_q_x_rlc,
            point_q_y_rlc,
            point_r_x_rlc,
            point_r_y_rlc,
            gas_cost,

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
        if let Some(PrecompileAuxData::EcAdd(aux_data)) = &step.aux_data {
            let keccak_rand = region.challenges().keccak_input();
            for (col, word_value) in [
                (&self.point_p_x_rlc, aux_data.p_x),
                (&self.point_p_y_rlc, aux_data.p_y),
                (&self.point_q_x_rlc, aux_data.q_x),
                (&self.point_q_y_rlc, aux_data.q_y),
                (&self.point_r_x_rlc, aux_data.r_x),
                (&self.point_r_y_rlc, aux_data.r_y),
            ] {
                col.assign(
                    region,
                    offset,
                    keccak_rand.map(|r| rlc::value(&word_value.to_le_bytes(), r)),
                )?;
            }
            // FIXME: when we handle invalid inputs (and hence failures in the precompile calls),
            // this will be assigned either fixed gas cost (in case of success) or the
            // entire gas passed to the precompile call (in case of failure).
            self.gas_cost.assign(
                region,
                offset,
                Value::known(F::from(GasCost::PRECOMPILE_BN256ADD.0)),
            )?;
        } else {
            log::error!("unexpected aux_data {:?} for ecAdd", step.aux_data);
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
