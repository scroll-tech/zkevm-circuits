use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::error::{ExecError, OogError};
use crate::evm::Opcode;
use crate::operation::{CallContextField, TxAccessListAccountOp, RW};
use crate::Error;
use eth_types::evm_types::OpcodeId;
use eth_types::{GethExecStep, ToAddress};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the
/// [`OogError::MemoryCopy`](crate::error::OogError::MemoryCopy).
#[derive(Clone, Copy, Debug)]
pub(crate) struct OOGMemoryCopy;

impl Opcode for OOGMemoryCopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert!([
            OpcodeId::CALLDATACOPY,
            OpcodeId::CODECOPY,
            OpcodeId::EXTCODECOPY,
            OpcodeId::RETURNDATACOPY
        ]
        .contains(&geth_step.op));

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::MemoryCopy));

        let is_extcodecopy = geth_step.op == OpcodeId::EXTCODECOPY;

        // According to EIP-2929, EXTCODECOPY constant gas cost is different for cold
        // and warm accounts.
        if is_extcodecopy {
            state.call_context_read(
                &mut exec_step,
                state.call()?.call_id,
                CallContextField::TxId,
                state.tx_ctx.id().into(),
            );

            let external_address = geth_step.stack.last()?.to_address();
            let is_warm = state.sdb.check_account_in_access_list(&external_address);
            state.push_op(
                &mut exec_step,
                RW::READ,
                TxAccessListAccountOp {
                    tx_id: state.tx_ctx.id(),
                    address: external_address,
                    is_warm,
                    is_warm_prev: is_warm,
                },
            );
        }

        // Each of CALLDATACOPY, CODECOPY and RETURNDATACOPY has 3 stack read values.
        // But EXTCODECOPY has 4. It has an extra stack pop for external address.
        let stack_read_num = if is_extcodecopy { 4 } else { 3 };
        for i in 0..stack_read_num {
            state.stack_read(
                &mut exec_step,
                geth_step.stack.nth_last_filled(i),
                geth_step.stack.nth_last(i)?,
            )?;
        }

        state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
        state.handle_return(geth_step)?;

        Ok(vec![exec_step])
    }
}
