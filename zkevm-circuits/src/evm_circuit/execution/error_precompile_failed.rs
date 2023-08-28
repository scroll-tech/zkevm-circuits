use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            constraint_builder::EVMConstraintBuilder,
            math_gadget::IsZeroGadget,
            memory_gadget::{CommonMemoryAddressGadget, MemoryAddressGadget},
            sum, CachedRegion, Cell, Word,
        },
    },
    table::CallContextFieldTag,
    util::Expr,
    witness::{Block, Call, ExecStep, Transaction},
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, U256};
use halo2_proofs::{circuit::Value, plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct ErrorPrecompileFailedGadget<F> {
    opcode: Cell<F>,
    is_call: IsZeroGadget<F>,
    is_callcode: IsZeroGadget<F>,
    is_delegatecall: IsZeroGadget<F>,
    is_staticcall: IsZeroGadget<F>,
    gas: Word<F>,
    callee_address: Word<F>,
    value: Word<F>,
    cd_address: MemoryAddressGadget<F>,
    rd_address: MemoryAddressGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ErrorPrecompileFailedGadget<F> {
    const NAME: &'static str = "ErrorPrecompileFailed";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ErrorPrecompileFailed;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        cb.opcode_lookup(opcode.expr(), 1.expr());

        let is_call = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALL.expr());
        let is_callcode = IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::CALLCODE.expr());
        let is_delegatecall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::DELEGATECALL.expr());
        let is_staticcall =
            IsZeroGadget::construct(cb, opcode.expr() - OpcodeId::STATICCALL.expr());

        // constrain op code
        // NOTE: this precompile gadget is for dummy use at the moment, the real error handling for
        // precompile will be done in each precompile gadget in the future. won't add step
        // state transition constraint here as well.
        cb.require_true(
            "opcode is one of [call, callcode, staticcall, delegatecall]",
            sum::expr(vec![
                is_call.expr(),
                is_callcode.expr(),
                is_delegatecall.expr(),
                is_staticcall.expr(),
            ]),
        );

        // Use rw_counter of the step which triggers next call as its call_id.
        let callee_call_id = cb.curr.state.rw_counter.clone();

        let gas = cb.query_word_rlc();
        let callee_address = cb.query_word_rlc();
        let value = cb.query_word_rlc();
        let cd_offset = cb.query_cell_phase2();
        let cd_length = cb.query_word_rlc();
        let rd_offset = cb.query_cell_phase2();
        let rd_length = cb.query_word_rlc();

        cb.stack_pop(gas.expr());
        cb.stack_pop(callee_address.expr());

        // `CALL` and `CALLCODE` opcodes have an additional stack pop `value`.
        cb.condition(is_call.expr() + is_callcode.expr(), |cb| {
            cb.stack_pop(value.expr())
        });
        cb.stack_pop(cd_offset.expr());
        cb.stack_pop(cd_length.expr());
        cb.stack_pop(rd_offset.expr());
        cb.stack_pop(rd_length.expr());
        cb.stack_push(0.expr());

        for (field_tag, value) in [
            (CallContextFieldTag::LastCalleeId, callee_call_id.expr()),
            (CallContextFieldTag::LastCalleeReturnDataOffset, 0.expr()),
            (CallContextFieldTag::LastCalleeReturnDataLength, 0.expr()),
        ] {
            cb.call_context_lookup(true.expr(), None, field_tag, value);
        }

        let cd_address = MemoryAddressGadget::construct(cb, cd_offset, cd_length);
        let rd_address = MemoryAddressGadget::construct(cb, rd_offset, rd_length);

        Self {
            opcode,
            is_call,
            is_callcode,
            is_delegatecall,
            is_staticcall,
            gas,
            callee_address,
            value,
            cd_address,
            rd_address,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let opcode = step.opcode.unwrap();
        let is_call_or_callcode =
            usize::from([OpcodeId::CALL, OpcodeId::CALLCODE].contains(&opcode));

        let [gas, callee_address] =
            [step.rw_indices[0], step.rw_indices[1]].map(|idx| block.rws[idx].stack_value());
        let value = if is_call_or_callcode == 1 {
            block.rws[step.rw_indices[2]].stack_value()
        } else {
            U256::zero()
        };
        let [cd_offset, cd_length, rd_offset, rd_length] = [
            step.rw_indices[is_call_or_callcode + 2],
            step.rw_indices[is_call_or_callcode + 3],
            step.rw_indices[is_call_or_callcode + 4],
            step.rw_indices[is_call_or_callcode + 5],
        ]
        .map(|idx| block.rws[idx].stack_value());

        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;
        self.is_call.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::CALL.as_u64()),
        )?;
        self.is_callcode.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::CALLCODE.as_u64()),
        )?;
        self.is_delegatecall.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::DELEGATECALL.as_u64()),
        )?;
        self.is_staticcall.assign(
            region,
            offset,
            F::from(opcode.as_u64()) - F::from(OpcodeId::STATICCALL.as_u64()),
        )?;
        self.gas.assign(region, offset, Some(gas.to_le_bytes()))?;
        self.callee_address
            .assign(region, offset, Some(callee_address.to_le_bytes()))?;
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;
        self.cd_address
            .assign(region, offset, cd_offset, cd_length)?;
        self.rd_address
            .assign(region, offset, rd_offset, rd_length)?;

        Ok(())
    }
}
