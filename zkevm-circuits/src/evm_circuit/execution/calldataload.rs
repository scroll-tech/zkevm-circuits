use halo2::{arithmetic::FieldExt, plonk::Error};

use crate::{
    evm_circuit::{
        param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_WORD},
        step::ExecutionState,
        table::TxContextFieldTag,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, StepStateTransition, Transition,
            },
            memory_gadget::BufferReaderGadget,
            Cell, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CallDataLoadGadget<F> {
    /// Gadget to constrain the same context.
    same_context: SameContextGadget<F>,
    /// Transaction id from the tx context.
    tx_id: Cell<F>,
    /// The bytes offset in calldata, from which we load a 32-bytes word.
    calldata_start: Cell<F>,
    /// The bytes offset in calldata, where we end the 32-bytes word.
    calldata_end: Cell<F>,
    /// Gadget to read from tx calldata, which we validate against the word
    /// pushed to stack.
    buffer_reader: BufferReaderGadget<F, N_BYTES_WORD, N_BYTES_MEMORY_ADDRESS>,
}

impl<F: FieldExt> ExecutionGadget<F> for CallDataLoadGadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLDATALOAD;

    const NAME: &'static str = "CALLDATALOAD";

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let calldata_start = cb.query_cell();
        let calldata_end = cb.query_cell();
        let tx_id = cb.query_cell();

        let buffer_reader =
            BufferReaderGadget::construct(cb, &calldata_start, &calldata_end);

        let mut calldata_word = [0u8; N_BYTES_WORD].map(|i| i.expr());
        for (i, data) in calldata_word.iter_mut().enumerate() {
            let read_flag = buffer_reader.read_flag(i);

            cb.condition(read_flag, |cb| {
                let read_byte = buffer_reader.byte(i);
                *data = read_byte.clone();
                cb.tx_context_lookup(
                    tx_id.expr(),
                    TxContextFieldTag::CallData,
                    Some(calldata_start.expr() + i.expr()),
                    read_byte,
                )
            });
        }

        cb.stack_push(RandomLinearCombination::random_linear_combine_expr(
            calldata_word,
            cb.power_of_randomness(),
        ));

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(2.expr()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(0.expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(
            cb,
            opcode,
            step_state_transition,
            None,
        );

        Self {
            same_context,
            calldata_start,
            calldata_end,
            tx_id,
            buffer_reader,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut halo2::circuit::Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction<F>,
        _call: &Call<F>,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // assign the tx id.
        self.tx_id
            .assign(region, offset, Some(F::from(tx.id as u64)))?;

        // set the value for bytes offset in calldata. This is where we start
        // reading bytes from.
        let calldata_offset =
            block.rws[step.rw_indices[0]].stack_value().as_usize();

        // assign the calldata start and end cells.
        self.calldata_start.assign(
            region,
            offset,
            Some(F::from(calldata_offset as u64)),
        )?;
        self.calldata_end.assign(
            region,
            offset,
            Some(F::from((calldata_offset + 32) as u64)),
        )?;

        // bytes after the end of calldata are set to 0.
        let mut calldata_bytes = vec![0u8; N_BYTES_WORD];
        for (i, byte) in calldata_bytes.iter_mut().enumerate() {
            if calldata_offset + i < tx.call_data_length {
                *byte = tx.call_data[calldata_offset + i];
            }
        }

        // assign to the buffer reader gadget.
        self.buffer_reader.assign(
            region,
            offset,
            calldata_offset as u64,
            (calldata_offset + N_BYTES_WORD) as u64,
            &calldata_bytes,
            vec![1u8; N_BYTES_WORD].as_slice(),
        )?;

        Ok(())
    }
}
